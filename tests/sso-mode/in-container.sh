#!/usr/bin/env bash
# Black-box assertions for sso-mode: socket-bound instances behind one shared
# oauth2-proxy with a per-instance email whitelist. See run.sh for why this
# lives outside tests/integration/ and what makes it honest.
set -uo pipefail

# Same double-proof refusal as every container tier: this script mutates system
# state and must only run inside a throwaway container.
if [[ ! -f /run/.containerenv && ! -f /.dockerenv ]] || [[ -z "${VIDE_IN_THROWAWAY_CONTAINER:-}" ]]; then
  printf 'FATAL: refusing to run — this test mutates system state and must only run\n' >&2
  printf '       inside the throwaway container built by tests/sso-mode/run.sh.\n' >&2
  exit 78   # EX_CONFIG
fi

REPO=${VIDE_REPO:-/vide}
PARENT=vide.example.test          # the shared SSO domain
U1=ittest                         # first SSO instance
U2=ittest2                        # second SSO instance (cross-instance authz)
U3=othertest                      # never in vide-proxy: the socket negative control
FQDN1=$U1.$PARENT
FQDN2=$U2.$PARENT
AUTH_HOST=auth.$PARENT
IDP_PORT=8555
IDP_ISSUER=http://127.0.0.1:$IDP_PORT     # ONE spelling feeds discovery AND the config
CLIENT_ID=vide-gate.apps.googleusercontent.com
CLIENT_SECRET=GOCSPX-fake-gate-secret-do-not-ship
O2P_PIN=7.15.3                    # pinned per run: the gate must not race upstream
O2P_PREV=7.15.2                   # the floor version — upgrade-sso walks PREV -> PIN
CADDY_VER=2.11.4
CADDY_SHA=527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9

# shellcheck source=../support/report.sh
. "$REPO/tests/support/report.sh"

expect_eq() { # <name> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
expect_ne() { # <name> <not-expected> <actual>
  if [[ "$2" != "$3" ]]; then ok "$1"; else bad "$1 (expected anything but '$2')"; fi
}
expect_ok()   { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else bad "$n (command failed: $*)"; fi; }
expect_fail() { local n=$1; shift; if "$@" >/dev/null 2>&1; then bad "$n (command unexpectedly succeeded: $*)"; else ok "$n"; fi; }
expect_contains() { # <name> <needle> <haystack>
  if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 (no '$2' in: ${3:0:200})"; fi
}
expect_missing() { # <name> <needle> <haystack>
  if [[ "$3" != *"$2"* ]]; then ok "$1"; else bad "$1 (unexpected '$2' present)"; fi
}
retry_until() { # <seconds> <cmd...> — bounded; a timeout is a FINDING, never a retry-to-green
  local deadline=$(( SECONDS + $1 )); shift
  while (( SECONDS < deadline )); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

# Ubuntu's tmp.mount shadows anything created in /tmp before boot settles; the
# arbiter learned this the hard way. Scratch is created now, after settle.
# Secrets live only on tmpfs, 0600, shredded on exit, and NEVER on argv
# (/proc/<pid>/cmdline is world-readable).
SECRET_DIR=$(umask 077; mktemp -d /dev/shm/vide-sso.XXXXXX)
WORK=$(mktemp -d)
IDP_PID=""
cleanup() {
  [[ -n "$IDP_PID" ]] && kill "$IDP_PID" 2>/dev/null
  find "$SECRET_DIR" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$SECRET_DIR" "$WORK"
}
trap cleanup EXIT
trap 'trap - INT;  cleanup; kill -INT  $$' INT
trap 'trap - TERM; cleanup; kill -TERM $$' TERM

SECRETS_FILE="$SECRET_DIR/sso-secrets"     # the --sso-secrets-stdin payload
IDP_KEY="$SECRET_DIR/idp.key"
IDP_CONTROL="$SECRET_DIR/idp-email"        # who logs in next; re-read per /authorize

# ---- 0. fixtures: users, IdP, caddy (the operator's job, played by the gate) ----
echo "== 0. fixtures =="

useradd -m -s /bin/bash "$U1" 2>/dev/null
useradd -m -s /bin/bash "$U2" 2>/dev/null
useradd -m -s /bin/bash "$U3" 2>/dev/null
expect_ok "target users exist" bash -c "id $U1 && id $U2 && id $U3"

DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl ca-certificates >/dev/null 2>&1
expect_ok "python3 present (bootstrap shim + fake IdP)" command -v python3

# The IdP keypair: generated per run, never checked in.
( umask 077; openssl genrsa -out "$IDP_KEY" 2048 2>/dev/null )
expect_ok "IdP keypair generated" test -s "$IDP_KEY"

printf 'alice@example.test\n' > "$IDP_CONTROL"
python3 "$REPO/tests/sso-mode/fake-idp.py" \
  --issuer="$IDP_ISSUER" --port="$IDP_PORT" --key="$IDP_KEY" \
  --client-id="$CLIENT_ID" --client-secret="$CLIENT_SECRET" \
  --control="$IDP_CONTROL" >"$WORK/idp.log" 2>&1 &
IDP_PID=$!
retry_until 15 curl -sf "$IDP_ISSUER/.well-known/openid-configuration" -o /dev/null
expect_ok "fake IdP discovery answers" curl -sf "$IDP_ISSUER/.well-known/openid-configuration" -o /dev/null
# Anti-vacuous: a JWKS whose modulus does not decode to 256 bytes would make
# every later "login failed" ambiguous between VIDE and the fixture.
n_len=$(curl -s "$IDP_ISSUER/jwks" | python3 -c '
import base64,json,sys
n=json.load(sys.stdin)["keys"][0]["n"]
print(len(base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))))')
expect_eq "IdP JWKS modulus is a real 2048-bit key" 256 "$n_len"
expect_eq "IdP issuer matches the configured URL byte-for-byte" "$IDP_ISSUER" \
  "$(curl -s "$IDP_ISSUER/.well-known/openid-configuration" | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])')"

# Caddy — the operator's proxy. VIDE never installs it (caddy.py renders text
# only); the gate plays the operator: pinned binary, verified, own unit.
curl -sL -o "$WORK/caddy.tgz" \
  "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VER/caddy_${CADDY_VER}_linux_amd64.tar.gz"
expect_eq "caddy tarball matches the pinned sha256" "$CADDY_SHA" \
  "$(sha256sum "$WORK/caddy.tgz" | cut -d' ' -f1)"
tar xzf "$WORK/caddy.tgz" -C "$WORK" caddy
install -m 0755 -o root -g root "$WORK/caddy" /usr/local/bin/caddy
useradd --system -M -d /var/lib/caddy -s /usr/sbin/nologin caddy 2>/dev/null
install -d -o caddy -g caddy -m 0750 /var/lib/caddy /etc/caddy
cat > /etc/systemd/system/caddy.service <<'UNIT'
[Unit]
Description=Caddy (sso-mode gate fixture — plays the operator's proxy)
[Service]
# Type=notify is the packaged unit's own, and here it is load-bearing rather
# than cosmetic: `caddy run` signals READY only after its listeners — including
# the admin endpoint — are up. Under the default Type=simple, `systemctl
# is-active` returns 0 the moment systemd has forked, so the three admin-socket
# rows below raced the execve and two of them went red against a remedy that
# works. The third went GREEN for the wrong reason: "nothing answers on 2019"
# passes trivially while caddy is not yet listening anywhere. A row that cannot
# tell "moved" from "not up yet" is not evidence.
Type=notify
User=caddy
Group=caddy
Environment=HOME=/var/lib/caddy
# CAP_NET_BIND_SERVICE: caddy runs as non-root but must bind :443/:80 (the real
# Debian caddy package grants the same). Without it, caddy starts with the
# global-only Caddyfile but FAILS the moment a site block (which listens on 443)
# is pasted — exactly the operator's setup.
AmbientCapabilities=CAP_NET_BIND_SERVICE
# The admin socket needs a directory caddy can create in: /run is root-owned and
# this unit drops to User=caddy, exactly like the Debian package. Shipping the
# `admin unix//...` line WITHOUT this is the advice VIDE published and could not
# have worked — caddy would fail to bind and take the front door with it. The
# gate now carries the documented remedy in full, so that advice is executed
# rather than asserted.
RuntimeDirectory=caddy
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
# The ONLY harness-authored Caddyfile content is this global block; every site
# block below is VIDE's emitted text, pasted verbatim. skip_install_trust: a
# non-root caddy can't tee its local root into the system store (we use --cacert
# against the harvested root.crt instead).
#
# `admin` moves to a permissioned socket — the remedy docs/sso.md publishes, run
# here rather than described. Two things it proves that nothing else did: that
# the socket actually BINDS under User=caddy (it does not without the
# RuntimeDirectory above), and that `systemctl reload caddy` — which allow and
# revoke run and treat as fail-hard — still works through it. `admin off` would
# break exactly that, which is why the docs refuse it.
#
# What this fixture does NOT prove, stated so nobody reads it as more than it
# is: it STARTS at the destination, so it certifies the end state and not the
# migration. docs/sso.md's step 3 — the one-time `systemctl restart caddy` —
# exists because RuntimeDirectory= materialises at unit start and `caddy reload`
# dials the admin address of the config being loaded, so an operator moving a
# RUNNING caddy cannot get there by reload. No tier walks that transition.
cat > /etc/caddy/Caddyfile <<'CADDYFILE'
{
	local_certs
	skip_install_trust
	admin unix//run/caddy/admin.sock
}
CADDYFILE
systemctl daemon-reload
systemctl enable --now caddy.service >/dev/null 2>&1
expect_ok "caddy fixture is active" systemctl is-active --quiet caddy.service
# The rows that make the published remedy evidence rather than advice. The
# readiness wait stays even under Type=notify: it costs nothing when the unit is
# already up, and without it a slow box turns a working remedy into a red row
# that reads as "the advice VIDE publishes does not work" — the most expensive
# false alarm this gate can raise.
retry_until 15 test -S /run/caddy/admin.sock
expect_ok "the admin socket bound under User=caddy" test -S /run/caddy/admin.sock
# 0200 (u=w), not 0600: that is caddy's own default for a unix bind address, and
# it is tighter than this row first asserted. Pinned by measurement rather than
# by expectation, because it is the number docs/sso.md publishes as the posture.
expect_eq "…as a socket only root and caddy itself can reach" "s-w------- caddy" \
  "$(stat -c '%A %U' /run/caddy/admin.sock 2>/dev/null)"
expect_eq "…in a RuntimeDirectory created at unit start" "750 caddy:caddy" \
  "$(stat -c '%a %U:%G' /run/caddy 2>/dev/null)"
# Ordered AFTER the socket rows on purpose: on its own this passes while caddy
# is merely not listening yet, which is how it stayed green through a run where
# the two rows around it were red.
expect_fail "nothing answers on the default admin port" \
  curl -fsS --max-time 2 http://127.0.0.1:2019/reverse_proxy/upstreams
expect_ok "systemctl reload caddy still works through the socket" \
  systemctl reload caddy.service

# The shipped oauth2-proxy unit is fully hardened for a REAL (rootful) systemd.
# Its namespace / seccomp / capability sandboxing needs setup privileges
# (CAP_SYS_ADMIN, UTS/mount namespaces) that ROOTLESS podman cannot grant — the
# unit fails 217/USER here, but works on the operator's box. This drop-in
# neutralizes that sandboxing so the FUNCTIONAL rows (login / per-instance
# authz / revoke / rotate) — the actual product surface — can run. What the
# gate deliberately does NOT test (rootless can't) is systemd's own sandboxing;
# the SHIPPED unit is unchanged and its full hardening is pinned statically by
# test_sso_units.TestProxyUnitLiterals and walked by `systemd-analyze security`
# on a real box in sso-smoke.md §8. Created BEFORE the install so it is already
# merged when converge_proxy does `systemctl enable --now`.
install -d /etc/systemd/system/vide-oauth2-proxy.service.d
cat > /etc/systemd/system/vide-oauth2-proxy.service.d/10-rootless-gate.conf <<'DROPIN'
# GATE-ONLY: relaxes the container-incompatible sandboxing (rootless podman).
# NOT shipped; the real unit's hardening is pinned by TestProxyUnitLiterals.
[Service]
ProtectSystem=no
ProtectHome=no
PrivateTmp=no
PrivateDevices=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectKernelLogs=no
ProtectControlGroups=no
ProtectClock=no
ProtectHostname=no
ProtectProc=default
RestrictAddressFamilies=
RestrictNamespaces=no
RestrictRealtime=no
RestrictSUIDSGID=no
LockPersonality=no
MemoryDenyWriteExecute=no
SystemCallFilter=
SystemCallArchitectures=
DROPIN
systemctl daemon-reload

# ---- 1. the SSO install (VIDE's own oauth2-proxy install path) ---------------
echo
echo "== 0.5 refusal before mutation (PRISTINE box, before §1) =="
# The manual smoke §3 checkbox was green while a scripted SSO install missing a
# required flag exited 64 only AFTER apt prereqs, the toolchain, a '$U1' user and
# /etc/vide/sso/fleet.env were already on the host. This section is the ABSENCE of
# that mutation, and it MUST run before §1: once the shared proxy is provisioned
# the missing-credential cells are unobservable (resolve keys on credentials_needed).
( umask 077
  printf 'VIDE_SSO_CLIENT_ID=%s\nVIDE_SSO_CLIENT_SECRET=%s\n' "$CLIENT_ID" "$CLIENT_SECRET" > "$SECRETS_FILE" )

untouched() { # <label> — the durable artifacts a VIDE SSO install would create.
  # NOTE: the target '$U1' is a pre-created fixture (VIDE auto-creates only the
  # 'vide' fallback, never a named target), so the OS user is NOT a VIDE mutation
  # here — the record / fleet.env / proxy.env / proxy-unit witnesses are.
  expect_fail "$1: no instance record"     test -e "/etc/vide/$U1.env"
  expect_fail "$1: no fleet.env"           test -e /etc/vide/sso/fleet.env
  expect_fail "$1: no proxy.env (secret)"  test -e /etc/vide/sso/proxy.env
  expect_eq   "$1: proxy unit not active"  "" \
    "$(systemctl is-active vide-oauth2-proxy.service 2>/dev/null | grep -x active)"
}
untouched "precondition (pristine)"

for miss in fqdn client-id secret allow badfqdn; do
  case "$miss" in
    fqdn)      set -- --no-gui --auth sso --user "$U1" --sso-client-id "$CLIENT_ID" --sso-allow alice@example.test; needle=--fqdn; want=64; stdin=/dev/null ;;
    client-id) set -- --no-gui --auth sso --user "$U1" --fqdn "$FQDN1" --sso-allow alice@example.test; needle=--sso-client-id; want=64; stdin=/dev/null ;;
    secret)    set -- --no-gui --auth sso --user "$U1" --fqdn "$FQDN1" --sso-client-id "$CLIENT_ID" --sso-allow alice@example.test; needle=--sso-secrets-stdin; want=64; stdin=/dev/null ;;
    allow)     set -- --no-gui --auth sso --user "$U1" --fqdn "$FQDN1" --sso-client-id "$CLIENT_ID" --sso-secrets-stdin; needle=--sso-allow; want=64; stdin=$SECRETS_FILE ;;
    badfqdn)   set -- --no-gui --auth sso --user "$U1" --fqdn "U.$PARENT" --sso-client-id "$CLIENT_ID" --sso-secrets-stdin --sso-allow alice@example.test; needle=fqdn; want=78; stdin=$SECRETS_FILE ;;
  esac
  VIDE_SSO_ISSUER_URL="$IDP_ISSUER" VIDE_OAUTH2_PROXY_VERSION="$O2P_PREV" \
    "$REPO/install.sh" "$@" <"$stdin" >"$WORK/r05.out" 2>"$WORK/r05.err"; rc=$?
  # Assert the secret is absent from the RAW output BEFORE redacting — checking it
  # after the sed would be vacuous (the sed already removed it).
  expect_missing  "…echoes no secret" "$CLIENT_SECRET" "$(cat "$WORK/r05.err" "$WORK/r05.out")"
  sed -i "s/$CLIENT_SECRET/[REDACTED]/g" "$WORK/r05.err" "$WORK/r05.out"
  expect_eq       "missing/bad --$miss exits $want" "$want" "$rc"
  expect_contains "…names the flag ($needle)" "$needle" "$(cat "$WORK/r05.err")"
  untouched "after the --$miss refusal"
done

echo
echo "== 1. sso install =="

( umask 077
  printf 'VIDE_SSO_CLIENT_ID=%s\nVIDE_SSO_CLIENT_SECRET=%s\n' "$CLIENT_ID" "$CLIENT_SECRET" > "$SECRETS_FILE" )

INSTALL_OUT="$WORK/install.out"
INSTALL_ERR="$WORK/install.err"
VIDE_CODE_SERVER_PIN_LATEST=1 \
VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
VIDE_OAUTH2_PROXY_VERSION="$O2P_PREV" \
  "$REPO/install.sh" --auth sso --user "$U1" --fqdn "$FQDN1" \
    --sso-client-id "$CLIENT_ID" --sso-secrets-stdin --sso-allow alice@example.test \
    <"$SECRETS_FILE" >"$INSTALL_OUT" 2>"$INSTALL_ERR"
install_rc=$?
# Redact before any dump can print: the client secret must never reach a log.
sed -i "s/$CLIENT_SECRET/[REDACTED]/g" "$INSTALL_ERR" "$INSTALL_OUT"

expect_eq "sso install exits 0" 0 "$install_rc"
if (( install_rc != 0 )); then
  printf '  --- install stderr (tail, secret redacted) ---\n' >&2
  tail -40 "$INSTALL_ERR" >&2
  report_summary; exit 1
fi

# A passwordless install mints NO code-server password: the inverse of the
# password arbiter's crown line.
expect_eq "a passwordless install prints ZERO SHOWN-ONCE secrets" 0 \
  "$(grep -cF 'SHOWN ONCE' "$INSTALL_ERR")"
expect_contains "stdout carries the pasted shell block" \
  "import /etc/vide/sso/caddy/$U1.caddy" "$(cat "$INSTALL_OUT")"
expect_contains "stdout carries the shared auth-subdomain block" \
  "$AUTH_HOST" "$(cat "$INSTALL_OUT")"

# ---- 2. rendered shape: the config that IS the auth boundary ------------------
# proxy.toml's POSTURE, which no tier asserted at all while the converge's write
# was made conditional and the only re-assertion of it was retired. The WIDTH is
# the security-relevant half: a widening hands write access over
# trusted_proxy_ips — this file's CVE-2026-40575 mitigation — to the one account
# on the box with a pre-authentication surface facing the internet, and it is
# invisible to every other check because the byte compare still matches.
expect_eq "proxy.toml is 0640 root:vide-oauth2" "640 root vide-oauth2" \
  "$(stat -c '%a %U %G' /etc/vide/sso/proxy.toml)"
echo
echo "== 2. rendered proxy config =="

TOML=/etc/vide/sso/proxy.toml
for lit in \
  'provider = "oidc"' \
  'reverse_proxy = true' \
  'trusted_proxy_ips = ["127.0.0.1/32"]' \
  'cookie_expire = "720h"' \
  'session_cookie_minimal = true' \
  'prompt = "select_account"' \
  'skip_provider_button = true' \
  'set_xauthrequest = true' \
  'authenticated_emails_file = "/etc/vide/sso/authenticated-emails"' \
  "cookie_domains = [\".$PARENT\"]" \
  "whitelist_domains = [\".$PARENT\"]" ; do
  if grep -qF "$lit" "$TOML" 2>/dev/null; then ok "toml has: $lit"; else bad "toml MISSING: $lit"; fi
done
# Absence pins. cookie_refresh with session_cookie_minimal is a startup crash;
# skip_auth_routes was the CVE-2025-54576 bypass; email_domains = "*" would make
# the whitelist decorative.
for forbidden in cookie_refresh skip_auth_routes skip_auth_regex api_routes \
                 insecure_oidc_allow_unverified_email email_domains ; do
  if grep -qE "^[[:space:]]*$forbidden[[:space:]]*=" "$TOML" 2>/dev/null; then
    bad "toml renders the FORBIDDEN key: $forbidden"
  else
    ok "toml never renders: $forbidden"
  fi
done

expect_eq "proxy.env is 0600 root:root" "600 root:root" \
  "$(stat -c '%a %U:%G' /etc/vide/sso/proxy.env 2>/dev/null)"
expect_eq "proxy unit is active" "active" "$(systemctl is-active vide-oauth2-proxy.service 2>/dev/null)"
# The secret must not be visible anywhere a non-root (or any) process can read:
# argv, the journal, or the install logs.
proxy_pid=$(systemctl show -p MainPID --value vide-oauth2-proxy.service 2>/dev/null)
if [[ -n "$proxy_pid" && "$proxy_pid" != 0 ]]; then
  if tr '\0' '\n' < "/proc/$proxy_pid/cmdline" | grep -qF "$CLIENT_SECRET"; then
    bad "the client secret is on the proxy's argv (/proc/<pid>/cmdline is world-readable)"
  else
    ok "the client secret never reaches argv"
  fi
else
  bad "proxy has no MainPID"
fi
if journalctl -u vide-oauth2-proxy.service --no-pager 2>/dev/null | grep -qF "$CLIENT_SECRET"; then
  bad "the client secret leaked into the journal"
else
  ok "the client secret never reaches the journal"
fi

# The binary came through VIDE's own install path, at the pinned version.
expect_ok "versioned binary dir exists" test -x "/opt/vide/oauth2-proxy/$O2P_PREV/oauth2-proxy"
expect_ok "current symlink exists" test -L /opt/vide/oauth2-proxy/current
expect_contains "recorded version is the pinned one" "$O2P_PREV" \
  "$(cat /etc/vide/sso/proxy.version 2>/dev/null)"

# ---- 3. socket posture: the perms ARE the passwordless authz policy -----------
echo
echo "== 3. socket posture =="

SOCK=/run/vide/$U1/code-server.sock
expect_ok "instance unit active" systemctl is-active --quiet "code-server@$U1"
retry_until 20 test -S "$SOCK"
expect_eq "socket is owner=$U1 group=vide-proxy mode 0660" "socket $U1:vide-proxy 660" \
  "$(stat -c '%F %U:%G %a' "$SOCK" 2>/dev/null)"
# FROZEN, not merely setgid. Until root takes this directory the instance user
# owns it, and 2750 restricts third parties while restricting the owner not at
# all — they may unlink and rename every entry, including the socket Caddy
# re-resolves on every connection. §13b executes that.
expect_eq "socket dir is FROZEN to root once the socket exists" "2750 root:vide-proxy" \
  "$(stat -c '%a %U:%G' "/run/vide/$U1" 2>/dev/null)"
# The inverse of the password contract's bind assertion: in socket mode there
# must be NO TCP listener for this instance at all.
expect_eq "no VIDE_PORT in the sso instance record" "" \
  "$(sed -n 's/^VIDE_PORT=//p' "/etc/vide/$U1.env" 2>/dev/null)"
expect_contains "the record declares sso mode" "VIDE_MODE=sso" "$(cat "/etc/vide/$U1.env" 2>/dev/null)"
listeners=$(ss -Htln | awk '{print $4}' | grep -cE ':(97[0-9][0-9]|99[0-9][0-9])$' || true)
expect_eq "socket mode opens no TCP listener in the allocator range" 0 "$listeners"
# caddy must be in the group AND its LIVE process must carry it — membership is
# read at process start, so a not-yet-restarted caddy is the classic mystery 502.
expect_contains "caddy is a member of vide-proxy" "caddy" "$(getent group vide-proxy)"
systemctl restart caddy.service   # the operator's one-time restart, as instructed
sleep 1
caddy_pid=$(systemctl show -p MainPID --value caddy.service)
proxy_gid=$(getent group vide-proxy | cut -d: -f3)
if grep -q "^Groups:.*\b$proxy_gid\b" "/proc/$caddy_pid/status" 2>/dev/null; then
  ok "the LIVE caddy process carries the vide-proxy gid"
else
  bad "caddy's live process lacks the vide-proxy gid (restart pending)"
fi

# ---- 4. paste the operator's blocks and complete a REAL login -----------------
echo
echo "== 4. crown assertion: a whitelisted email actually gets the IDE =========="

# The operator pastes VIDE's emitted text verbatim — no harness edits.
sed -n '/^# --- VIDE/,$p' "$INSTALL_OUT" >> /etc/caddy/Caddyfile
systemctl reload caddy.service || systemctl restart caddy.service
retry_until 20 curl -sk "https://127.0.0.1/" -o /dev/null
CA=/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
retry_until 20 test -s "$CA"
expect_ok "caddy's internal CA is available for the gate's curl" test -s "$CA"

JAR=$WORK/alice.jar
web() { # <jar> <host> [curl args...] — a browser-shaped request through Caddy
  local jar=$1 host=$2; shift 2
  curl -s -o "$WORK/body" -w '%{http_code}' -L --max-redirs 12 \
    --cacert "$CA" --resolve "$host:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
    -b "$jar" -c "$jar" "https://$host/" "$@"
}
printf 'alice@example.test\n' > "$IDP_CONTROL"
code=$(web "$JAR" "$FQDN1")
expect_eq "whitelisted alice completes SSO and reaches the IDE (200)" 200 "$code"
expect_contains "the body really is code-server, not a proxy page" "code-server" "$(cat "$WORK/body")"

# ---- 4a. the /vide identity page: who am I, and how do I get out --------------
# It answers on the INSTANCE host, from behind the same forward_auth. The whole
# question is ordering: if it ever renders before the proxy has decided, it
# hands out an identity taken from an unverified header.
echo
echo "== 4a. /vide identity page =="

vide_page() { # <jar> — no -L: a redirect here is the interesting answer
  curl -s -o "$WORK/vide.body" -w '%{http_code}' --max-redirs 0 \
    --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
    -b "$1" "https://$FQDN1/vide"
}

# (a) THE assertion: unauthenticated, the page must not exist as far as the
# caller is concerned. A 200 here is the whole feature backfiring.
anon=$(vide_page /dev/null)
expect_missing "an unauthenticated /vide is NOT answered (auth runs first)" "200" "$anon"
expect_missing "…and leaks no address in the body" "@example.test" "$(cat "$WORK/vide.body")"

# (b) authenticated: it names the account, this instance, and the way out.
code=$(vide_page "$JAR")
expect_eq "an authorized session gets the page (200)" 200 "$code"
expect_contains "…naming the Google account it authorized" "alice@example.test" \
  "$(cat "$WORK/vide.body")"
expect_contains "…naming this instance" "$FQDN1" "$(cat "$WORK/vide.body")"
expect_contains "…and the fleet-wide sign_out lever" \
  "https://$AUTH_HOST/oauth2/sign_out" "$(cat "$WORK/vide.body")"
expect_contains "…saying plainly that it signs out EVERY instance" \
  "EVERY VIDE instance" "$(cat "$WORK/vide.body")"

# (b2) the round trip a human actually walks: read the page, click Sign out,
# land somewhere that describes what just happened. Before this, sign_out with
# no `rd` dropped the operator on the auth root's sign-IN copy — "if you have
# just signed in you are done", above a link to the sign-out just used. Found
# live within minutes of shipping that page, so it gets a live row.
signout_href=$(grep -o "https://$AUTH_HOST/oauth2/sign_out?rd=[^']*" "$WORK/vide.body" | head -1)
expect_contains "the page's Sign out link carries a return marker" "rd=" "$signout_href"
# A session of its OWN: sign_out clears the cookie of whoever calls it (the
# cookie IS the session — there is no server-side store), so walking it with
# $JAR would sign the rest of this gate out from under §5-§9.
printf 'alice@example.test\n' > "$IDP_CONTROL"
expect_eq "a throwaway session to spend on the sign-out round trip" 200 \
  "$(web "$WORK/out.jar" "$FQDN1")"
out_code=$(curl -s -o "$WORK/out.body" -w '%{http_code}' -L --max-redirs 5 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
  -b "$WORK/out.jar" -c "$WORK/out.jar" "$signout_href")
expect_eq "following it lands on a real page, not a 404" 200 "$out_code"
expect_contains "…which says the sign-out happened, and that it was fleet-wide" \
  "Signed out of EVERY VIDE instance" "$(cat "$WORK/out.body")"
expect_missing "…and never claims the opposite event" "just signed in" \
  "$(cat "$WORK/out.body")"
# A bare visit to the same root must still get the neutral copy — the marker is
# what distinguishes them, and it must not be assumed.
bare=$(curl -s -o "$WORK/bare.body" -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$AUTH_HOST:443:127.0.0.1" "https://$AUTH_HOST/")
expect_eq "a bare visit to the auth root still answers" 200 "$bare"
expect_missing "…without claiming a sign-out that never happened" \
  "Signed out of EVERY" "$(cat "$WORK/bare.body")"
# and it really signed out — the copy would be a lie otherwise.
dead=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" -b "$WORK/out.jar" "https://$FQDN1/vide")
expect_missing "the session that walked the sign-out is really dead" "200" "$dead"
# …and the OTHER live session is untouched: sign_out clears the caller's cookie,
# it does not reach into another browser. "Fleet-wide" means one cookie covers
# every instance, NOT that one user's exit logs out the box.
expect_eq "another browser's session is NOT collaterally signed out" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 --cacert "$CA" \
     --resolve "$FQDN1:443:127.0.0.1" -b "$JAR" "https://$FQDN1/vide")"

# (b3) the auth root answers TWO ways now, and the split IS the boundary. It
# cannot be gated instead — sign-out lands here too and that visitor has just
# destroyed the session a gate would demand — so both branches answer 200 and
# the only difference is what they are allowed to say.
auth_root() { # <curl-args...> — the same URL every time; the caller varies identity
  curl -s -o "$WORK/root.body" -w '%{http_code}' --max-redirs 0 \
    --cacert "$CA" --resolve "$AUTH_HOST:443:127.0.0.1" "$@" "https://$AUTH_HOST/"
}
expect_missing "the auth root names no account to a stranger" "@example.test" \
  "$(cat "$WORK/bare.body")"
expect_eq "the same root, carrying a live session, still answers 200" 200 \
  "$(auth_root -b "$JAR")"
expect_contains "…and now names the account that session authorized" \
  "alice@example.test" "$(cat "$WORK/root.body")"
# THE row this page exists to justify. copy_headers overwrites the identity from
# the auth RESPONSE, but only when the proxy sets one; the emitted block strips
# the inbound header first so a forged one cannot survive a 202 that sets none.
# Hermetically this is only visible live — no render assertion can see a header.
expect_eq "a forged identity header still gets an answer" 200 \
  "$(auth_root -H 'X-Auth-Request-Email: mallory@example.test')"
expect_missing "…and the page does NOT echo the forged identity" \
  "mallory@example.test" "$(cat "$WORK/root.body")"
# Belt and braces: forging it ALONGSIDE a real session must not swap the name
# either — the proxy's value has to win, not merely be present.
expect_eq "a forged header alongside a real session answers 200" 200 \
  "$(auth_root -b "$JAR" -H 'X-Auth-Request-Email: mallory@example.test')"
expect_contains "…still naming the account the proxy vouched for" \
  "alice@example.test" "$(cat "$WORK/root.body")"
expect_missing "…and never the forged one" "mallory@example.test" \
  "$(cat "$WORK/root.body")"

# (c) the reserved prefix really is a prefix, and it did not eat the editor.
sub=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" -b "$JAR" "https://$FQDN1/vide/anything")
expect_eq "the /vide* prefix is reserved, not just the bare path" 200 "$sub"
code=$(web "$JAR" "$FQDN1")
expect_eq "…and the editor still answers at / (the page shadows nothing)" 200 "$code"
expect_contains "…with code-server, not VIDE's page" "code-server" "$(cat "$WORK/body")"

# ---- 4b. no-whitelist hardening: forged identity headers + a safe cookie -------
# The load-bearing SSO claim: with NO IP-whitelist
# the shared oauth2-proxy is the SOLE internet-facing gate. Two properties that
# gate must hold, which the rows above assert only in the RENDERED config, walked
# here LIVE against the running proxy.
echo
echo "== 4b. no-whitelist hardening =="

# (a) header-spoof: an UNAUTHENTICATED client that forges the very identity
# headers oauth2-proxy itself emits (set_xauthrequest) must NOT be believed. The
# auth decision is the SESSION COOKIE; trusted_proxy_ips = ["127.0.0.1/32"] means
# forwarded/identity headers are trusted only from Caddy on loopback, never from
# the client — the CVE-2026-40575 (X-Forwarded-Uri spoof) class, proven live.
spoof=$(curl -s -o "$WORK/spoof.body" -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
  -H 'X-Auth-Request-Email: alice@example.test' \
  -H 'X-Forwarded-Email: alice@example.test' \
  -H 'X-Forwarded-User: alice@example.test' \
  -H 'X-Forwarded-Uri: /' \
  "https://$FQDN1/")
expect_missing "forged identity headers do NOT authenticate (no cookie, no whitelist)" "200" "$spoof"
expect_missing "…and the spoofed request never reaches code-server" "code-server" "$(cat "$WORK/spoof.body")"

# (b) the session cookie is safe on the open internet: Secure (never sent over
# plain http), HttpOnly (JS/XSS cannot read it), SameSite=Lax (the CSRF floor).
# A fresh login, capturing every redirect hop's response headers.
printf 'alice@example.test\n' > "$IDP_CONTROL"
curl -s -o /dev/null -D "$WORK/login.hdrs" -L --max-redirs 12 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
  -c "$WORK/flags.jar" "https://$FQDN1/"
# the session cookie (_oauth2_proxy=<value>, or a numbered chunk) — NOT the
# transient _oauth2_proxy_csrf nor the post-logout clear (=;). Lowercased because
# cookie attributes are case-insensitive.
cookieline=$(tr 'A-Z' 'a-z' < "$WORK/login.hdrs" \
  | grep -E 'set-cookie: _oauth2_proxy(_[0-9]+)?=[^;]' | tail -1)
if [[ -n "$cookieline" ]]; then
  expect_contains "session cookie is Secure"       "secure"       "$cookieline"
  expect_contains "session cookie is HttpOnly"     "httponly"     "$cookieline"
  expect_contains "session cookie is SameSite=Lax" "samesite=lax" "$cookieline"
else
  bad "no _oauth2_proxy session cookie was set on a successful login"
fi

# ---- 5-9. the discrimination rows: who is refused, and HOW ---------------------
echo
echo "== 5-9. authz discrimination =="

# 5. A non-whitelisted identity authenticates but must NEVER reach the IDE.
printf 'mallory@example.test\n' > "$IDP_CONTROL"
code=$(web "$WORK/mallory.jar" "$FQDN1")
expect_eq "non-whitelisted mallory is refused (403), never 200" 403 "$code"

# The unverified-email positive control: the proxy must refuse the redeem, so a
# forged email_verified:false identity cannot ride in.
printf 'alice@example.test unverified\n' > "$IDP_CONTROL"
code=$(web "$WORK/unverified.jar" "$FQDN1")
expect_missing "an unverified email never reaches the IDE" "200" "$code"
printf 'alice@example.test\n' > "$IDP_CONTROL"

# 6. Case sensitivity is REAL: oauth2-proxy's per-request allowed_emails query
# is case-sensitive against the session email, with no lowercasing. VIDE renders
# a lowercase query (normalize_email); Google always asserts a lowercase email,
# so real logins match. But an IdP that asserts a NON-lowercase email is denied
# (403) — the trap the spike named. This pins that the mismatch is a denial, not
# a silent allow (fail-closed), and documents that emails must be lowercase
# end-to-end.
printf 'Alice@Example.Test\n' > "$IDP_CONTROL"
code=$(web "$WORK/mixed.jar" "$FQDN1")
expect_eq "a non-lowercase IdP email is DENIED (case-sensitive query; Google normalizes)" 403 "$code"
printf 'alice@example.test\n' > "$IDP_CONTROL"

# 7. '+' addresses: Go's query parser turns a literal '+' into a space, so the
# renderer must emit %2B or the entry silently never matches.
vide allow 'user+tag@example.test' "$U1" >/dev/null 2>&1
expect_contains "a '+' address is percent-encoded in the rendered query" "user%2Btag@example.test" \
  "$(cat "/etc/vide/sso/caddy/$U1.caddy")"
printf 'user+tag@example.test\n' > "$IDP_CONTROL"
code=$(web "$WORK/plus.jar" "$FQDN1")
expect_eq "the '+' address logs in and reaches the IDE" 200 "$code"
vide revoke 'user+tag@example.test' "$U1" >/dev/null 2>&1
printf 'alice@example.test\n' > "$IDP_CONTROL"

# 8. Second instance, alice NOT on its list: she is authenticated fleet-wide but
# must get a 403 that is NOT redirected — redirecting a 403 loops forever.
VIDE_CODE_SERVER_PIN_LATEST=1 VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
  "$REPO/install.sh" --auth sso --user "$U2" --fqdn "$FQDN2" \
  --sso-allow bob@example.test </dev/null >"$WORK/install2.out" 2>"$WORK/install2.err"
expect_eq "second sso install exits 0 (joins the existing proxy)" 0 "$?"
sed -n '/^# --- VIDE/,$p' "$WORK/install2.out" >> /etc/caddy/Caddyfile
systemctl reload caddy.service
sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 5 -L \
  --cacert "$CA" --resolve "$FQDN2:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
  -b "$JAR" "https://$FQDN2/")
expect_eq "alice's live session on a foreign instance is 403, not a redirect loop" 403 "$code"
# The identity page must inherit that decision, not sit beside it: authenticated
# fleet-wide is NOT authorized here, and a page that says "you are signed in"
# would contradict the 403 the editor just gave on the same host.
vcode=$(curl -s -o "$WORK/foreign.body" -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$FQDN2:443:127.0.0.1" -b "$JAR" "https://$FQDN2/vide")
expect_eq "…and /vide on that instance is 403 too, never a friendly page" 403 "$vcode"
expect_missing "…leaking no address" "alice@example.test" "$(cat "$WORK/foreign.body")"

# 9. The empty-set fail-open edge: an empty allowed_emails allows EVERY
# authenticated user upstream. The renderer must emit a deny sentinel instead.
vide --yes revoke bob@example.test "$U2" >/dev/null 2>&1
expect_contains "an emptied whitelist renders the deny sentinel" "deny@vide.invalid" \
  "$(cat "/etc/vide/sso/caddy/$U2.caddy")"
expect_missing "an emptied whitelist NEVER renders a bare allowed_emails=" "allowed_emails=&" \
  "$(cat "/etc/vide/sso/caddy/$U2.caddy")"
systemctl reload caddy.service; sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 5 -L \
  --cacert "$CA" --resolve "$FQDN2:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
  -b "$JAR" "https://$FQDN2/")
expect_eq "a deny-sentinel instance refuses an authenticated session (403)" 403 "$code"

# ---- 10-11. the two revocation paths ------------------------------------------
echo
echo "== 10-11. revocation =="

# 11 first (cross-instance): alice on BOTH instances; revoking her from U2 must
# not touch her U1 session. --yes: alice is U2's only email, so the revoke would
# make U2 deny-all (the last-email destructive gate).
vide allow alice@example.test "$U2" >/dev/null 2>&1
systemctl reload caddy.service; sleep 1
code=$(web "$WORK/alice2.jar" "$FQDN2")
expect_eq "alice allowed on the second instance reaches it (200)" 200 "$code"
vide --yes revoke alice@example.test "$U2" >/dev/null 2>&1   # the verb reloads caddy itself
sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 5 -L \
  --cacert "$CA" --resolve "$FQDN2:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
  -b "$WORK/alice2.jar" "https://$FQDN2/")
expect_eq "cross-instance revoke denies her there (403) — the verb reloaded caddy" 403 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 5 -L \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
  -b "$JAR" "https://$FQDN1/")
expect_eq "her session on the OTHER instance is untouched (200)" 200 "$code"

# 10 (fleet exit): revoking her last grant removes her from the union file, and
# the proxy re-reads that file per request — so the denial is immediate and needs
# NO caddy action at all. This is also the functional proof that the fsnotify
# watcher survives our atomic-rename writes.
vide --yes revoke alice@example.test "$U1" >/dev/null 2>&1   # her last grant
expect_missing "alice is gone from the union authn file" "alice@example.test" \
  "$(cat /etc/vide/sso/authenticated-emails)"
denied() {
  local c
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
    --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" -b "$JAR" "https://$FQDN1/")
  [[ "$c" != 200 ]]
}
if retry_until 15 denied; then
  ok "fleet-exit revoke denies her live session with NO caddy reload (union file is hot)"
else
  bad "fleet-exit revoke did not propagate — fsnotify missed the rename (use --force-restart)"
fi
vide allow alice@example.test "$U1" >/dev/null 2>&1   # restore for the rotate row

# ---- 12. rotate-sso: the fleet-wide kill switch --------------------------------
echo
echo "== 12. rotate-sso =="

printf 'alice@example.test\n' > "$IDP_CONTROL"
code=$(web "$JAR" "$FQDN1")
expect_eq "alice logs in again after re-allow (200)" 200 "$code"
pid_before=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
env_before=$(sha256sum /etc/vide/sso/proxy.env | cut -d' ' -f1)
vide --yes rotate-sso >/dev/null 2>&1
expect_eq "rotate-sso exits 0" 0 "$?"
expect_ok "the cookie secret really changed" bash -c \
  "[[ \$(sha256sum /etc/vide/sso/proxy.env | cut -d' ' -f1) != '$env_before' ]]"
pid_after=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
expect_ok "the proxy RESTARTED (rotate restarts; allow/revoke never do)" bash -c \
  "[[ '$pid_before' != '$pid_after' && -n '$pid_after' && '$pid_after' != 0 ]]"
# --max-time ON EVERY /ping PROBE IN THIS TIER, and it is not cosmetic.
# The fleet's port is held by a systemd socket unit now, so a probe against a
# down proxy no longer gets ECONNREFUSED — the kernel completes the handshake
# into the accept queue and the request BLOCKS. curl's default has no total
# timeout, so `retry_until 20` around a bare curl stops being "20 quick tries"
# and becomes twenty hangs. Every /ping in the 3.1 and 4.x tiers carries this.
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_ok "the proxy came back healthy with the new secret" \
  curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
# THE assertion: the old cookie must be dead. Without this, rotate-sso is theater.
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" -b "$JAR" "https://$FQDN1/")
expect_missing "the pre-rotation cookie is DEAD" "200" "$code"
code=$(web "$WORK/fresh.jar" "$FQDN1")
expect_eq "a fresh login works after rotation (200)" 200 "$code"

# ---- 12b. rotate-sso's RECOVERY path, from the browser that was signed in -----
# The row above (and its host-smoke twin) log in with a FRESH jar — they model a
# user arriving from a new device. The operator arrives from the SAME browser,
# still holding the pre-rotation cookies, and that path dead-ended three times
# when it was walked against real Google on 2026-07-27 (tests/manual/sso-smoke.md).
# Everything here fails closed; the defect was that the way OUT was unmarked.
echo
echo "== 12b. rotate-sso recovery (dirty jar) =="

# (a) The stale CSRF cookie is voided along with the session, so upstream may
# refuse the first attempt with "CSRF token mismatch, potential attack". VIDE
# cannot suppress upstream's page — what it MUST guarantee is that the operator
# is not stuck: the same browser, same jar, gets in without clearing anything.
printf 'alice@example.test\n' > "$IDP_CONTROL"
dirty1=$(web "$JAR" "$FQDN1")
dirty2=$(web "$JAR" "$FQDN1")
expect_eq "the pre-rotation browser recovers WITHOUT clearing cookies (200)" 200 "$dirty2"

# The jar above carries only the dead SESSION cookie. The real browser also held
# a CSRF cookie signed with the old secret, so forge that half too — a cookie the
# proxy cannot decrypt is, from its side, what rotate-sso made of the operator's.
#
# HONEST SCOPE, measured 2026-07-27: this does NOT reproduce the "potential
# attack" 403. Both attempts answer 200, because /oauth2/start writes a fresh
# csrf cookie under the SAME name and overwrites the poisoned one before anything
# reads it. So whatever produced the live 403 needed more than a stale cookie —
# most likely two csrf cookies at different domain/path scopes sent together.
# Do not read a green here as "dead end 1 is covered": its only regression guard
# is rotate-sso's warning (test_sso_verbs + prove-teeth T23). What this row DOES
# pin is worth keeping on its own: an undecryptable csrf cookie must not be able
# to lock a browser out of the fleet.
now=$(date +%s)
printf '#HttpOnly_.%s\tTRUE\t/\tTRUE\t%s\t_oauth2_proxy_csrf\tstale-under-the-old-secret\n' \
  "$PARENT" "$((now + 3600))" >> "$JAR"
poisoned1=$(web "$JAR" "$FQDN1")
poisoned2=$(web "$JAR" "$FQDN1")
expect_eq "an UNDECRYPTABLE csrf cookie cannot lock a browser out of the fleet" 200 "$poisoned2"
echo "    (first attempt with the forged stale csrf answered $poisoned1 — 200 means"
echo "     the same-name overwrite absorbed it; a 403 here would mean this tier had"
echo "     finally caught the live dead end, and the comment above needs revisiting)"

# (b) The dead end that WAS ours: oauth2-proxy serves only /oauth2/*, so the
# auth host's bare root 404s — and that root is exactly where a post-rotation
# re-login lands (upstream's error page offers a Sign in button with no `rd`).
# The emitted auth block must answer it, or a successful login reads as a broken
# fleet at the worst possible moment.
root_code=$(curl -s -o "$WORK/authroot.body" -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$AUTH_HOST:443:127.0.0.1" "https://$AUTH_HOST/")
expect_eq "the auth host's root ANSWERS instead of 404ing a logged-in operator" 200 "$root_code"
expect_contains "…and points back at the instance URL shape" "your-subdomain.$PARENT" \
  "$(cat "$WORK/authroot.body")"
expect_contains "…dressed like the rest: the mark is there" "<svg" "$(cat "$WORK/authroot.body")"
expect_contains "…and names the fleet-wide sign_out lever" \
  "https://$AUTH_HOST/oauth2/sign_out" "$(cat "$WORK/authroot.body")"
# The handler runs before any auth — it must not claim an identity it never checked.
expect_missing "…and never asserts a session it did not verify" "you are signed in" \
  "$(tr 'A-Z' 'a-z' < "$WORK/authroot.body")"

# (c) The narrowing check: answering the root must not shadow the login
# endpoints themselves — /oauth2/start still has to reach the proxy.
start_code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$AUTH_HOST:443:127.0.0.1" "https://$AUTH_HOST/oauth2/start")
expect_missing "the root handler does not shadow /oauth2/* (start still lives)" \
  "404" "$start_code"

# ---- 13. socket-perms teeth (the negative controls that de-vacuous §3) ---------
echo
echo "== 13. socket teeth =="

chmod 0666 "$SOCK"
doctor_out=$(vide doctor 2>&1); doctor_rc=$?
expect_ok "doctor goes RED on a world-writable socket" bash -c "[[ $doctor_rc -ne 0 ]]"
expect_contains "doctor NAMES the socket-perm fact" "$SOCK" "$doctor_out"
systemctl restart "code-server@$U1"          # the documented heal
retry_until 20 test -S "$SOCK"
expect_eq "a restart re-creates the socket at 0660" "660" "$(stat -c '%a' "$SOCK")"
expect_ok "doctor is green again" vide doctor
# A user outside vide-proxy must not be able to reach the IDE through the socket.
expect_fail "a non-member user cannot connect to the socket" \
  su - "$U3" -c "curl -s --max-time 5 --unix-socket $SOCK http://localhost/healthz"

# ---- 13b. the socket-directory freeze: the attack, executed --------------------
# The 2026-07-31 whole-tree block. Two reviewers reached it independently by
# reading; nothing anywhere executed it. This tier already built the precondition
# for the worst version at §0 (a real caddy admin socket) and then pointed nothing
# at it. These rows point at it.
#
# This is also the only place in the repo that runs a PRE-FIX CONTROL: the same
# attack against a unit with the freeze sed'd out. Without it, "the attack failed"
# is satisfied by a dead instance, a typo'd path, or a symlink target that never
# existed — every one of which reads as "the fix works".
echo
echo "== 13b. the socket directory is not the instance user's to rewrite =="

UNIT_FILE=/etc/systemd/system/code-server@.service
DROPIN_DIR=/etc/systemd/system/code-server@$U1.service.d

with_unit_mutation() { # <sed-expr> <label> — restart U1 under a mutated ExecStartPost
  local expr=$1 label=$2 orig mutant
  orig=$(grep '^ExecStartPost=' "$UNIT_FILE")
  mutant=$(printf '%s' "$orig" | sed "$expr")
  # prove()'s cmp -s discipline, and it is not optional here: a sed that stopped
  # matching after a benign reword produces "the attack failed", i.e. a green
  # that means the exact opposite of what it says.
  if [[ "$mutant" == "$orig" ]]; then
    bad "$label: the mutation did not apply — the sed expression rotted"; return 1
  fi
  mkdir -p "$DROPIN_DIR"
  # printf, never a heredoc with expansion: the line carries $$ and %% verbatim
  # and a single $ would make sh expand nothing, so the loop never relabels and
  # the control "succeeds" for a fixture reason.
  { printf '[Service]\nExecStartPost=\n'; printf '%s\n' "$mutant"; } > "$DROPIN_DIR/90-mutation.conf"
  systemctl daemon-reload
  systemctl restart "code-server@$U1" || { bad "$label: the mutant would not start"; return 1; }
  retry_until 30 test -S "$SOCK" || { bad "$label: no socket under the mutant"; return 1; }
  # the helper's self-check: the PRE-FIX posture must really be back
  expect_eq "$label: the pre-fix posture is genuinely restored" "2750 $U1:vide-proxy" \
    "$(stat -c '%a %U:%G' "/run/vide/$U1" 2>/dev/null)"
}
restore_unit() {
  rm -f "$DROPIN_DIR/90-mutation.conf"; rmdir "$DROPIN_DIR" 2>/dev/null
  systemctl daemon-reload
  systemctl restart "code-server@$U1"
  retry_until 30 test -S "$SOCK"
  expect_eq "the freeze is back after the control" "2750 root:vide-proxy" \
    "$(stat -c '%a %U:%G' "/run/vide/$U1" 2>/dev/null)"
}

# Preconditions. A row asserting "the attack failed" is satisfied by a dead
# instance, so state the box is healthy first. The IdP is re-pointed at alice
# because §12 rotated the cookie secret and §12b left the jar recovering.
printf 'alice@example.test\n' > "$IDP_CONTROL"
# The posture is asserted HERE, not only at §3: every expect_fail below means
# nothing unless the freeze is actually in force at this moment, and §3 ran
# hundreds of rows and several restarts ago.
expect_eq "the socket dir is frozen right now, not just at §3" "2750 root:vide-proxy" \
  "$(stat -c '%a %U:%G' "/run/vide/$U1" 2>/dev/null)"
expect_eq "the socket itself is still the instance user's" "socket $U1:vide-proxy 660" \
  "$(stat -c '%F %U:%G %a' "$SOCK" 2>/dev/null)"
expect_eq "alice's own IDE answers through Caddy" 200 "$(web "$JAR" "$FQDN1")"

# The primitive. Every one of these is a plain filesystem operation the instance
# user could perform freely before the freeze.
expect_fail "the instance user cannot delete her own socket" \
  su - "$U1" -c "rm -f $SOCK"
expect_fail "...nor plant a symlink at a SIBLING instance's socket (shell as $U2)" \
  su - "$U1" -c "ln -sf /run/vide/$U2/code-server.sock $SOCK"
expect_fail "...nor at the operator's caddy admin socket (the whole reverse proxy)" \
  su - "$U1" -c "ln -sf /run/caddy/admin.sock $SOCK"
expect_fail "...nor move the socket aside to make room for one" \
  su - "$U1" -c "mv $SOCK /run/vide/$U1/x.sock"
expect_fail "...nor create anything at all in the directory" \
  su - "$U1" -c "touch /run/vide/$U1/x"
expect_eq "...and the path Caddy dials is still a plain socket" "socket" \
  "$(stat -c '%F' "$SOCK" 2>/dev/null)"
expect_ok "...and not a symlink" test ! -L "$SOCK"

# THE PRE-FIX CONTROL. Same box, same attacker, freeze removed. These two rows are
# the difference between "green on the fixed unit" and "red on the unfixed one",
# and they are the only place the Critical is demonstrated rather than described.
# The mutation has TWO parts, and both are needed to reproduce the pre-fix world.
# Removing the freeze alone is no longer enough: the vide-proxy grant now happens
# AS PART of the freeze, so a unit with the chown sed'd out leaves the directory
# 2750 <user>:<primary> — which the user owns but Caddy cannot walk, and the
# attack does not reproduce for the second of the two reasons this round closed.
# The helper's own posture self-check caught exactly that when the first part was
# added and the second was not.
if with_unit_mutation \
   's@n=0; while@chgrp vide-proxy "\$\$D" || exit 1; chmod 2750 "\$\$D" || exit 1; n=0; while@; s@chown root:vide-proxy "\$\$D" || exit 1; @@' \
   "pre-fix"; then
  expect_ok "PRE-FIX CONTROL: without the freeze the symlink really is plantable" \
    su - "$U1" -c "rm -f $SOCK && ln -s /run/caddy/admin.sock $SOCK"
  # The decisive request: a legitimate session on her OWN hostname, proxied by the
  # `handle` fallthrough into whatever the path now resolves to. "apps" is the
  # discriminator — code-server's own 404 body cannot contain it, Caddy's admin
  # config always does.
  curl -s -o "$WORK/admin.body" --max-time 10 --cacert "$CA" \
    --resolve "$FQDN1:443:127.0.0.1" -b "$JAR" "https://$FQDN1/config/" >/dev/null 2>&1
  expect_contains "PRE-FIX CONTROL: ...and Caddy serves its OWN admin API through the instance" \
    '"apps"' "$(cat "$WORK/admin.body" 2>/dev/null)"
fi
restore_unit
# MEASURED, 2026-07-31, and it surprised the round that wrote these rows: putting
# the socket back is NOT enough. Caddy pools keep-alive connections per upstream
# ADDRESS, and a pooled connection still terminates at whatever the path resolved
# to when it was opened — so after restore_unit the instance is healthy, the
# directory is frozen, the symlink is gone, and Caddy goes on answering from the
# admin socket. Four later rows in this gate went red on exactly that.
# This is a RECOVERY fact, not a fixture wart, and it is pinned in both
# directions: an operator closing this hole on a live box must restart caddy, or
# it keeps serving the attacker's upstream out of the pool.
expect_contains "the pooled connection still reaches the OLD upstream until caddy restarts" \
  '"apps"' "$(curl -s --max-time 10 --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" \
      -b "$JAR" "https://$FQDN1/config/" 2>/dev/null)"
systemctl restart caddy.service
retry_until 20 curl -sk "https://127.0.0.1/" -o /dev/null
expect_eq "alice's IDE is healthy again after the control" 200 "$(web "$JAR" "$FQDN1")"
expect_missing "...and the admin API is no longer reachable through her hostname" '"apps"' \
  "$(curl -s --max-time 10 --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" \
      -b "$JAR" "https://$FQDN1/config/" 2>/dev/null)"

# ---- 13c. fail-closed: a socket that never appears loses the instance ----------
# The historical shape was a silent fail-OPEN — the loop fell out, `sh` exited 0,
# and the unit started with its directory still writable by its user. Proving the
# opposite direction (that removing the exit 1 makes this box start happily) is
# done deterministically in the fast tier by prove-teeth T63 and the sh driver;
# what only real systemd can show is that a non-zero ExecStartPost actually FAILS
# the unit. The journal assertion is what stops this row passing for an unrelated
# failure.
echo
echo "== 13c. fail-closed =="

FAIL_DIR=/etc/systemd/system/code-server@$U3.service.d
mkdir -p "$FAIL_DIR"
# No /etc/vide/<user>.env is planted: registry.list_instances globs state_dir/*.env,
# so a record here would be a phantom instance and would redden §14's doctor row
# for an unrelated reason. Environment= in the drop-in supplies VIDE_SOCKET instead.
cat > "$FAIL_DIR/90-never-binds.conf" <<'NEVERBIND'
[Service]
Environment=VIDE_SOCKET=/run/vide/othertest/code-server.sock
ExecStart=
ExecStart=/bin/sleep 300
Restart=no
NEVERBIND
systemctl daemon-reload
# Started in the background so the WINDOW can be observed while it is open: this
# unit never binds, so it holds the pre-freeze state for the whole 45s budget —
# which is exactly what an instance user does deliberately, since she owns the
# ExecStart binary ($HOME/.local/bin/code-server).
systemctl start "code-server@$U3" & start_job=$!
retry_until 20 test -d "/run/vide/$U3"
dir_during_wait=$(stat -c '%a %U:%G' "/run/vide/$U3" 2>/dev/null)
# code-server must be able to write this directory to bind at all, so the user
# owning it during the wait is unavoidable. Her owning a directory CADDY CAN WALK
# is not — the vide-proxy grant is part of the freeze rather than a step before
# it. Until that changed, this read "2750 othertest:vide-proxy" for 45 seconds.
# expect_eq, not expect_missing: the latter passes on the empty string `stat`
# returns whenever the directory was never observed, which is the vacuity this
# gate exists to refuse. The MODE is asserted with the group because traversal
# depends on both — and this is a narrowing, not a closure: the user owns this
# directory and can chmod it herself. What is pinned is that VIDE does not widen
# it for her.
expect_eq "VIDE hands nobody the walk into the dir while the user still owns it" \
  "700 $U3:$U3" "$dir_during_wait"
echo "    (directory during the wait: $dir_during_wait)"
wait "$start_job"; start_rc=$?
expect_ok "a socket that never appears FAILS the unit" \
  bash -c "[[ $start_rc -ne 0 ]]"
expect_eq "...and it lands in failed, not active" "failed" \
  "$(systemctl is-active "code-server@$U3" 2>/dev/null)"
expect_contains "...and the journal says WHY, in our words" "did not bind" \
  "$(journalctl -u "code-server@$U3" -n 50 --no-pager 2>/dev/null)"
rm -f "$FAIL_DIR/90-never-binds.conf"; rmdir "$FAIL_DIR" 2>/dev/null
systemctl daemon-reload
systemctl reset-failed "code-server@$U3" 2>/dev/null
expect_fail "the fail-closed fixture planted no phantom instance record" \
  test -e "/etc/vide/$U3.env"

# ---- 13d. the port reservation: the squat, executed ----------------------------
# The fleet's authorization port used to be free whenever oauth2-proxy was not
# holding it, and whoever took it answered forward_auth for EVERY instance on the
# box. A systemd socket unit now binds it as PID 1 from sockets.target and keeps
# holding it across the proxy stopping, restarting and crash-looping.
#
# THE ROW THAT SEPARATES THE FIX FROM THE STATUS QUO IS THE FIRST ONE: stop the
# SERVICE and leave the RESERVATION up. Any arrangement where both are down
# proves nothing — that is simply the old world. Everything below is written
# around keeping those two apart, and the pre-fix control at the end shows the
# same commands succeeding once the reservation is taken away.
#
# The actor is $U3 (othertest): a real unprivileged account with no VIDE
# instance, no role and no sudo. Rootless podman means "root" here is uid 0 in a
# user namespace, so a row that ran the bind as root would prove nothing about a
# real box; running it as $U3 is what makes the refusal meaningful, because $U3
# is unprivileged in the namespace exactly as it would be outside one.
echo
echo "== 13d. the fleet's authorization port is reserved =="

PROXY_SOCK_UNIT=vide-oauth2-proxy.socket
# Precondition, asserted rather than assumed: if the reservation were not in
# effect, every row below would pass for the wrong reason.
expect_eq "the reservation unit is listening before we start" "active" \
  "$(systemctl is-active "$PROXY_SOCK_UNIT" 2>/dev/null)"
# EXACT, not a substring: `pid=1` matches `pid=1234` — i.e. it matches the proxy
# itself, which is the one answer that would make this row prove the opposite of
# what it claims. grep -E anchors the field.
expect_ok "...and systemd itself holds the port, not the proxy" bash -c \
  "ss -Htlnp 'sport = :4180' 2>/dev/null | grep -Eq 'pid=1(,|\)|\$)'"

# The bind attempt, as the unprivileged account. errno is asserted, not just the
# exit code: EADDRINUSE (98) is the fix working, EACCES (13) would mean something
# else refused us, and a bare non-zero exit could be a python that failed to
# start. `try_bind` prints the errno name or the word BOUND.
cat > /tmp/try_bind.py <<'TRYBIND'
import socket, sys
s = socket.socket()
# SO_REUSEADDR, because a real attacker sets it and because WITHOUT it this
# probe fails for a reason that has nothing to do with the reservation. Closing
# a listening socket leaves its ACCEPTED children in TIME_WAIT on the same local
# address, so a later bind() without this option gets EADDRINUSE from the
# corpses of Caddy's own forward_auth connections — which is what made the
# PRE-FIX CONTROL below report "the squat was refused" on a box where nothing
# was holding the port at all. A control that fails for the wrong reason reads
# exactly like the fix working, and certifies nothing.
#
# It does NOT weaken the refusal rows above: SO_REUSEADDR permits binding over
# TIME_WAIT, never over a LISTENING socket. Stealing a live listener needs
# SO_REUSEPORT and a matching effective uid, which against systemd's root socket
# an unprivileged account cannot have. The two rows are each other's proof:
# REFUSED while the reservation holds, BOUND once it is taken away.
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", 4180))
except OSError as e:
    print(__import__("errno").errorcode.get(e.errno, e.errno))
else:
    print("BOUND")
TRYBIND
chmod 0644 /tmp/try_bind.py

systemctl stop vide-oauth2-proxy.service
expect_eq "the service is down..." "inactive" \
  "$(systemctl is-active vide-oauth2-proxy.service 2>/dev/null)"
expect_eq "...while the reservation stays up — THIS is the whole fix" "active" \
  "$(systemctl is-active "$PROXY_SOCK_UNIT" 2>/dev/null)"
expect_eq "an unprivileged bind on the fleet's port is REFUSED" "EADDRINUSE" \
  "$(runuser -u "$U3" -- python3 /tmp/try_bind.py 2>&1 | tail -1)"

# The crash-loop arm: the state the reservation exists for, and the one the two
# disabled rate limiters are about. A service that cannot start must not be able
# to drag the socket unit into `failed`, because a failed socket unit closes its
# descriptors and hands the port back.
cp /etc/vide/sso/proxy.env /tmp/proxy.env.good
sed -i 's|^OAUTH2_PROXY_CLIENT_SECRET=.*|OAUTH2_PROXY_CLIENT_SECRET=|' /etc/vide/sso/proxy.env
# ROT CHECK on the fixture, the same discipline §13b uses. Without it, the day
# the secret key is renamed this sed matches nothing, the proxy starts perfectly
# well, and the two rows below pass while proving that a HEALTHY proxy keeps the
# port held — which is not the claim they make.
expect_fail "13d crash-loop fixture really mutated proxy.env (rot check)" \
  cmp -s /tmp/proxy.env.good /etc/vide/sso/proxy.env
systemctl start vide-oauth2-proxy.service 2>/dev/null || true
sleep 8   # long enough for several RestartSec=5 cycles to land
# POSTURE SELF-CHECK: the rows below claim the reservation survives a CRASH LOOP,
# so the loop has to be shown to exist. NRestarts is the signal that replaced
# `failed` when the start limiter was switched off — a proxy that is quietly
# healthy here would make the two rows below prove nothing.
expect_ok "...and the proxy really is crash-looping (NRestarts advanced)" bash -c \
  '[ "$(systemctl show -p NRestarts --value vide-oauth2-proxy.service)" -gt 0 ]'
expect_eq "the reservation survives a crash-looping proxy" "active" \
  "$(systemctl is-active "$PROXY_SOCK_UNIT" 2>/dev/null)"
expect_eq "...and the port is still refused during the loop" "EADDRINUSE" \
  "$(runuser -u "$U3" -- python3 /tmp/try_bind.py 2>&1 | tail -1)"
cp /tmp/proxy.env.good /etc/vide/sso/proxy.env
systemctl reset-failed vide-oauth2-proxy.service 2>/dev/null || true
systemctl restart vide-oauth2-proxy.service
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_ok "the proxy is healthy again on the inherited descriptor" \
  curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
# IT REALLY DID INHERIT RATHER THAN BIND. Without this the rows above would also
# pass on a box where the proxy simply bound the port itself once the socket unit
# released it — which is the pre-fix world.
#
# THE EVIDENCE IS THE SOCKET'S OWNING UID, not LISTEN_FDS in the exec
# environment, and that is a correction made the first time this section ever
# ran. `/proc/<pid>/environ` of a process belonging to another user needs
# ptrace-mode access, i.e. CAP_SYS_PTRACE — and this tier runs under ROOTLESS
# podman, whose default capability set does not include it (`CapEff` here is
# 0x800405fb; bit 19 is clear). So root-in-container reads an empty string, and
# the row could never have passed in the posture the tier deliberately runs in.
# It was written, and never executed, for as long as the section was unrun.
#
# The replacement is stronger rather than weaker. A socket's recorded uid is its
# CREATOR's: systemd created this one as PID 1, so it reads 0 even though the
# process serving on it runs as vide-oauth2. Had the proxy bound the address
# itself, the uid would be the proxy's. That is the inheritance, stated by the
# kernel, and unlike an environment variable it is not something the process
# could have been handed by any other route.
proxy_pid=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
expect_eq "the proxy was HANDED the descriptor, it did not bind" "[0]" \
  "$(PYTHONPATH="$REPO/src" python3 -c \
     'from vide import system; print(sorted(system.hop_holders(4180).certain))')"
expect_ne "...and the process serving on it is NOT uid 0" \
  "0" "$(stat -c %u "/proc/$proxy_pid" 2>/dev/null)"
expect_fail "the journal shows no fd-range error" \
  bash -c "journalctl -u vide-oauth2-proxy -b --no-pager 2>/dev/null | grep -q 'fd outside of range'"

# VIDE'S OWN READERS, against this kernel. Everything above asserts the BOX is
# right; these assert that the code which has to SEE that box agrees with it.
# The unit tier can only model them, and a model's green is a claim about the
# model.
#
# 1. THE OWNER OF THE LISTENING SOCKET, which is the whole reservation check.
#    systemd creates it as PID 1, and the proxy INHERITS the descriptor — a
#    socket's recorded owner is its creator, so this must read 0 even though the
#    process serving on it runs as vide-oauth2 with a MainPID of its own. That
#    inheritance is the one thing a fabricated /proc/net/tcp cannot demonstrate.
expect_eq "the socket on the fleet's port is owned by uid 0" "[0]" \
  "$(PYTHONPATH="$REPO/src" python3 -c \
     'from vide import system; print(sorted(system.hop_holders(4180).certain))')"
# …and it is NOT the proxy's own uid, which is what an UN-migrated box reads.
# Asserted as a difference rather than assumed, because if the two happened to
# coincide the row above would be satisfied by the pre-fix state.
expect_ne "...and that is not the proxy's own uid" \
  "$(id -u vide-oauth2)" "0"

# 2. THE SAME ANSWER WITHOUT ROOT. /proc/net/tcp is world-readable, which is
#    half the reason this reader replaced an `ss -Htlnp` parse: attribution
#    stops being a root-only capability, so a non-root `vide doctor` — and
#    `doctor --quiet`, the documented cron hook — gets the real answer instead
#    of choosing between assuming the good case and reddening a healthy fleet.
#    §13d otherwise runs as root from top to bottom, so this is the only place
#    in the tree where the unprivileged path is executed at all.
expect_eq "a NON-ROOT caller gets the same answer, not an unknown" "[0]" \
  "$(runuser -u "$U3" -- env PYTHONPATH="$REPO/src" python3 -c \
     'from vide import system; print(sorted(system.hop_holders(4180).certain))' 2>&1 | tail -1)"

# 3. DOCTOR AGAINST A LIVE SQUATTER — the only end-to-end evidence this
#    release's central detection claim can get. Every squat row in the unit tier
#    hands proxy_health a uid set directly, so the path
#    /proc/net/tcp -> parse -> usurped -> containment ladder is walked nowhere.
#    Here there is a real unprivileged process on the real port.
systemctl stop vide-oauth2-proxy.service "$PROXY_SOCK_UNIT"
# A FILE AND A MARKER, not an inline `-c` behind `runuser &`. Backgrounding
# `runuser` gives $! the pid of RUNUSER, and killing that does not reap the
# python CHILD holding the socket — which is how the first run of this section
# left the port bound and made the PRE-FIX CONTROL forty lines below report
# EADDRINUSE where it must report BOUND. A green section that had already
# broken its own last row.
cat > /tmp/squat.py <<'SQUAT'
import os, socket, time
s = socket.socket()
# Same reason as try_bind.py: the proxy's just-closed connections sit in
# TIME_WAIT on this exact address, and a squatter that cannot get past them is
# not the squatter this row is about.
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 4180))
s.listen(8)
# ITS OWN PID, written by the process that actually holds the socket. The
# teardown below has no other way to reach it: $! is runuser's pid, not
# python's, and this image ships no pkill/pgrep/killall — so the first two
# attempts at this teardown were silent no-ops, one of them hidden by a
# `|| true`. The address then stayed held and every row after it failed.
open("/tmp/squat.pid", "w").write(str(os.getpid()))
time.sleep(120)
SQUAT
chmod 0644 /tmp/squat.py
rm -f /tmp/squat.pid
runuser -u "$U3" -- python3 /tmp/squat.py &
retry_until 15 test -s /tmp/squat.pid
expect_eq "the squatter really holds the port (rot check)" "$(id -u "$U3")" \
  "$(PYTHONPATH="$REPO/src" python3 -c \
     'from vide import system; print(sorted(system.hop_holders(4180).certain)[0])')"
squat_out=$(vide doctor 2>&1 || true)
expect_contains "doctor names a live squatter on the fleet's hop" "TAKEN" "$squat_out"
expect_contains "...with the containment ladder, not an advisory row" "BYPASS" "$squat_out"
expect_contains "...containment first" "stop caddy" "$squat_out"
# It must NOT need the squatter to answer /ping: this one never answers HTTP at
# all. Before the uid read, the ladder was gated on `answers` — i.e. on the
# attacker's cooperation.
expect_contains "...even though the squatter answers no HTTP at all" \
  "uid $(id -u "$U3")" "$squat_out"
# Kill the PROCESS THAT HOLDS THE SOCKET, by the pid it wrote itself, and then
# PROVE the address came back. Every row below rests on the port being free, and
# two earlier versions of this teardown left it held — the first because `$!` is
# runuser's pid rather than python's, the second because this image ships no
# pkill and `|| true` swallowed the failure. Both times the "address is free
# again" row was the only thing that noticed, and one of those times it passed
# VACUOUSLY: the squatter had failed to bind at all, so the address was free
# because nothing ever took it. Two bugs covering for each other.
kill "$(cat /tmp/squat.pid)" 2>/dev/null || true
retry_until 15 bash -c '[ -z "$(ss -Htln "sport = :4180")" ]'
expect_eq "the squatter is gone and the address is free again" "[]" \
  "$(PYTHONPATH="$REPO/src" python3 -c \
     'from vide import system; print(sorted(system.hop_holders(4180).certain))')"
rm -f /tmp/squat.py /tmp/squat.pid
systemctl start "$PROXY_SOCK_UNIT" vide-oauth2-proxy.service
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
proxy_pid=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
expect_ok "doctor reads clean again once the squatter is gone" vide doctor

# 4. The start-time reader, against a witness that reads NEITHER of its inputs.
#    `ps -o lstart` was the first choice and it is not independent: procps
#    computes boot_time() + ticks/Hertz from the same /proc/stat btime and the
#    same field 22, with the same flooring. It settles the field INDEX and the
#    presence of the anchor, and nothing about the claim that licenses the whole
#    comparison — that the result is in the frame st_mtime is stamped in.
#    `date +%s` is clock_gettime(CLOCK_REALTIME); it touches neither file.
pre=$(date +%s)
systemctl restart vide-oauth2-proxy.service
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
post=$(date +%s)
proxy_pid=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
started=$(PYTHONPATH="$REPO/src" python3 -c \
  "from vide import system; print(int(system.proc_start_realtime($proxy_pid)))")
# THE LOWER BOUND CARRIES THE READER'S DOCUMENTED ERROR, and the first run of
# this row is what made that concrete: it measured started = pre - 1. That is
# not a fault, it is `_START_TIME_SLACK`'s whole subject observed on a real
# kernel — /proc/stat's btime is printed in WHOLE SECONDS and floored, and field
# 22 is floored to clock ticks, so the answer is up to 1 + 1/USER_HZ seconds
# EARLY and never late. A bracket that did not absorb it was asserting the
# reader is exact, which the product's own constant says it is not. Two seconds
# on the low side, none on the high: LATE would be a real fault and stays a
# failure.
expect_ok "the start-time reader lands inside a wall-clock bracket around the restart" \
  bash -c "[ \$(( ${pre} - 2 )) -le ${started} ] && [ ${started} -le ${post} ]"
# …and the direction of the residual is asserted, not assumed: it must never
# read LATER than the wall clock said the restart finished.
expect_ok "...and it is early-or-equal, never late" \
  bash -c "[ ${started} -le ${post} ]"
# NO `ps -o lstart` ROW HERE, AND THAT IS A DECISION RATHER THAN AN OMISSION.
# Two reasons, and the second one is what removed it.
#
# It is not an independent witness: procps computes lstart as
# boot_time() + ticks/Hertz, from the same /proc/stat btime and the same field
# 22, with the same integer flooring. It can settle the field INDEX and nothing
# about the clock frame — which is what the bracket above is for.
#
# And it does not survive contact with a container. On this tier's own image the
# comparison measured ps = 1785456000 against a true start of 1785538553: a
# round number, i.e. midnight — `date -d` had parsed the DATE out of ctime's
# format and dropped the time. The rot check (`test -n`) passed, because a wrong
# answer is still an answer. Keeping a witness whose failure mode is a plausible
# number, guarded by a check that cannot see it, is worse than having none: it
# is the "negative assertion whose subject does not exist" shape with the sign
# flipped. `systemctl show -p ExecMainStartTimestamp` is the right second source
# if one is ever wanted — it is systemd's own realtime reading at exec, not a
# re-derivation from the two files under test.

# PRE-FIX CONTROL. Take the reservation away and re-run the identical bind: it
# must SUCCEED. Without this the section certifies nothing — a bind that fails
# for some unrelated reason would read exactly like a bind the fix refused.
systemctl stop vide-oauth2-proxy.service
systemctl stop "$PROXY_SOCK_UNIT"
expect_eq "PRE-FIX CONTROL: with no reservation, the squat SUCCEEDS" "BOUND" \
  "$(runuser -u "$U3" -- python3 /tmp/try_bind.py 2>&1 | tail -1)"
systemctl start "$PROXY_SOCK_UNIT"
systemctl start vide-oauth2-proxy.service
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_eq "the reservation is restored for the rows that follow" "active" \
  "$(systemctl is-active "$PROXY_SOCK_UNIT" 2>/dev/null)"
rm -f /tmp/try_bind.py /tmp/proxy.env.good

# ---- 14. doctor + 15. idempotence ---------------------------------------------
echo
echo "== 14-15. doctor and converge =="

expect_ok "doctor is green on a healthy sso box" vide doctor
expect_ok "doctor --quiet folds the proxy in (an sso instance exists)" vide doctor --quiet
systemctl stop vide-oauth2-proxy.service
expect_fail "doctor goes RED when the shared proxy is down" vide doctor --quiet
systemctl start vide-oauth2-proxy.service
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null

inst_pid_before=$(systemctl show -p MainPID --value "code-server@$U1")
proxy_pid_before=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
VIDE_CODE_SERVER_PIN_LATEST=1 VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
  "$REPO/install.sh" --auth sso --user "$U1" --fqdn "$FQDN1" \
  </dev/null >"$WORK/converge.out" 2>"$WORK/converge.err"
expect_eq "converge of an sso instance exits 0" 0 "$?"
expect_eq "converge restarts nothing (instance MainPID stable)" "$inst_pid_before" \
  "$(systemctl show -p MainPID --value "code-server@$U1")"
expect_eq "converge restarts nothing (proxy MainPID stable)" "$proxy_pid_before" \
  "$(systemctl show -p MainPID --value vide-oauth2-proxy.service)"
expect_eq "converge emits no secret of any kind" 0 \
  "$(grep -cF 'SHOWN ONCE' "$WORK/converge.err")"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" -b "$WORK/fresh.jar" "https://$FQDN1/")
expect_eq "a live session survives a converge (200)" 200 "$code"

# ---- 16. upgrade-sso + rollback ------------------------------------------------
echo
echo "== 16. upgrade-sso =="

VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" vide upgrade-sso >/dev/null 2>&1
expect_eq "upgrade-sso exits 0" 0 "$?"
expect_contains "current now points at the new version" "$O2P_PIN" \
  "$(readlink -f /opt/vide/oauth2-proxy/current)"
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_ok "the proxy is healthy on the new binary" curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" -b "$WORK/fresh.jar" "https://$FQDN1/")
expect_eq "sessions survive an upgrade (cookie secret unchanged)" 200 "$code"
kept=$(ls -1 /opt/vide/oauth2-proxy | grep -c '^7\.' || true)
expect_eq "exactly N and N-1 are kept on disk" 2 "$kept"

# ---- 16c. the migration lever is not a fleet-wide restart button ---------------
# THE DEFECT THIS ROUND FIXED, EXECUTED. A converge rewrote a byte-identical
# proxy.toml; that restamped the file NEWER than the running gate; so the next
# upgrade-sso read the gate as stale and bounced it — on a run in which not one
# byte had changed, for a verb three separate messages send operators to.
#
# §14-15 already asserts the CONVERGE itself restarts nothing. Nothing asserted
# what the converge does to THE VERB THAT FOLLOWS IT, which is where the whole
# cost landed, and both halves were green in isolation while this shipped.
echo
echo "== 16c. a converge does not arm the next upgrade =="
VIDE_CODE_SERVER_PIN_LATEST=1 VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
  "$REPO/install.sh" --auth sso --user "$U1" --fqdn "$FQDN1" \
  </dev/null >"$WORK/c16c.out" 2>"$WORK/c16c.err"
# EXIT CODES CHECKED, and this is not ceremony. Both commands below are SETUP
# for a negative assertion — "the MainPID did not move" — so a converge or an
# upgrade that DIED leaves the pid unchanged and the row reports ok. The green
# would then be produced by the verb not running.
expect_eq "16c's converge exits 0" 0 "$?"
# …and the migrated box is not told, on every install forever, that its
# reservation is still pending. Same string doctor uses as its migration-day red
# row: on one box, in one minute, install.sh said NOT YET RESERVED while
# `vide doctor` said reserved and exited green.
expect_fail "...and does not claim the reservation is pending on a migrated box" \
  grep -q 'NOT YET RESERVED' "$WORK/c16c.err"
pid_before=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" vide upgrade-sso >/dev/null 2>&1
expect_eq "16c's first upgrade-sso exits 0" 0 "$?"
expect_eq "a converge does not make the next upgrade-sso bounce the gate" \
  "$pid_before" "$(systemctl show -p MainPID --value vide-oauth2-proxy.service)"
# THE MTIME CLAUSE, FIRING POSITIVELY ON A REAL KERNEL — which nothing else
# reaches. The content edit below restarts the gate through the `wrote` clause
# (upgrade-sso re-renders proxy.toml, finds it changed, writes it), i.e. through
# the one clause that touches no host read at all. A bare `touch` of a unit file
# leaves the content identical, so `wrote` stays empty and the ONLY thing left
# is st_mtime compared against btime + field 22. If those two clocks were
# misaligned by a boot, a namespace or a step, this is the row that says so.
touch /etc/systemd/system/vide-oauth2-proxy.socket
VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" vide upgrade-sso >"$WORK/touch.out" 2>&1
expect_ne "a unit file newer than the running gate IS a restart" \
  "$pid_before" "$(systemctl show -p MainPID --value vide-oauth2-proxy.service)"
expect_contains "...and the warning names the file whose mtime moved" \
  "vide-oauth2-proxy.socket was written after" "$(cat "$WORK/touch.out")"
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
pid_before=$(systemctl show -p MainPID --value vide-oauth2-proxy.service)
# …and the opposite sign, or the row above is satisfied by an upgrade-sso that
# never restarts anything at all. A CONTENT change, not a touch: it is the one
# form that is correct under either shape of the decision.
printf '\n# operator edit\n' >> /etc/vide/sso/proxy.toml
VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" vide upgrade-sso >/dev/null 2>&1
expect_ne "...but a gate older than its config IS restarted" \
  "$pid_before" "$(systemctl show -p MainPID --value vide-oauth2-proxy.service)"
expect_fail "...and VIDE's render was restored over the edit" \
  grep -q '^# operator edit$' /etc/vide/sso/proxy.toml
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_ok "the gate is healthy after both levers" \
  curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null

# ---- 16b. the CVE floor, on a box seeded BELOW it ------------------------------
echo
echo "== 16b. CVE floor =="
# §16 walks PREV -> PIN, i.e. upward FROM the floor. The case that matters to an
# operator is the one no tier reached: a box installed before the floor existed,
# still fronting the internet with a vulnerable binary. VIDE refuses to INSTALL
# below the floor (resolve_version guards both the pin and the resolved latest),
# so that box cannot be produced through the product — it is seeded here exactly
# as a pre-floor VIDE would have left it. Load-bearing under the no-IP-whitelist
# principle: the proxy is the sole gate, so its patch level IS the perimeter.
O2P_VULN=7.15.1   # < FLOOR 7.15.2 — the X-Forwarded-Uri spoof, CVE-2026-40575

vuln_asset="oauth2-proxy-v$O2P_VULN.linux-amd64.tar.gz"
curl -sL -o "$WORK/$vuln_asset" \
  "https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v$O2P_VULN/$vuln_asset"
tar xzf "$WORK/$vuln_asset" -C "$WORK" "oauth2-proxy-v$O2P_VULN.linux-amd64/oauth2-proxy"
install -D -m 0755 -o root -g root \
  "$WORK/oauth2-proxy-v$O2P_VULN.linux-amd64/oauth2-proxy" \
  "/opt/vide/oauth2-proxy/$O2P_VULN/oauth2-proxy"
ln -sfn "/opt/vide/oauth2-proxy/$O2P_VULN" /opt/vide/oauth2-proxy/current
printf 'VIDE_OAUTH2_PROXY_VERSION=%s\nVIDE_OAUTH2_PROXY_SHA256=%s\n' \
  "$O2P_VULN" "$(sha256sum "$WORK/$vuln_asset" | cut -d' ' -f1)" \
  > /etc/vide/sso/proxy.version
# 1. The floor turns out to be enforced TWICE, and the second one is the
#    interesting one: VIDE's rendered proxy.toml carries `trusted_proxy_ips`,
#    a key oauth2-proxy only learned in 7.15.2 — the very release that closed
#    CVE-2026-40575, because that setting IS the mitigation. So a below-floor
#    binary cannot even parse this config: the policy check in resolve_version
#    can be sidestepped by seeding (as done above), the config cannot.
seedout=$("/opt/vide/oauth2-proxy/$O2P_VULN/oauth2-proxy" \
  --config /etc/vide/sso/proxy.toml 2>&1 | head -5)
expect_contains "a below-floor binary cannot parse VIDE's config at all" \
  "invalid keys: trusted_proxy_ips" "$seedout"

# 2. …and that refusal is FAIL-CLOSED: the gate serves nothing. The dangerous
#    shape would be an old binary that starts happily and silently ignores the
#    spoof mitigation — this proves VIDE never lands there.
systemctl restart vide-oauth2-proxy.service >/dev/null 2>&1
sleep 3
expect_fail "the shared gate does not come up on a below-floor binary" \
  curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
downcode=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 --max-time 10 \
  --cacert "$CA" --resolve "$FQDN1:443:127.0.0.1" -b "$WORK/fresh.jar" "https://$FQDN1/")
expect_ne_200() { if [[ "$2" != 200 ]]; then ok "$1"; else bad "$1 (got 200 — FAIL-OPEN)"; fi; }
expect_ne_200 "…and an established session reaches NO IDE while it is down" "$downcode"

# 3. doctor must SEE it — a green doctor on a vulnerable gate is the worst
#    possible outcome, because it is the signal an operator trusts.
doc=$(vide doctor 2>&1)
expect_contains "doctor names the below-floor binary" \
  "is BELOW the 7.15.2 security floor" "$doc"
expect_fail "doctor refuses to exit 0 on a vulnerable proxy" vide doctor

# 4. a below-floor PIN is refused — and must never walk the box BACKWARDS onto an
#    even older binary than the one it is already stuck on.
before=$(readlink -f /opt/vide/oauth2-proxy/current)
out=$(VIDE_OAUTH2_PROXY_VERSION=7.15.0 vide upgrade-sso 2>&1); rc=$?
expect_eq       "a below-floor pin is refused" 1 "$(( rc == 0 ? 0 : 1 ))"
expect_contains "…naming the security floor" "security floor" "$out"
expect_contains "…and the CVE it closes" "CVE-2026-40575" "$out"
expect_eq       "…without moving the installed binary an inch" \
  "$before" "$(readlink -f /opt/vide/oauth2-proxy/current)"

# 5. the repair path itself: upgrade-sso lifts a below-floor box over the floor,
#    FROM the crash-looping state above — not from a comfortable idle one. This
#    row is why units/oauth2-proxy.service carries a wide restart budget: with the
#    original 5x3s the seeded binary exhausted it, systemd rate-limited the unit,
#    and `systemctl restart` inside upgrade-sso then FAILED — so the documented
#    repair for a vulnerable box was itself broken, and prune never ran, leaving
#    the vulnerable build on disk. Found 2026-07-27.
VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" vide upgrade-sso >"$WORK/floorfix.out" 2>&1
fix_rc=$?
expect_eq "upgrade-sso exits 0 on a below-floor box" 0 "$fix_rc"
expect_contains "current now points above the floor" "$O2P_PIN" \
  "$(readlink -f /opt/vide/oauth2-proxy/current)"
# readlink proves the pointer moved; --version proves the BINARY did.
expect_contains "the binary behind it really is the new one" "$O2P_PIN" \
  "$(/opt/vide/oauth2-proxy/current/oauth2-proxy --version 2>&1)"
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_ok "the proxy is healthy after the floor repair" \
  curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_missing "doctor stops flagging the floor once repaired" "BELOW" "$(vide doctor 2>&1)"
# Retention keeps N and N-1 — assert the vulnerable build is not one of them, so
# a later rollback cannot quietly re-expose the box.
expect_fail "the vulnerable build is gone from disk (rollback cannot re-expose)" \
  test -e "/opt/vide/oauth2-proxy/$O2P_VULN"

# ---- 16d. the premise every guard rests on, MEASURED ----------------------------
#
# Four separate refusals in this release exist because "a daemon-reload after a
# changed ListenStream= releases the old address and binds nothing". Until this
# section that sentence was an argument from systemd's source and nothing in any
# tier had ever watched it happen. If it is false, the refusal in
# install_proxy_socket_unit defends against nothing and the converge's NOT BOUND
# warning describes a state that cannot exist — and BOTH would ship with full
# green unit coverage, because the unit tier stubs the very reader that would say
# so. This is the row that cannot be replaced by a model.
#
# Placed AFTER 16b so a leaked pin cannot satisfy that section's `expect_fail`,
# and it restores its own state with positive assertions rather than `|| true`.
echo
echo "== 16d. the reload premise, and the move refusal =="

cp /etc/systemd/system/vide-oauth2-proxy.socket "$WORK/sock.good"
cp /etc/vide/sso/fleet.env "$WORK/fleet.good"
holders() { PYTHONPATH="$REPO/src" python3 -c \
  "from vide import system; print(sorted(system.hop_holders($1).certain))"; }
# Its OWN copy of the bind probe. §13d writes one to /tmp far above, and
# depending on it made this section fail for a reason that has nothing to do
# with the reservation — a row that dies of ENOENT reads exactly like a row
# whose subject misbehaved. A section's preconditions are its own.
#
# UNDER /tmp AND NOT $WORK, deliberately: $WORK is a `mktemp -d` owned 0700 by
# root, so the unprivileged account cannot traverse into it and the row died of
# EACCES instead — the second time in one section that a probe failed for a
# reason unrelated to its subject. Distinct filename, so it still depends on no
# other section.
cat > /tmp/try_bind_16d.py <<'TRYBIND16D'
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", 4180))
except OSError as e:
    print(__import__("errno").errorcode.get(e.errno, e.errno))
else:
    print("BOUND")
TRYBIND16D
chmod 0644 /tmp/try_bind_16d.py
expect_eq "16d precondition: systemd is holding the fleet's hop" "[0]" "$(holders 4180)"

sed -i 's|^ListenStream=127\.0\.0\.1:4180$|ListenStream=127.0.0.1:4181|' \
  /etc/systemd/system/vide-oauth2-proxy.socket
expect_fail "rot check: the ListenStream edit really applied" \
  cmp -s "$WORK/sock.good" /etc/systemd/system/vide-oauth2-proxy.socket
systemctl daemon-reload
expect_eq "the manager reports the NEW address after a bare daemon-reload" \
  "127.0.0.1:4181 (Stream)" \
  "$(systemctl show -p Listen --value vide-oauth2-proxy.socket)"
expect_eq "...and the unit still reads ACTIVE" "active" \
  "$(systemctl is-active vide-oauth2-proxy.socket)"
# THE SERVICE MUST BE STOPPED FOR THIS TO MEAN ANYTHING, and that is the whole
# subtlety of the section. systemd drops its own descriptor because the address
# no longer matches the reloaded configuration — but the PROXY still holds a dup
# of that same socket, so 4180 stays bound and reads uid 0 while the service
# runs. A row written without this stop would report "still held" and read as the
# premise being FALSE.
systemctl stop vide-oauth2-proxy.service
expect_eq "...while it is holding NEITHER address — not the old one" "[]" "$(holders 4180)"
expect_eq "...nor the new one" "[]" "$(holders 4181)"
expect_eq "an unprivileged bind on the fleet's hop now SUCCEEDS" "BOUND" \
  "$(runuser -u "$U3" -- python3 /tmp/try_bind_16d.py 2>&1 | tail -1)"

# The refusal, on a real manager. The pin moves; the unit must not follow it.
cp "$WORK/sock.good" /etc/systemd/system/vide-oauth2-proxy.socket
systemctl daemon-reload
# RESTART, NOT START, and the first draft of this section got it wrong in the
# instructive direction: the socket unit is still `active` here — holding
# nothing, because the reload above dropped its descriptor — and `systemctl
# start` on an already-active unit returns -EALREADY and reports SUCCESS without
# rebinding. That is the same mechanism the converge's NOT BOUND warning exists
# for, and it is why that warning cannot be an arm of the `not was_active`
# branch. The tier caught this harness bug through the very behaviour it tests.
systemctl restart vide-oauth2-proxy.socket vide-oauth2-proxy.service
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_eq "the reservation is back before the pin is touched" "[0]" "$(holders 4180)"
sed -i 's|^VIDE_SSO_PROXY_PORT=4180$|VIDE_SSO_PROXY_PORT=4181|' /etc/vide/sso/fleet.env
expect_contains "rot check: the pin edit really applied" "4181" \
  "$(cat /etc/vide/sso/fleet.env)"
VIDE_CODE_SERVER_PIN_LATEST=1 VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
  "$REPO/install.sh" --auth sso --user "$U1" --fqdn "$FQDN1" \
  </dev/null >"$WORK/c16d.out" 2>"$WORK/c16d.err"
expect_eq "16d's converge still exits 0 (it refuses the WRITE, never the verb)" 0 "$?"
expect_contains "…and says it refused to move the reservation" "REFUSING" \
  "$(cat "$WORK/c16d.err")"
expect_contains "the unit file on disk still names the OLD address" \
  "ListenStream=127.0.0.1:4180" \
  "$(cat /etc/systemd/system/vide-oauth2-proxy.socket)"
expect_eq "…and systemd is still holding it" "[0]" "$(holders 4180)"
# The other write that follows the pin: a routine grant must not repoint the
# instance bodies at an address nothing holds.
expect_fail "a grant refuses to repoint the fleet's authorization hop" \
  vide allow "late@$PARENT" "$U1"
expect_contains "…and the instance body still dials the held address" \
  "127.0.0.1:4180" "$(cat "/etc/vide/sso/caddy/$U1.caddy")"
expect_contains "doctor names the moved pin" "THE PIN MOVED" "$(vide doctor 2>&1)"
# The ATTRIBUTION, on the one box in the tree where the abandoned address is
# genuinely held by this box's own PID-1 reservation. The row used to say "and
# it is not this reservation" here — false, and shipped green, in the state the
# refusal family deliberately parks operators in. The natural response to that
# sentence is the containment ladder, whose every rung either takes the fleet
# down or frees the address the operator's Caddyfile still dials.
expect_contains "…and says WHO is holding the abandoned address" \
  "THIS BOX'S OWN reservation" "$(vide doctor 2>&1)"
expect_missing "…and does not accuse its own reservation of squatting" \
  "is NOT this box's reservation" "$(vide doctor 2>&1)"
# The auth host on the same box, and this whole group inverted with the change
# that made its body an import. There used to be a High finding here about WHICH
# sentence the operator got — re-paste it, or DO NOT RE-PASTE — because the block
# they pasted carried the hop, so on a moved-pin box pasting it aimed the login
# flow at an unheld address. Nobody pastes the body now: what they hold is a site
# header and an import, naming no port, so there is no sentence to choose and no
# paste to get wrong. What replaces those rows is the guarantee underneath them.
expect_missing "the converge no longer has a paste to warn about" \
  "DO NOT RE-PASTE" "$(cat "$WORK/c16d.err")"
expect_missing "…and neither does doctor" \
  "DO NOT RE-PASTE" "$(vide doctor 2>&1)"
expect_missing "…nor the verb every other message names" \
  "DO NOT RE-PASTE" "$(vide info "$U1" 2>&1 >/dev/null)"
expect_contains "…which still prints the three-line block on stdout" \
  "auth.$PARENT" "$(vide info "$U1" 2>/dev/null)"
expect_contains "…as an import of the body VIDE owns" \
  "import" "$(vide info "$U1" 2>/dev/null)"
# THE ROW THAT MATTERS ON THIS BOX. The pin has moved and the reservation refused
# to follow, so the gate is still on the OLD address — and the converge must
# DECLINE to re-render the body at the new pin rather than aim the fleet's login
# host at a port nobody serves.
expect_contains "the converge refuses to repoint the auth body off the gate" \
  "REFUSING" "$(cat "$WORK/c16d.err")"
expect_contains "…and the body on disk still dials the address being served" \
  "127.0.0.1:4180" "$(cat /etc/vide/sso/caddy/auth.caddy)"

# 16d-b: A REMOVED FRAGMENT IS STILL A LOADED RESERVATION. The premise the
# manager-first ordering rests on. The unit tier MODELS this state (a stubbed
# `unit_listen_streams` answering an address while SYSTEMD_DIR is empty, pinned
# by T149) — what it cannot do is show that a real systemd behaves that way,
# which is the whole reason the model is worth anything. This section is the
# measurement the model stands on.
rm /etc/systemd/system/vide-oauth2-proxy.socket
expect_eq "a removed unit file is still a LOADED reservation until the reload" \
  "127.0.0.1:4180 (Stream)" \
  "$(systemctl show -p Listen --value vide-oauth2-proxy.socket)"
expect_eq "…and it is still HOLDING the address" "[0]" "$(holders 4180)"
VIDE_CODE_SERVER_PIN_LATEST=1 VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
  "$REPO/install.sh" --auth sso --user "$U1" --fqdn "$FQDN1" \
  </dev/null >"$WORK/c16db.out" 2>"$WORK/c16db.err"
expect_eq "16d-b's converge still exits 0 with no fragment on disk" 0 "$?"
expect_contains "…the write is refused on the MANAGER's word, not the file's" \
  "REFUSING" "$(cat "$WORK/c16db.err")"
expect_fail "…and nothing was written back" \
  test -e /etc/systemd/system/vide-oauth2-proxy.socket
expect_eq "…and the address is still held throughout" "[0]" "$(holders 4180)"

# 16d-c: THE RELOAD IS THE RELEASE — the premise the PERMIT arm rests on. A
# fragment that is gone parses no ports, no port matches the serialized fd, and
# the descriptor is closed. 16d measures the changed-address half of this above;
# this is the absent-fragment half, and nothing measured it.
systemctl daemon-reload
expect_eq "a daemon-reload over an ABSENT fragment releases the descriptor" "" \
  "$(systemctl show -p Listen --value vide-oauth2-proxy.socket)"
# THE ADDRESS IS STILL HELD AT THIS INSTANT, AND STILL AS uid 0. The running gate
# holds a DUP of the listening socket PID 1 created, and /proc/net/tcp's uid
# column is the socket inode's i_uid — fixed at sock_alloc() from the creator's
# fsuid and never re-evaluated across exec, dup or SCM_RIGHTS. So the proxy
# inheriting fd:3 does not make the row read `vide-oauth2`; §16b measures exactly
# this and says so. Stopping the service is what actually frees it, which is why
# the release is asserted AFTER the stop rather than before.
expect_eq "…while the running gate still holds its inherited copy, as uid 0" \
  "[0]" "$(holders 4180)"
systemctl stop vide-oauth2-proxy.service
expect_eq "…and stopping the gate is what finally frees the address" "[]" \
  "$(holders 4180)"

# Restore, asserted in the affirmative so a silent no-op cannot satisfy it.
cp "$WORK/fleet.good" /etc/vide/sso/fleet.env
cp "$WORK/sock.good" /etc/systemd/system/vide-oauth2-proxy.socket
systemctl daemon-reload
systemctl restart vide-oauth2-proxy.socket vide-oauth2-proxy.service
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:4180/ping" -o /dev/null
expect_eq "16d restored: systemd holds the fleet's hop again" "[0]" "$(holders 4180)"
expect_ok "16d restored: doctor reads clean again" vide doctor

# ---- 17. guards ----------------------------------------------------------------
echo
echo "== 17. guards =="

expect_fail "destroy without --yes refuses (no tty)" vide destroy "$U2"
expect_ok "the instance survived the refused destroy" systemctl is-active --quiet "code-server@$U2"
rot_out=$(vide --yes rotate "$U1" 2>&1); rot_rc=$?
expect_ok "vide rotate on an sso instance fails" bash -c "[[ $rot_rc -ne 0 ]]"
expect_contains "…and names rotate-sso as the fleet-wide lever" "rotate-sso" "$rot_out"
mm_out=$(VIDE_CODE_SERVER_PIN_LATEST=1 "$REPO/install.sh" --auth password --user "$U1" \
  --fqdn "$FQDN1" </dev/null 2>&1); mm_rc=$?
expect_ok "a password converge onto an sso instance fails (mode is immutable)" bash -c "[[ $mm_rc -ne 0 ]]"
expect_contains "…and names the reinstall path" "destroy" "$mm_out"

# ---- 18. destroy: the tombstone (a dangling import takes down ALL sites) --------
echo
echo "== 18. destroy =="

vide --yes destroy "$U2" >/dev/null 2>&1
expect_eq "destroy of an sso instance exits 0" 0 "$?"
expect_ok "the imported caddy body still EXISTS (never delete: a dangling import kills every site)" \
  test -f "/etc/vide/sso/caddy/$U2.caddy"
expect_contains "…and is a 410 tombstone" "respond" "$(cat "/etc/vide/sso/caddy/$U2.caddy")"
expect_ok "caddy still loads its config after the destroy" \
  /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
expect_fail "the allow-list is gone" test -e "/etc/vide/sso/allowlists/$U2"
expect_ok "the destroyed user's \$HOME survives" test -d "/home/$U2"
expect_ok "the shared proxy SURVIVES the last-but-one instance destroy (durable singleton)" \
  systemctl is-active --quiet vide-oauth2-proxy.service

report_summary
