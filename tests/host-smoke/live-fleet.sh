#!/usr/bin/env bash
# The live-fleet gate: does a PER-INSTANCE `vide upgrade` disturb anything it
# does not own — the other instance, or the shared SSO plane?
#
# Why it exists: "a live upgrade does not disturb other sessions" was a
# production behavior no tier exercised. The
# sso-mode gate restarts instances but never holds TWO live sessions across an
# upgrade, and host-smoke stops before anyone has logged in at all. The claim
# under test is the one an operator actually cares about: upgrading Alice's IDE
# must not sign Bob out.
#
# WHERE IT RUNS — the exact INVERSE of host-smoke's pristine gate. host-smoke
# demands a virgin box and leaves behind a two-instance SSO fleet; this tier
# demands that fleet. Run it on the same box, right after:
#     sudo VIDE_DISPOSABLE_BOX=1 tests/host-smoke/run.sh
#     sudo VIDE_DISPOSABLE_BOX=1 tests/host-smoke/live-fleet.sh
#
# ROLLBACK CONTRACT: like host-smoke, this MUTATES THE HOST (rewrites the
# operator Caddyfile, restarts the proxy, upgrades an instance) and does not
# clean up — rollback is the baseline snapshot restore.
#
# NOT covered here (deliberately): `vide rotate <sso-user>` "invalidating the
# old cookie" — in SSO mode that verb REFUSES and names rotate-sso (asserted by
# host-smoke §4), and rotate-sso is fleet-wide by design (asserted by the
# sso-mode gate). Per-instance credential rotation is a PASSWORD-mode concern.
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---- refusals ------------------------------------------------------------------
if [[ -f /run/.containerenv || -f /.dockerenv ]]; then
  printf 'FATAL: live-fleet asserts REAL-host behavior; use the sso-mode gate\n' >&2
  printf '       inside containers.\n' >&2
  exit 78   # EX_CONFIG
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'FATAL: live-fleet needs root (restarts real units): sudo %s\n' "$0" >&2
  exit 77
fi
if [[ "${VIDE_DISPOSABLE_BOX:-}" != 1 ]]; then
  printf 'FATAL: refusing — this run mutates the host irreversibly (rewrites the\n' >&2
  printf '       operator Caddyfile, upgrades an instance; no cleanup). If this box\n' >&2
  printf '       is disposable and a baseline snapshot exists, re-run with\n' >&2
  printf '       VIDE_DISPOSABLE_BOX=1.\n' >&2
  exit 78
fi

PARENT=vide.example.test
U1=hsttest
U2=hsttest2
FQDN1=$U1.$PARENT
FQDN2=$U2.$PARENT
AUTH_HOST=auth.$PARENT
EMAIL1=alice@example.test
EMAIL2=bob@example.test
IDP_PORT=8555
IDP_ISSUER=http://127.0.0.1:$IDP_PORT
CLIENT_ID=vide-gate.apps.googleusercontent.com
CLIENT_SECRET=GOCSPX-fake-gate-secret-do-not-ship
PROXY_PORT=4180
CA=/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt

# Fleet gate: the inverse of "pristine". Every miss below means the operator
# skipped host-smoke (or restored the snapshot since) — the box, not the code.
fleet_missing() { printf 'FATAL: %s — run tests/host-smoke/run.sh on this box first.\n' "$1" >&2; exit 75; }
[[ -d /etc/vide ]]                                  || fleet_missing "no /etc/vide"
[[ -f /etc/vide/$U1.env && -f /etc/vide/$U2.env ]]  || fleet_missing "the $U1/$U2 fleet is not installed"
grep -q '^VIDE_MODE=sso$' "/etc/vide/$U1.env"       || fleet_missing "$U1 is not an SSO instance"
grep -q '^VIDE_MODE=sso$' "/etc/vide/$U2.env"       || fleet_missing "$U2 is not an SSO instance"
systemctl is-active --quiet vide-oauth2-proxy.service || fleet_missing "vide-oauth2-proxy is not active"
systemctl is-active --quiet caddy.service           || fleet_missing "caddy is not active"
# The fixture identity must be the one host-smoke installed: this tier re-launches
# that same fake IdP, and a mismatched client_id would fail the redeem in a way
# that looks like a product bug. The id lives in proxy.env (0600, root) next to
# the two secrets — VIDE keeps the whole credential triple off the world-readable
# proxy.toml, so this is the only place to read it.
grep -q "^OAUTH2_PROXY_CLIENT_ID=$CLIENT_ID$" /etc/vide/sso/proxy.env \
  || fleet_missing "proxy.env carries a different client_id than the host-smoke fixture"

# shellcheck source=../support/report.sh
. "$REPO/tests/support/report.sh"

expect_eq() { # <name> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
expect_ne() { # <name> <not-expected> <actual>
  if [[ "$2" != "$3" ]]; then ok "$1"; else bad "$1 (expected a change, still '$3')"; fi
}
expect_ok()   { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else bad "$n (command failed: $*)"; fi; }
expect_contains() { # <name> <needle> <haystack>
  if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 (no '$2' in: ${3:0:200})"; fi
}
retry_until() { # <seconds> <cmd...> — bounded; a timeout is a FINDING
  local deadline=$(( SECONDS + $1 )); shift
  while (( SECONDS < deadline )); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

SECRET_DIR=$(umask 077; mktemp -d /dev/shm/vide-live.XXXXXX) || exit 71
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

IDP_KEY="$SECRET_DIR/idp.key"
IDP_CONTROL="$SECRET_DIR/idp-email"

# ---- 0. bring the fixture IdP back up -----------------------------------------
echo "== 0. fixture IdP (host-smoke killed it and shredded its key) =="
# host-smoke's cleanup trap kills the IdP and shreds its RSA key on tmpfs, but
# the installed proxy still points oidc_issuer_url at it. So a login is
# impossible until the SAME issuer answers again — with a NEW key, because the
# old one is gone. The signing KID is a fixture constant ("vide-fake-1"), so a
# proxy that cached the old JWKS would reject the new signatures under a
# familiar-looking kid: it must be restarted ONCE, before any session is
# established, so every session in this run is minted against one key.
if systemctl is-active --quiet vide-fixture-idp.service 2>/dev/null; then
  # reboot-persistence.sh installs the same fixture as a boot-persistent unit
  # (the proxy cannot survive a reboot without its issuer). Adopt it instead of
  # racing it for the port — and drive WHICH identity logs in through ITS
  # control file, or every login here would silently mint whatever identity that
  # file happens to name.
  echo "  info adopting the boot-persistent fixture IdP (vide-fixture-idp.service)"
  IDP_CONTROL=/var/lib/vide-fixture-idp/control
else
  ( umask 077; openssl genrsa -out "$IDP_KEY" 2048 2>/dev/null )
  expect_ok "IdP keypair generated" test -s "$IDP_KEY"
  printf '%s\n' "$EMAIL1" > "$IDP_CONTROL"
  python3 "$REPO/tests/sso-mode/fake-idp.py" \
    --issuer="$IDP_ISSUER" --port="$IDP_PORT" --key="$IDP_KEY" \
    --client-id="$CLIENT_ID" --client-secret="$CLIENT_SECRET" \
    --control="$IDP_CONTROL" >"$WORK/idp.log" 2>&1 &
  IDP_PID=$!
fi
retry_until 15 curl -sf "$IDP_ISSUER/.well-known/openid-configuration" -o /dev/null
expect_ok "fake IdP discovery answers" \
  curl -sf "$IDP_ISSUER/.well-known/openid-configuration" -o /dev/null
# go-oidc compares the discovery issuer byte-for-byte with the CONFIGURED one;
# assert the two agree here rather than debugging an opaque redeem failure later.
expect_eq "the IdP issuer matches the proxy's configured oidc_issuer_url" \
  "$(grep -oP '(?<=^oidc_issuer_url = ")[^"]+' /etc/vide/sso/proxy.toml)" \
  "$(curl -s "$IDP_ISSUER/.well-known/openid-configuration" \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])')"

# ---- 1. play the operator: paste the site blocks -------------------------------
echo
echo "== 1. operator paste: the site blocks VIDE emitted =="
# host-smoke never pastes them (it asserts up to the proxy's /ping), so nothing
# on this box serves the instance FQDNs yet. The blocks are taken from `vide
# info` — the product's own record-first output — and the shared auth block from
# the VIDE-owned file it names, so the harness authors no proxy policy of its
# own. local_certs: *.vide.example.test is not a real domain, so there is no ACME
# path; skip_install_trust because caddy runs unprivileged and cannot write the
# system trust store — the gate's curl trusts the harvested root explicitly.
cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.pre-live-fleet.$$" 2>/dev/null
{
  printf '{\n\tlocal_certs\n\tskip_install_trust\n}\n\n'
  # THE SHARED BLOCK COMES FROM `vide info`, NOT FROM `cat auth.caddy`. That file
  # is the auth host's BODY now — no site header, no braces of its own, because
  # the operator's Caddyfile supplies them around an `import` of it. Catting it
  # here produced a config Caddy cannot parse at all, which is a harness bug that
  # would have read as the product emitting a broken block.
  "$REPO/vide" info "$U1" 2>/dev/null \
    | sed -n '/^# --- VIDE shared SSO auth endpoint/,$p'
  printf '\n'
  # …and the SHARED block is dropped from each of them. `vide info` re-emits it
  # per user, deliberately (cli.py: the only path by which a changed block
  # reaches an already-installed fleet), and its own header says `paste ONCE for
  # the whole box`. Concatenating two users' output verbatim therefore hands
  # caddy three copies of auth.<parent> and it refuses the whole config with
  # `ambiguous site definition` — every site down, not just VIDE's. Measured:
  # this is what the tier did until 2026-08-08, and it had not been re-run since
  # `vide info` gained the re-emit on 2026-07-27, so its last green predates the
  # composition it was asserting.
  "$REPO/vide" info "$U1" 2>/dev/null | sed -n '/^# --- VIDE/,$p' \
    | sed '/^# --- VIDE shared SSO auth endpoint/,$d'
  printf '\n'
  "$REPO/vide" info "$U2" 2>/dev/null | sed -n '/^# --- VIDE/,$p' \
    | sed '/^# --- VIDE shared SSO auth endpoint/,$d'
} > /etc/caddy/Caddyfile
expect_contains "the pasted Caddyfile carries $U1's site block" \
  "$FQDN1 {" "$(cat /etc/caddy/Caddyfile)"
expect_contains "the pasted Caddyfile carries $U2's site block" \
  "$FQDN2 {" "$(cat /etc/caddy/Caddyfile)"
expect_contains "…and the shared auth endpoint" "$AUTH_HOST {" "$(cat /etc/caddy/Caddyfile)"
# …exactly once, and asserted as a config caddy will ACCEPT rather than as three
# greps that all pass on a file it refuses. Without this row the duplicate-block
# defect above surfaced as twelve reds in §2/§4/§5 — every one of them an HTTP
# 000 from a front door that never came up — which reads like the product
# signing sessions out. The same lesson §16d's probes are annotated with: a
# harness fault that mimics a subject fault costs a whole run to tell apart.
expect_eq "…exactly once (three copies is a config caddy refuses)" \
  "1" "$(grep -c "^$AUTH_HOST {" /etc/caddy/Caddyfile)"
expect_ok "the pasted Caddyfile is a config caddy accepts" \
  caddy validate --config /etc/caddy/Caddyfile

systemctl restart vide-oauth2-proxy.service   # drop the stale JWKS (see §0)
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:$PROXY_PORT/ping" -o /dev/null
expect_ok "the proxy is healthy on the fresh IdP" \
  curl -sf --max-time 5 "http://127.0.0.1:$PROXY_PORT/ping" -o /dev/null
# RESTART, never reload: supplementary group membership is read once at process
# start, so a caddy that was already running when VIDE added it to 'vide-proxy'
# cannot open the instance sockets — the classic mystery 502, and precisely the
# one-time step `vide info` instructs the operator to take. Assert the LIVE
# process carries the gid rather than trusting `id caddy`, which reads the
# database and would be green while the running process is stale.
expect_contains "caddy is a member of vide-proxy" "caddy" "$(getent group vide-proxy)"
systemctl restart caddy.service
retry_until 20 curl -sk "https://127.0.0.1/" -o /dev/null
caddy_pid=$(systemctl show -p MainPID --value caddy.service)
proxy_gid=$(getent group vide-proxy | cut -d: -f3)
if grep -qE "^Groups:.*\b$proxy_gid\b" "/proc/$caddy_pid/status" 2>/dev/null; then
  ok "the LIVE caddy process carries the vide-proxy gid"
else
  bad "caddy's live process lacks the vide-proxy gid — every IDE fetch will 502"
fi
retry_until 20 test -s "$CA"
expect_ok "caddy's internal CA is available for the gate's curl" test -s "$CA"

# ---- 2. two live sessions, one per identity ------------------------------------
echo
echo "== 2. two live sessions =="
JAR1=$WORK/alice.jar
JAR2=$WORK/bob.jar
login() { # <jar> <host> <email> — a browser-shaped login through Caddy
  local jar=$1 host=$2 email=$3
  printf '%s\n' "$email" > "$IDP_CONTROL"
  curl -s -o "$WORK/body" -w '%{http_code}' -L --max-redirs 12 \
    --cacert "$CA" --resolve "$host:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
    -b "$jar" -c "$jar" "https://$host/"
}
# A request that must NOT re-authenticate: --max-redirs 0 turns any bounce to
# /oauth2/start into a visible non-200 instead of a silently re-minted session.
# This is the whole proof technique of §4 — a live session either survives or it
# does not, with no second login to paper over it.
held() { # <jar> <host>
  curl -s -o "$WORK/held.body" -w '%{http_code}' --max-redirs 0 \
    --cacert "$CA" --resolve "$2:443:127.0.0.1" --resolve "$AUTH_HOST:443:127.0.0.1" \
    -b "$1" "https://$2/"
}

code=$(login "$JAR1" "$FQDN1" "$EMAIL1")
expect_eq "$EMAIL1 completes SSO and reaches $U1's IDE (200)" 200 "$code"
expect_contains "…and the body really is code-server" "code-server" "$(cat "$WORK/body")"
code=$(login "$JAR2" "$FQDN2" "$EMAIL2")
expect_eq "$EMAIL2 completes SSO and reaches $U2's IDE (200)" 200 "$code"
expect_contains "…and the body really is code-server" "code-server" "$(cat "$WORK/body")"

# De-vacuous the two jars: they are genuinely DIFFERENT identities, not one
# shared cookie that would make every isolation row below trivially green.
expect_eq "$EMAIL2's session is refused on $U1 (403, per-instance authz)" 403 "$(held "$JAR2" "$FQDN1")"
expect_eq "$EMAIL1's session is refused on $U2 (403, per-instance authz)" 403 "$(held "$JAR1" "$FQDN2")"

# ---- 3. the blast-radius snapshot ----------------------------------------------
echo
echo "== 3. upgrade $U1 — what must NOT move =="
mainpid() { systemctl show -p MainPID --value "$1"; }
PROXY_PID_BEFORE=$(mainpid vide-oauth2-proxy.service)
U1_PID_BEFORE=$(mainpid "code-server@$U1.service")
U2_PID_BEFORE=$(mainpid "code-server@$U2.service")
PROXY_ENV_BEFORE=$(sha256sum /etc/vide/sso/proxy.env | cut -d' ' -f1)
AUTHZ_BEFORE=$(sha256sum /etc/vide/sso/authenticated-emails | cut -d' ' -f1)

"$REPO/vide" --yes upgrade "$U1" >"$WORK/upgrade.out" 2>"$WORK/upgrade.err"
upgrade_rc=$?
expect_eq "vide upgrade $U1 exits 0" 0 "$upgrade_rc"
if (( upgrade_rc != 0 )); then tail -20 "$WORK/upgrade.err" >&2; fi

# The upgrade must really have restarted the target — otherwise every row below
# is vacuously green because nothing happened at all.
retry_until 60 systemctl is-active --quiet "code-server@$U1.service"
expect_ne "$U1 was actually restarted (its MainPID moved)" \
  "$U1_PID_BEFORE" "$(mainpid "code-server@$U1.service")"

expect_eq "the SHARED proxy was NOT restarted (same MainPID)" \
  "$PROXY_PID_BEFORE" "$(mainpid vide-oauth2-proxy.service)"
expect_eq "$U2's instance was NOT restarted (same MainPID)" \
  "$U2_PID_BEFORE" "$(mainpid "code-server@$U2.service")"
expect_eq "the cookie secret was NOT re-minted (proxy.env unchanged)" \
  "$PROXY_ENV_BEFORE" "$(sha256sum /etc/vide/sso/proxy.env | cut -d' ' -f1)"
expect_eq "the authz union was NOT rewritten (authenticated-emails unchanged)" \
  "$AUTHZ_BEFORE" "$(sha256sum /etc/vide/sso/authenticated-emails | cut -d' ' -f1)"

# ---- 4. the crown: the sessions survived ---------------------------------------
echo
echo "== 4. crown: neither live session was signed out =="
# Bob never shared anything with the upgrade but the box itself.
expect_eq "$EMAIL2's session on $U2 survives the upgrade of $U1 (200, no re-auth)" \
  200 "$(held "$JAR2" "$FQDN2")"
# Alice's own IDE restarted under her; the SESSION lives at the proxy, not in
# code-server, so her cookie must still be honoured once the socket is back.
retry_until 60 test -S "/run/vide/$U1/code-server.sock"
retry_until 30 bash -c "[[ \$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 \
  --cacert '$CA' --resolve '$FQDN1:443:127.0.0.1' -b '$JAR1' 'https://$FQDN1/') == 200 ]]"
code=$(held "$JAR1" "$FQDN1")
expect_eq "$EMAIL1's session survives the restart of her OWN instance (200, no re-auth)" \
  200 "$code"
expect_contains "…and she lands on code-server, not a proxy page" \
  "code-server" "$(cat "$WORK/held.body")"

# ---- 5. teeth: the crown rows can actually go red -------------------------------
echo
echo "== 5. teeth: a fleet-wide kill DOES sign both sessions out =="
# §4 asserts two sessions survived. That is only evidence if this harness can
# observe a session NOT surviving — otherwise "200, no re-auth" could be green
# because nothing was ever being checked. rotate-sso re-mints the cookie secret
# and is fleet-wide BY DESIGN (the stolen-cookie kill switch), so it is the
# positive control: the same two `held` probes that returned 200 above must now
# refuse to serve either IDE. Destructive to both sessions — it runs LAST.
"$REPO/vide" --yes rotate-sso >"$WORK/rotate.out" 2>"$WORK/rotate.err"
rotate_rc=$?
expect_eq "vide rotate-sso exits 0" 0 "$rotate_rc"
retry_until 20 curl -sf --max-time 5 "http://127.0.0.1:$PROXY_PORT/ping" -o /dev/null
expect_ok "the proxy is healthy after the rotation" \
  curl -sf --max-time 5 "http://127.0.0.1:$PROXY_PORT/ping" -o /dev/null
expect_ne "$EMAIL1's cookie is DEAD after rotate-sso (so §4's 200 meant something)" \
  200 "$(held "$JAR1" "$FQDN1")"
expect_ne "$EMAIL2's cookie is DEAD after rotate-sso (fleet-wide, both instances)" \
  200 "$(held "$JAR2" "$FQDN2")"
# And the kill switch is not a wrecking ball: a FRESH login still works.
code=$(login "$WORK/alice2.jar" "$FQDN1" "$EMAIL1")
expect_eq "a fresh login works after the rotation (200)" 200 "$code"

echo
report_summary
