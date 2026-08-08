#!/usr/bin/env bash
# The host-smoke gate: the AUTOMATABLE residue of tests/manual/sso-smoke.md,
# walked on a REAL, DISPOSABLE box — never in a container.
#
# Why it exists: the sso-mode gate runs under rootless podman, which cannot
# grant the namespace/seccomp/capability privileges the shipped oauth2-proxy
# unit's hardening needs, so that gate neutralizes the sandboxing with a
# GATE-ONLY drop-in and proves the functional surface. This tier is the
# inverse: a real rootful systemd, the SHIPPED unit untouched, on a box whose
# whole value is that it can be thrown away. It automates sso-smoke.md:
#   §0 refusal-before-mutation on a box that is pristine for real,
#   §3 the client secret never appearing in any /proc/<pid>/cmdline,
#   §8 the shipped unit reaching active(running) + /ping under full hardening,
#      with `systemd-analyze security` reported for the record,
# plus the rotate/rotate-sso boundary and the join-existing narration (§5/§6).
# What deliberately stays MANUAL in sso-smoke.md: everything needing a real
# browser, real Google, real DNS/TLS, or a human at a terminal (§1,2,4,7,9).
#
# ROLLBACK CONTRACT: this script MUTATES THE HOST (apt packages, users, units,
# /etc/vide, /opt/vide) and does not clean up after itself — the operator
# restores the box from a baseline snapshot (your provider's console) between
# rounds.
# The refusal below therefore demands an explicit, per-invocation waiver.
#
# Needs: root, network, python3 + openssl (fixture IdP), a pristine box.
# Run: sudo VIDE_DISPOSABLE_BOX=1 tests/host-smoke/run.sh
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---- refusals: the exact INVERSE of the container tiers -----------------------
if [[ -f /run/.containerenv || -f /.dockerenv ]]; then
  printf 'FATAL: host-smoke asserts REAL-host behavior (the shipped unit under a\n' >&2
  printf '       rootful systemd); a container proves nothing here. Use the\n' >&2
  printf '       sso-mode gate inside containers.\n' >&2
  exit 78   # EX_CONFIG
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'FATAL: host-smoke needs root (real installs, real units): sudo %s\n' "$0" >&2
  exit 77
fi
if [[ "${VIDE_DISPOSABLE_BOX:-}" != 1 ]]; then
  printf 'FATAL: refusing — this run mutates the host irreversibly (no cleanup;\n' >&2
  printf '       rollback is a snapshot restore). If this box is disposable and a\n' >&2
  printf '       baseline snapshot exists, re-run with VIDE_DISPOSABLE_BOX=1.\n' >&2
  exit 78
fi
# Pristine gate: §0 is meaningless on a dirty box, and a dirty box means the
# operator forgot to restore the snapshot — tell them, never "fix" it here.
for w in /etc/vide /opt/vide /etc/systemd/system/vide-oauth2-proxy.service; do
  if [[ -e "$w" ]]; then
    printf 'FATAL: %s exists — the box is not pristine. Restore the baseline\n' "$w" >&2
    printf '       snapshot and re-run.\n' >&2
    exit 75   # EX_TEMPFAIL: the box, not the code
  fi
done
if id vide >/dev/null 2>&1 || getent group vide-proxy >/dev/null 2>&1; then
  printf 'FATAL: a vide user/group exists — restore the baseline snapshot.\n' >&2
  exit 75
fi

# shellcheck source=../support/report.sh
. "$REPO/tests/support/report.sh"

expect_eq() { # <name> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
expect_ok()   { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else bad "$n (command failed: $*)"; fi; }
expect_fail() { local n=$1; shift; if "$@" >/dev/null 2>&1; then bad "$n (command unexpectedly succeeded: $*)"; else ok "$n"; fi; }
expect_contains() { # <name> <needle> <haystack>
  if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 (no '$2' in: ${3:0:200})"; fi
}
expect_missing() { # <name> <needle> <haystack>
  if [[ "$3" != *"$2"* ]]; then ok "$1"; else bad "$1 (unexpected '$2' present)"; fi
}
retry_until() { # <seconds> <cmd...> — bounded; a timeout is a FINDING
  local deadline=$(( SECONDS + $1 )); shift
  while (( SECONDS < deadline )); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

PARENT=vide.example.test
U1=hsttest
U2=hsttest2
FQDN1=$U1.$PARENT
FQDN2=$U2.$PARENT
IDP_PORT=8555
IDP_ISSUER=http://127.0.0.1:$IDP_PORT
CLIENT_ID=vide-gate.apps.googleusercontent.com
CLIENT_SECRET=GOCSPX-fake-gate-secret-do-not-ship
O2P_PIN=7.15.3
PROXY_PORT=4180

# Secrets on tmpfs only, 0600, shredded on exit, never on argv (same discipline
# as the sso-mode gate: /proc/<pid>/cmdline is world-readable).
SECRET_DIR=$(umask 077; mktemp -d /dev/shm/vide-host.XXXXXX) || exit 71  # no tmpfs, no run
WORK=$(mktemp -d)
IDP_PID=""
SCAN_PID=""
cleanup() {
  [[ -n "$IDP_PID" ]] && kill "$IDP_PID" 2>/dev/null
  [[ -n "$SCAN_PID" ]] && kill "$SCAN_PID" 2>/dev/null
  find "$SECRET_DIR" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$SECRET_DIR" "$WORK"
}
trap cleanup EXIT
trap 'trap - INT;  cleanup; kill -INT  $$' INT
trap 'trap - TERM; cleanup; kill -TERM $$' TERM

SECRETS_FILE="$SECRET_DIR/sso-secrets"
IDP_KEY="$SECRET_DIR/idp.key"
IDP_CONTROL="$SECRET_DIR/idp-email"

# ---- 0. fixtures: target users + the loopback IdP ----------------------------
echo "== 0. fixtures =="
useradd -m -s /bin/bash "$U1" 2>/dev/null
useradd -m -s /bin/bash "$U2" 2>/dev/null
expect_ok "target users exist" bash -c "id $U1 && id $U2"
expect_ok "python3 present" command -v python3
expect_ok "openssl present" command -v openssl

( umask 077; openssl genrsa -out "$IDP_KEY" 2048 2>/dev/null )
expect_ok "IdP keypair generated" test -s "$IDP_KEY"
printf 'alice@example.test\n' > "$IDP_CONTROL"
python3 "$REPO/tests/sso-mode/fake-idp.py" \
  --issuer="$IDP_ISSUER" --port="$IDP_PORT" --key="$IDP_KEY" \
  --client-id="$CLIENT_ID" --client-secret="$CLIENT_SECRET" \
  --control="$IDP_CONTROL" >"$WORK/idp.log" 2>&1 &
IDP_PID=$!
retry_until 15 curl -sf "$IDP_ISSUER/.well-known/openid-configuration" -o /dev/null
expect_ok "fake IdP discovery answers" \
  curl -sf "$IDP_ISSUER/.well-known/openid-configuration" -o /dev/null

( umask 077
  printf 'VIDE_SSO_CLIENT_ID=%s\nVIDE_SSO_CLIENT_SECRET=%s\n' \
    "$CLIENT_ID" "$CLIENT_SECRET" > "$SECRETS_FILE" )
# The scanner's needle lives in a 0600 tmpfs file, never on the scanner's own
# argv — otherwise the scan itself would smear the secret over world-readable
# /proc/<pid>/cmdline ~5x/sec and could self-hit under PID reuse.
NEEDLE="$SECRET_DIR/scan-needle"
( umask 077; printf '%s\n' "$CLIENT_SECRET" > "$NEEDLE" )

# ---- 1. sso-smoke §0: refusal before mutation, on a REALLY pristine box -------
echo
echo "== 1. refusal before mutation (sso-smoke §0, real box) =="
# argon2 is a VIDE apt prerequisite, so "did a refusal install it?" is a
# mutation witness — but only relative to THIS box's baseline (a snapshot that
# ever hosted a real install may carry it already; found on round 1).
argon2_state() { dpkg -s argon2 >/dev/null 2>&1 && echo present || echo absent; }
ARGON2_BASE=$(argon2_state)
untouched() { # <label> — the durable artifacts a VIDE SSO install would create
  expect_fail "$1: no /etc/vide"           test -e /etc/vide
  expect_fail "$1: no /opt/vide"           test -e /opt/vide
  expect_fail "$1: no vide user"           id vide
  expect_fail "$1: no vide-proxy group"    getent group vide-proxy
  expect_fail "$1: no proxy unit file"     test -e /etc/systemd/system/vide-oauth2-proxy.service
  expect_eq   "$1: argon2 state unchanged ($ARGON2_BASE)" "$ARGON2_BASE" "$(argon2_state)"
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
  VIDE_SSO_ISSUER_URL="$IDP_ISSUER" VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" \
    "$REPO/install.sh" "$@" <"$stdin" >"$WORK/r1.out" 2>"$WORK/r1.err"; rc=$?
  expect_missing  "…echoes no secret" "$CLIENT_SECRET" "$(cat "$WORK/r1.err" "$WORK/r1.out")"
  sed -i "s/$CLIENT_SECRET/[REDACTED]/g" "$WORK/r1.err" "$WORK/r1.out"
  expect_eq       "missing/bad --$miss exits $want" "$want" "$rc"
  expect_contains "…names the flag ($needle)" "$needle" "$(cat "$WORK/r1.err")"
  untouched "after the --$miss refusal"
done

# ---- 2. the real install, with a live /proc secret scan (sso-smoke §3) --------
echo
echo "== 2. sso install on the real host + /proc/*/cmdline secret scan =="
# The sampler races every process spawn during the install: any appearance of
# the secret on ANY argv is a finding. NUL-tolerant read via tr.
SCAN_HITS="$WORK/cmdline-hits"
# The fixture IdP is the ONE sanctioned argv carrier of the (fake) secret —
# it mirrors the hermetic gate's invocation and is out of scope here; skip its
# pid so the scan asserts over VIDE's processes only (found on round 1: 54
# self-hits, zero from VIDE).
( while :; do
    for f in /proc/[0-9]*/cmdline; do
      [[ "$f" == "/proc/$IDP_PID/cmdline" ]] && continue
      tr '\0' ' ' <"$f" 2>/dev/null | grep -qF -f "$NEEDLE" &&
        { echo "HIT: $f: $(tr '\0' ' ' <"$f" 2>/dev/null | head -c 200)"; }
    done
    sleep 0.2
  done >"$SCAN_HITS" 2>/dev/null ) &
SCAN_PID=$!

VIDE_CODE_SERVER_PIN_LATEST=1 \
VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" \
  "$REPO/install.sh" --auth sso --user "$U1" --fqdn "$FQDN1" \
    --sso-client-id "$CLIENT_ID" --sso-secrets-stdin --sso-allow alice@example.test \
    <"$SECRETS_FILE" >"$WORK/install.out" 2>"$WORK/install.err"
install_rc=$?
# ORDERING IS LOAD-BEARING: the scanner must be dead (kill+wait) BEFORE any
# sed carries the secret on its argv where the scanner could observe it.
kill "$SCAN_PID" 2>/dev/null; wait "$SCAN_PID" 2>/dev/null; SCAN_PID=""
sed -i "s/$CLIENT_SECRET/[REDACTED]/g" "$WORK/install.err" "$WORK/install.out" "$SCAN_HITS"

expect_eq "sso install exits 0 on the real host" 0 "$install_rc"
if (( install_rc != 0 )); then
  printf '  --- install stderr (tail, secret redacted) ---\n' >&2
  tail -40 "$WORK/install.err" >&2
  report_summary; exit 1
fi
expect_ok "the scan log exists (the sampler actually ran)" test -f "$SCAN_HITS"
expect_eq "the client secret NEVER appeared on any /proc cmdline" 0 \
  "$(wc -l <"$SCAN_HITS")"
(( $(wc -l <"$SCAN_HITS") )) && head -3 "$SCAN_HITS" >&2   # redacted above
expect_eq "a passwordless install prints ZERO SHOWN-ONCE secrets" 0 \
  "$(grep -cF 'SHOWN ONCE' "$WORK/install.err")"
expect_ok "instance unit is active" systemctl is-active --quiet "code-server@$U1.service"
expect_ok "rendered caddy body exists" test -s "/etc/vide/sso/caddy/$U1.caddy"
# Deterministic, race-free complement to the sampler: the LONG-LIVED proxy's
# own argv provably carries no secret (the sampler can only say it never saw one).
proxy_argv() {
  tr '\0' ' ' <"/proc/$(systemctl show -p MainPID --value vide-oauth2-proxy.service)/cmdline" 2>/dev/null
}
expect_missing "the live proxy's argv carries no secret" "$CLIENT_SECRET" "$(proxy_argv)"

# ---- 3. sso-smoke §8: the SHIPPED unit under a real rootful systemd -----------
echo
echo "== 3. shipped-unit hardening under real systemd (sso-smoke §8) =="
expect_fail "no relaxation drop-in exists (the unit is the SHIPPED one)" \
  test -e /etc/systemd/system/vide-oauth2-proxy.service.d
expect_ok "vide-oauth2-proxy is active (running) under full hardening" \
  systemctl is-active --quiet vide-oauth2-proxy.service
if ! systemctl is-active --quiet vide-oauth2-proxy.service; then
  systemctl status vide-oauth2-proxy.service --no-pager -l 2>&1 | tail -15 >&2
fi
expect_ok "/ping answers through the hardened unit" \
  curl -sf --max-time 5 "http://127.0.0.1:$PROXY_PORT/ping" -o /dev/null
SEC_LINE=$(systemd-analyze security vide-oauth2-proxy.service --no-pager 2>/dev/null | tail -1)
expect_contains "systemd-analyze security parses the unit" "Overall exposure level" "$SEC_LINE"
printf '  info %s\n' "$SEC_LINE"

# ---- 4. verb boundary + join-existing (sso-smoke §5/§6) -----------------------
echo
echo "== 4. rotate boundary + join-existing =="
out=$("$REPO/vide" --yes rotate "$U1" 2>&1); rc=$?
expect_eq       "vide rotate on an SSO user refuses" 1 "$(( rc == 0 ? 0 : 1 ))"
expect_contains "…and names rotate-sso" "rotate-sso" "$out"

expect_ok "proxy.env exists before the join (de-vacuouses the sha pin)" \
  test -s /etc/vide/sso/proxy.env
PROXY_SHA_BEFORE=$(sha256sum /etc/vide/sso/proxy.env | cut -d' ' -f1)
VIDE_CODE_SERVER_PIN_LATEST=1 VIDE_SSO_ISSUER_URL="$IDP_ISSUER" \
VIDE_OAUTH2_PROXY_VERSION="$O2P_PIN" \
  "$REPO/install.sh" --no-gui --auth sso --user "$U2" --fqdn "$FQDN2" \
    --sso-allow bob@example.test </dev/null >"$WORK/join.out" 2>"$WORK/join.err"
join_rc=$?
expect_eq "join-existing (no credentials) succeeds" 0 "$join_rc"
expect_missing "…without asking for a secret" "--sso-secrets-stdin" \
  "$(cat "$WORK/join.err")"
expect_eq "proxy.env untouched by the join (cookie secret never re-minted)" \
  "$PROXY_SHA_BEFORE" "$(sha256sum /etc/vide/sso/proxy.env | cut -d' ' -f1)"
expect_missing "the proxy argv still carries no secret after the join" \
  "$CLIENT_SECRET" "$(proxy_argv)"

out=$(VIDE_SSO_ISSUER_URL="$IDP_ISSUER" "$REPO/install.sh" --no-gui --auth sso \
  --user "$U2" --fqdn "$U2.other.example" --sso-allow bob@example.test 2>&1 </dev/null); rc=$?
expect_eq       "an FQDN outside the parent domain refuses" 1 "$(( rc == 0 ? 0 : 1 ))"
expect_contains "…naming the parent domain" "$PARENT" "$out"

echo
report_summary
