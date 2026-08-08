#!/usr/bin/env bash
# The reboot-persistence gate: does the fleet come back BY ITSELF?
#
# Why it exists: every other tier asserts state on a box that has been running
# continuously since the install. `systemctl enable` is issued and its exit code
# checked, but no tier has ever proven the claim that flag actually makes — that
# after a power cycle, the instances, the shared SSO proxy and the operator's
# caddy all return to active WITHOUT anyone logging in. For a box whose whole
# job is to host somebody's IDE, "survives a reboot" is not a nice-to-have.
#
# TWO PHASES, because a script cannot outlive the reboot it triggers:
#     sudo VIDE_DISPOSABLE_BOX=1 tests/host-smoke/reboot-persistence.sh --before
#     sudo reboot                    # …wait for the box…
#     sudo VIDE_DISPOSABLE_BOX=1 tests/host-smoke/reboot-persistence.sh --after
#
# --before records the units' enablement, their live state and THIS boot's
# boot_id into a state file under /var/lib (which survives a reboot; /run and
# /tmp do not — that is the point). --after asserts against it.
#
# The boot_id comparison is load-bearing, not decoration: without it, running
# --after WITHOUT rebooting would pass every row trivially, and the gate would
# certify a reboot that never happened.
#
# Runs on the fleet host-smoke leaves behind — same fleet gate as live-fleet.sh.
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE=/var/lib/vide-reboot-probe

PHASE=${1:-}
case "$PHASE" in
  --before|--after) ;;
  *) printf 'usage: %s --before | --after   (reboot in between)\n' "$0" >&2; exit 64 ;;
esac

if [[ -f /run/.containerenv || -f /.dockerenv ]]; then
  printf 'FATAL: a container cannot be rebooted the way a box is — this gate is\n' >&2
  printf '       host-only.\n' >&2
  exit 78
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'FATAL: needs root (reads unit state, writes %s): sudo %s\n' "$STATE" "$0" >&2
  exit 77
fi
if [[ "${VIDE_DISPOSABLE_BOX:-}" != 1 ]]; then
  printf 'FATAL: refusing — this gate is walked around a REAL reboot of the host.\n' >&2
  printf '       If this box is disposable, re-run with VIDE_DISPOSABLE_BOX=1.\n' >&2
  exit 78
fi

U1=hsttest
U2=hsttest2
PROXY_PORT=4180
UNITS=("code-server@$U1.service" "code-server@$U2.service" \
       vide-oauth2-proxy.service caddy.service)

fleet_missing() { printf 'FATAL: %s — run tests/host-smoke/run.sh on this box first.\n' "$1" >&2; exit 75; }
[[ -d /etc/vide ]]                                 || fleet_missing "no /etc/vide"
[[ -f /etc/vide/$U1.env && -f /etc/vide/$U2.env ]] || fleet_missing "the $U1/$U2 fleet is not installed"

# shellcheck source=../support/report.sh
. "$REPO/tests/support/report.sh"

expect_eq() { # <name> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
expect_ne() { # <name> <not-expected> <actual>
  if [[ "$2" != "$3" ]]; then ok "$1"; else bad "$1 (expected a change, still '$3')"; fi
}
expect_ok() { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else bad "$n (command failed: $*)"; fi; }
retry_until() { local deadline=$(( SECONDS + $1 )); shift
  while (( SECONDS < deadline )); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

# The fixture IdP must OUTLIVE the reboot, or this gate measures the stand
# instead of the product: oauth2-proxy resolves its OIDC issuer during STARTUP
# and exits 1 when that fails, so a dead issuer leaves the proxy `failed` after
# every boot and the persistence row would be red for a reason that has nothing
# to do with `systemctl enable`. host-smoke runs its IdP as a foreground child
# and shreds the key on exit; here it needs a unit of its own, ordered ahead of
# the proxy. Installed ONLY when the configured issuer is loopback — on a box
# pointed at real Google there is nothing to stand in for.
ISSUER=$(grep -oP '(?<=^oidc_issuer_url = ")[^"]+' /etc/vide/sso/proxy.toml 2>/dev/null)
FIXTURE_DIR=/var/lib/vide-fixture-idp
FIXTURE_UNIT=/etc/systemd/system/vide-fixture-idp.service

install_fixture_idp() {
  local port=${ISSUER##*:}
  install -d -m 0700 "$FIXTURE_DIR"
  [[ -s "$FIXTURE_DIR/idp.key" ]] ||
    ( umask 077; openssl genrsa -out "$FIXTURE_DIR/idp.key" 2048 2>/dev/null )
  [[ -s "$FIXTURE_DIR/control" ]] ||
    ( umask 077; printf 'alice@example.test\n' > "$FIXTURE_DIR/control" )
  # 0600: the (fake) client secret rides on ExecStart, so it lands in the live
  # process's world-readable /proc/<pid>/cmdline. That is tolerable ONLY because
  # this is a disposable gate box and the value is a self-labelling fixture —
  # never a pattern to copy into anything VIDE ships.
  ( umask 077; cat > "$FIXTURE_UNIT" <<UNIT
[Unit]
Description=fixture OIDC IdP (host-smoke gate ONLY — never ship this)
# Ordered AHEAD of the proxy so the reboot row measures VIDE's own persistence
# rather than a race against this stand-in.
Before=vide-oauth2-proxy.service

[Service]
Type=exec
ExecStart=/usr/bin/python3 $REPO/tests/sso-mode/fake-idp.py \\
  --issuer=$ISSUER --port=$port --key=$FIXTURE_DIR/idp.key \\
  --client-id=vide-gate.apps.googleusercontent.com \\
  --client-secret=GOCSPX-fake-gate-secret-do-not-ship \\
  --control=$FIXTURE_DIR/control
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  )
  systemctl daemon-reload
  systemctl enable --now vide-fixture-idp.service >/dev/null 2>&1
}

# ---- --before: record ----------------------------------------------------------
if [[ "$PHASE" == --before ]]; then
  echo "== recording the pre-reboot state =="
  if [[ "$ISSUER" == http://127.0.0.1:* ]]; then
    echo "  info the proxy points at a loopback fixture issuer ($ISSUER) —"
    echo "  info installing it as a boot-persistent unit for the reboot"
    install_fixture_idp
    retry_until 15 curl -sf "$ISSUER/.well-known/openid-configuration" -o /dev/null
    expect_ok "the fixture IdP answers discovery" \
      curl -sf "$ISSUER/.well-known/openid-configuration" -o /dev/null
    # The proxy is only `failed` right now because the issuer was gone; give it
    # a clean start so the recorded state is honest.
    systemctl reset-failed vide-oauth2-proxy.service 2>/dev/null
    systemctl start vide-oauth2-proxy.service 2>/dev/null
    retry_until 20 systemctl is-active --quiet vide-oauth2-proxy.service
  fi
  ( umask 077
    printf 'boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
    for u in "${UNITS[@]}"; do
      printf '%s\tenabled=%s\tactive=%s\n' "$u" \
        "$(systemctl is-enabled "$u" 2>&1)" "$(systemctl is-active "$u" 2>&1)"
    done
  ) > "$STATE"
  cat "$STATE"
  # A recording where nothing was enabled or active would make --after vacuous.
  live=$(grep -c 'active=active' "$STATE")
  expect_eq "all ${#UNITS[@]} units are active BEFORE the reboot" "${#UNITS[@]}" "$live"
  enab=$(grep -c 'enabled=enabled' "$STATE")
  expect_eq "all ${#UNITS[@]} units are enabled BEFORE the reboot" "${#UNITS[@]}" "$enab"
  echo
  echo "  next: sudo reboot   — then re-run this script with --after"
  report_summary
  exit $?
fi

# ---- --after: assert -----------------------------------------------------------
echo "== asserting the fleet came back by itself =="
[[ -s "$STATE" ]] || { printf 'FATAL: no %s — run --before first.\n' "$STATE" >&2; exit 75; }

BOOT_BEFORE=$(sed -n 's/^boot_id=//p' "$STATE")
expect_ne "the box REALLY rebooted (boot_id changed)" \
  "$BOOT_BEFORE" "$(cat /proc/sys/kernel/random/boot_id)"

# Fixture first: if the stand-in issuer did not come back, the proxy row below
# says nothing about VIDE and the operator should be told which one broke.
if [[ -f "$FIXTURE_UNIT" ]]; then
  retry_until 30 systemctl is-active --quiet vide-fixture-idp.service
  expect_ok "(fixture) the stand-in IdP came back after the reboot" \
    systemctl is-active --quiet vide-fixture-idp.service
fi

# systemd finishes bringing units up asynchronously; a bounded wait is not
# leniency, it is the difference between "came back" and "came back instantly".
for u in "${UNITS[@]}"; do retry_until 60 systemctl is-active --quiet "$u"; done

while IFS=$'\t' read -r unit enab act; do
  [[ "$unit" == boot_id=* || -z "$unit" ]] && continue
  want_enabled=${enab#enabled=}
  want_active=${act#active=}
  [[ "$want_enabled" == enabled ]] &&
    expect_eq "$unit is still enabled after the reboot" \
      enabled "$(systemctl is-enabled "$unit" 2>&1)"
  [[ "$want_active" == active ]] &&
    expect_eq "$unit came back ACTIVE with no human intervention" \
      active "$(systemctl is-active "$unit" 2>&1)"
done < "$STATE"

# Unit state is necessary but not sufficient: the runtime plumbing lives in
# /run, which the reboot wiped. These rows prove it was rebuilt.
expect_ok "$U1's socket was recreated under the wiped /run" \
  test -S "/run/vide/$U1/code-server.sock"
expect_ok "$U2's socket was recreated under the wiped /run" \
  test -S "/run/vide/$U2/code-server.sock"
# …and RE-FROZEN. The freeze is per-activation state: RuntimeDirectory is
# recreated owned by the instance user on every start, and ExecStartPost takes it
# back once the socket exists. A reboot is the only place that whole cycle runs
# unattended, for every instance at once, which is also the case no container tier
# can reproduce — so this is the row that says the control survives the event it
# was least tested against.
for u in "$U1" "$U2"; do
  expect_eq "$u's socket directory was re-frozen after the reboot" "2750 root:vide-proxy" \
    "$(stat -c '%a %U:%G' "/run/vide/$u" 2>/dev/null)"
  # NOT `stat -c %F` against the English literal `socket`: that field is
  # gettext-translated, and this is the one tier that runs on a REAL host under
  # sudo, which preserves the operator's LANG. `test -S` asks the same question
  # in the shell, in no language. The unit learned this the hard way one commit
  # earlier; a test that reintroduces the bug it pins is worse than no test.
  expect_ok "…and the path is still a socket, not something else" \
    test -S "/run/vide/$u/code-server.sock"
  expect_eq "…and the socket itself is still $u's" "$u:vide-proxy 660" \
    "$(stat -c '%U:%G %a' "/run/vide/$u/code-server.sock" 2>/dev/null)"
done
# The socket-wait budget under BOOT CONTENTION is the load-bearing unrun
# assertion of the freeze. Record what this
# box actually took, so the 45s in the unit stops being a reasoned number and
# becomes a measured one. Not an assertion: one observation is evidence, not a
# threshold, and a threshold guessed from one box is how a budget gets tightened
# into an outage.
for u in "$U1" "$U2"; do
  printf '    [observation] %s reached active at %s\n' "$u" \
    "$(systemctl show -p ActiveEnterTimestamp --value "code-server@$u.service" 2>/dev/null)"
done
printf '    [observation] userspace was up at %s\n' \
  "$(systemctl show -p UserspaceTimestamp --value 2>/dev/null)"
retry_until 30 curl -sf --max-time 5 "http://127.0.0.1:$PROXY_PORT/ping" -o /dev/null
expect_ok "the shared proxy answers /ping after the reboot" \
  curl -sf --max-time 5 "http://127.0.0.1:$PROXY_PORT/ping" -o /dev/null

echo
echo "  next: re-run live-fleet.sh — it proves a full login still works on the"
echo "        rebooted box, which unit state alone cannot show."
report_summary
