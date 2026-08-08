#!/usr/bin/env bash
# Black-box assertions for the dedicated-'vide' journey (bare root, no
# --user, no VIDE_USER, VIDE_ALLOW_ROOT unset) on a minimal image without
# the sudo package. See run.sh for why this lives outside tests/integration/.
set -uo pipefail

# Same double-proof refusal as the arbiter: this script mutates system state
# and must only run inside a throwaway container.
if [[ ! -f /run/.containerenv && ! -f /.dockerenv ]] || [[ -z "${VIDE_IN_THROWAWAY_CONTAINER:-}" ]]; then
  printf 'FATAL: refusing to run — this test mutates system state and must only run\n' >&2
  printf '       inside the throwaway container built by tests/vide-branch/run.sh.\n' >&2
  exit 78   # EX_CONFIG
fi

REPO=${VIDE_REPO:-/vide}
FQDN=vide.example.test

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

WORK=$(mktemp -d /dev/shm/vide-branch.XXXXXX)
chmod 700 "$WORK"
LOGIN_PW_FILE="$WORK/login.pw"
CS_PW_FILE="$WORK/cs.pw"

# bare-root invocation: strip every steering variable the harness might carry
# (VIDE_DRY_RUN too — the bootstrap shim itself reads it, install.sh:18)
bare_root() { env -u VIDE_USER -u VIDE_ALLOW_ROOT -u SUDO_USER -u VIDE_DRY_RUN "$@"; }

# ---- 1. anti-vacuous precondition: the deceptive minimal-image state --------
# The GROUP exists (base-passwd gid 27) while the PACKAGE is absent — exactly
# what made `useradd -G sudo` succeed and the failure surface a minute later
# at visudo. If the base image ever gains sudo, this goes red instead of the
# whole scenario going silently vacuous.
expect_fail "precondition: no sudo binary" command -v sudo
expect_fail "precondition: no visudo binary" test -x /usr/sbin/visudo
expect_ok   "precondition: the sudo GROUP exists regardless" getent group sudo

# python3 is the shim's own bootstrap dependency (a real box usually has it);
# install it FIRST so the dry-run leg previews the PYTHON steps instead of
# stopping at the shim's "cannot preview without python3". This must not
# disturb the fixture: python3 does not pull the sudo package.
DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 >/dev/null 2>&1
expect_ok   "python3 bootstrap installed" command -v python3
expect_fail "python3 bootstrap left the box still sudo-less" command -v sudo

# ---- 2. dry-run first, on the (otherwise) untouched box ---------------------
# The pre-fix code DIED here: install_sudoers ran visudo unconditionally.
DRY_ERR="$WORK/dry.err"
bare_root "$REPO/install.sh" --dry-run --fqdn "$FQDN" </dev/null >/dev/null 2>"$DRY_ERR"
expect_eq "dry-run exits 0 on a sudo-less box" 0 "$?"
expect_contains "dry-run narrates the ensure-sudo step" \
  "apt-get install -y sudo" "$(cat "$DRY_ERR")"
expect_fail "dry-run created no user" id vide
expect_fail "dry-run wrote no sudoers drop-in" test -e /etc/sudoers.d/vide-vide
expect_fail "dry-run wrote no state dir" test -e /etc/vide

# ---- 3. the real bare-root install ------------------------------------------
INSTALL_ERR="$WORK/install.err"
INSTALL_OUT="$WORK/install.out"
VIDE_CODE_SERVER_PIN_LATEST=1 bare_root "$REPO/install.sh" --fqdn "$FQDN" \
  </dev/null >"$INSTALL_OUT" 2>"$INSTALL_ERR"
install_rc=$?

# Capture BOTH one-time passwords, then redact — before any failure dump.
# Order in the stream: login/sudo first (vide branch), code-server second.
( umask 077
  grep -F 'SHOWN ONCE' "$INSTALL_ERR" | sed -n 's/.*): //p' | sed -n 1p | tr -d '\n' > "$LOGIN_PW_FILE"
  grep -F 'SHOWN ONCE' "$INSTALL_ERR" | sed -n 's/.*): //p' | sed -n 2p | tr -d '\n' > "$CS_PW_FILE" )
sed -i 's/\(SHOWN ONCE[^)]*)\): .*/\1: [REDACTED]/' "$INSTALL_ERR"

expect_eq "bare-root install exits 0" 0 "$install_rc"
if (( install_rc != 0 )); then
  printf '  --- install stderr (tail, passwords redacted) ---\n' >&2
  tail -30 "$INSTALL_ERR" >&2
  report_summary; exit 1
fi

expect_contains "the bare-root fallback warn fired" \
  "using dedicated non-root user 'vide'" "$(cat "$INSTALL_ERR")"
expect_eq "exactly TWO SHOWN-ONCE secrets (login/sudo + code-server)" 2 \
  "$(grep -cF 'SHOWN ONCE' "$INSTALL_ERR")"
if [[ -s "$LOGIN_PW_FILE" && -s "$CS_PW_FILE" ]]; then
  if cmp -s "$LOGIN_PW_FILE" "$CS_PW_FILE"; then
    bad "the two secrets must differ"
  else
    ok "the two secrets differ"
  fi
else
  bad "could not capture both SHOWN-ONCE secrets"
fi

expect_ok "user vide exists" id vide
expect_eq "vide's shell is bash" "/bin/bash" "$(getent passwd vide | cut -d: -f7)"
expect_contains "vide is in the sudo group" "vide" "$(getent group sudo)"
expect_ok "visudo now exists (the fix's core claim)" test -x /usr/sbin/visudo
expect_ok "sudo package installed" command -v sudo
expect_eq "drop-in mode/owner" "440 root:root" \
  "$(stat -c '%a %U:%G' /etc/sudoers.d/vide-vide 2>/dev/null)"
expect_contains "drop-in kills the warm timestamp" "timestamp_timeout=0" \
  "$(cat /etc/sudoers.d/vide-vide 2>/dev/null)"
expect_ok "drop-in passes visudo" /usr/sbin/visudo -cf /etc/sudoers.d/vide-vide
expect_ok "pwset marker exists" test -f /etc/vide/vide.pwset
expect_eq "pwset marker is an EMPTY 0600 file (never the plaintext)" "600 0" \
  "$(stat -c '%a %s' /etc/vide/vide.pwset 2>/dev/null)"

# ---- 4. password-sudo works END TO END --------------------------------------
# The assertion that makes "sudo group without sudo package" impossible to
# ship again: the captured login password must actually authenticate sudo.
sudo_with_pw() { # <pw-file> — rc of `sudo true` as vide, password on stdin
  runuser -u vide -- sudo -S -k -p '' true < "$1" >/dev/null 2>&1
}
expect_ok "vide's password-sudo authenticates with the SHOWN-ONCE password" \
  sudo_with_pw "$LOGIN_PW_FILE"
printf 'wrong-password-000\n' > "$WORK/wrong.pw"
expect_fail "a wrong password is refused" sudo_with_pw "$WORK/wrong.pw"
# timestamp_timeout=0 semantics need a DISCRIMINATING shape: `sudo -k cmd`
# never records a cached credential (sudo(8)), so a plain "-k then -n" pair
# fails on ANY config — vacuous. Warm up WITHOUT -k and probe -n inside ONE
# session (same sh parent → same timestamp key even with no tty); AUTH_OK is
# the control proving the warm-up really authenticated, COLD is the verdict.
ts_probe=$(runuser -u vide -- sh -c \
  'sudo -S -p "" true 2>/dev/null && echo AUTH_OK && { sudo -n true 2>/dev/null && echo WARM || echo COLD; }' \
  < "$LOGIN_PW_FILE")
expect_contains "timestamp probe: the warm-up sudo authenticated (control)" \
  "AUTH_OK" "$ts_probe"
expect_contains "no warm timestamp survives a REAL sudo (timestamp_timeout=0)" \
  "COLD" "$ts_probe"

# ---- 5. instance sanity, lean (the arbiter owns the toolchain axis) ---------
expect_ok "code-server@vide active" systemctl is-active --quiet code-server@vide
PORT=$(sed -n 's/^VIDE_PORT=//p' /etc/vide/vide.env 2>/dev/null)
if [[ -n "$PORT" ]]; then
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$PORT/healthz" 2>/dev/null || printf '000')
  expect_eq "healthz answers on loopback" 200 "$code"
  expect_contains "listener is loopback-only" "127.0.0.1:$PORT" \
    "$(ss -Htln | awk '{print $4}')"
else
  bad "no VIDE_PORT record in /etc/vide/vide.env"
fi
expect_contains "stdout carries the Caddy snippet" \
  "reverse_proxy 127.0.0.1:" "$(cat "$INSTALL_OUT")"

# ---- 6. idempotence of the new provisioning shape ----------------------------
sha_before=$(sha256sum /etc/sudoers.d/vide-vide | cut -d' ' -f1)
SECOND_ERR="$WORK/second.err"
VIDE_CODE_SERVER_PIN_LATEST=1 bare_root "$REPO/install.sh" --fqdn "$FQDN" \
  </dev/null >/dev/null 2>"$SECOND_ERR"
rc2=$?
expect_eq "second bare-root run exits 0" 0 "$rc2"
expect_eq "no NEW login-password line on re-run (marker guard)" 0 \
  "$(grep -cF "login/sudo password" "$SECOND_ERR")"
expect_eq "no SHOWN-ONCE line of ANY kind on a converge" 0 \
  "$(grep -cF "SHOWN ONCE" "$SECOND_ERR")"
sed -i 's/\(SHOWN ONCE[^)]*)\): .*/\1: [REDACTED]/' "$SECOND_ERR"
expect_eq "sudoers drop-in unchanged" \
  "$sha_before" "$(sha256sum /etc/sudoers.d/vide-vide | cut -d' ' -f1)"

rm -rf "$WORK"
report_summary
