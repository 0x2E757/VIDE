#!/usr/bin/env bash
# tests/integration/in-container.sh — the integration tier's body. Runs as root
# INSIDE a throwaway systemd container and mutates it freely. Never on a host.
#
# WHY THIS EXISTS: static checks are structurally blind to how a downloaded tool
# behaves once installed. Three toolchain bugs
# shipped with it green. Every one of them lived in the SAME place: the workspace
# toolchain as seen by the non-root target user through a LOGIN shell. code-server
# answers /healthz on its own bundled Node, so neither "install.sh exited 0" nor
# "/healthz is 200" can see that class of failure. The assertions below are built
# around that axis, and the negative controls prove they have teeth.
#
# BLACK-BOX CONTRACT: this file may depend ONLY on VIDE's external surface — argv,
# exit codes, files on disk, systemd unit state, HTTP behavior. It must never
# read VIDE's internals or call an internal `_`-prefixed function: a gate that
# knows how VIDE works starts passing for the wrong reason.
# tests/unit/test_harness_guards.py statically enforces this.
#
# `set -e` is deliberately absent: a failed assertion must be
# RECORDED and the suite continue, so one run reports every regression, not the
# first.
set -uo pipefail

# ---- the structural refusal ------------------------------------------------
# This must be the first logic in the file. Everything below installs a toolchain
# into /opt, writes /etc/vide, symlinks /usr/local/bin, and enables a systemd unit.
# On a developer's laptop — or on any box that is not disposable — that is a
# disaster, not a test. Refuse before the first mutation. Both proofs are
# required: the env var alone could be exported by accident on a host, and the
# container marker alone would let a stray `podman exec` into someone's real
# container run this.
if [[ ! -f /run/.containerenv && ! -f /.dockerenv ]] || [[ -z "${VIDE_IN_THROWAWAY_CONTAINER:-}" ]]; then
  printf 'FATAL: refusing to run — this test mutates system state and must only run\n' >&2
  printf '       inside the throwaway container built by tests/integration/run.sh.\n' >&2
  exit 78   # EX_CONFIG
fi

REPO=${VIDE_REPO:-/vide}
IT_USER=${VIDE_IT_USER:-ittest}
FQDN=vide.example.test          # never resolves; exercises probe_transport's warn path

# shellcheck source=../support/report.sh
. "$REPO/tests/support/report.sh"

# ---- assertion vocabulary (argv, never eval; failure output names the fact) ----

expect_eq() { # <name> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
expect_ne() { # <name> <unexpected> <actual>
  if [[ "$2" != "$3" ]]; then ok "$1"; else bad "$1 (should not have been '$2')"; fi
}
expect_contains() { # <name> <needle> <haystack>
  if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 (no '$2' in: ${3:0:200})"; fi
}
expect_rc() { # <name> <expected-rc> <cmd...>
  local name=$1 want=$2; shift 2
  local out rc
  out=$("$@" 2>&1); rc=$?
  if (( rc == want )); then ok "$name"; else bad "$name (rc=$rc, want $want: ${out:0:200})"; fi
}
# expect_ok/expect_fail: the command's own success is the assertion.
expect_ok()   { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else bad "$n (command failed: $*)"; fi; }
expect_fail() { local n=$1; shift; if "$@" >/dev/null 2>&1; then bad "$n (command unexpectedly succeeded: $*)"; else ok "$n"; fi; }

# as_user <cmd-string> — a real LOGIN shell for the target user. `su -` is load
# bearing: only a login shell sources /etc/profile.d/vide-pnpm.sh, which is where
# PNPM_HOME and the pnpm global-bin PATH entry come from. A
# non-login `su ittest -c` skips it and would report a cheerful false green — the
# exact shape of one of the three bugs this suite exists to catch.
as_user()       { su - "$IT_USER" -c "$1"; }
as_user_nologin() { su "$IT_USER" -c "$1"; }

# http_code <curl-args...> — the status of a request, or 000 on transport failure.
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null || printf '000'; }

retry_until() { # <attempts> <cmd...>
  local n=$1; shift
  local i
  for (( i = 1; i <= n; i++ )); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

# ---- 0. the box is a real systemd box --------------------------------------

# wait_for_systemd <seconds> — echo the settled state, return 0 iff usable.
#
# Do NOT trust `systemctl is-system-running --wait` alone here. `--wait` only waits
# once it has CONNECTED to PID 1; a `podman exec` that lands before systemd has
# opened /run/systemd/private fails instantly with "Failed to connect to system
# scope bus" and exits non-zero, having waited for nothing. That is a race, and it
# is won or lost by whether the image had to be built first. Poll instead: an empty
# state means "no bus yet", not "no systemd".
wait_for_systemd() {
  local deadline=$(( SECONDS + ${1:-120} )) state=''
  while (( SECONDS < deadline )); do
    state=$(systemctl is-system-running 2>/dev/null)
    case "$state" in
      # `degraded` is normal in a container: units that need real hardware fail.
      running|degraded)     printf '%s\n' "$state"; return 0 ;;
      stopping|maintenance) printf '%s\n' "$state"; return 1 ;;
      # '' (no bus yet), initializing, starting, offline -> keep waiting.
    esac
    sleep 1
  done
  printf '%s\n' "${state:-none}"
  return 1
}

echo "boot"
if sysstate=$(wait_for_systemd 120); then
  ok "systemd PID 1 finished booting ($sysstate)"
else
  bad "systemd did not boot (state: $sysstate)"; report_summary; exit 1
fi
expect_ok "preflight's systemd marker exists" test -d /run/systemd/system

# ---- scratch, created only AFTER the boot ------------------------------------
#
# Ordering is load bearing. Ubuntu's systemd enables `tmp.mount`, which mounts a
# FRESH tmpfs over /tmp during boot — anything created there beforehand is still on
# the old (now shadowed) mount and simply vanishes from view. Debian's boot does not
# shadow it. A `mktemp -d` at the top of this file therefore worked on Debian and
# silently disappeared on Ubuntu, one `podman exec` later. Verified with a canary
# file on both images. Create scratch once the mounts have settled.
#
# Secrets live only on tmpfs, 0600, and are shredded on exit. They are never passed
# on argv: /proc/<pid>/cmdline is world-readable, and `ps` would expose the very
# password whose entropy is password mode's primary auth control.
SECRET_DIR=$(umask 077; mktemp -d /dev/shm/vide-it.XXXXXX)
WORK=$(mktemp -d)
cleanup() {
  find "$SECRET_DIR" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$SECRET_DIR" "$WORK"
}
# EXIT does the cleanup; the signal traps clear themselves and re-raise so the process
# dies with the true 128+signo status (and shreds the secret on the way out) instead of
# masquerading as a clean exit.
trap cleanup EXIT
trap 'trap - INT;  cleanup; kill -INT  $$' INT
trap 'trap - TERM; cleanup; kill -TERM $$' TERM

PW_FILE="$SECRET_DIR/pw"
PW2_FILE="$SECRET_DIR/pw2"

# ---- 1. a non-root target user, as on a real VM -----------------------------

useradd -m -s /bin/bash "$IT_USER" 2>/dev/null || true
expect_ok "target user '$IT_USER' exists" id "$IT_USER"

# ---- 2. the real install ----------------------------------------------------

echo
echo "install.sh (real, root, network)"
INSTALL_ERR="$WORK/install.err"
INSTALL_OUT="$WORK/install.out"
# PIN_LATEST resolves today's tag and pins it, so every step of THIS run installs
# one consistent code-server rather than racing an upstream release mid-suite.
VIDE_CODE_SERVER_PIN_LATEST=1 \
  "$REPO/install.sh" --user "$IT_USER" --fqdn "$FQDN" \
  >"$INSTALL_OUT" 2>"$INSTALL_ERR"
install_rc=$?

# Capture the one-time password, then redact — BEFORE anything can print the log.
# install.sh generates the password late in the sequence, but a run
# that fails AFTER ensure_config still leaves it in install.err, so the redaction
# has to precede the failure dump below or a failing run would leak it to the
# console. Password lands in a 0600 tmpfs file, off any argv.
( umask 077; grep -F 'SHOWN ONCE' "$INSTALL_ERR" | sed -n 's/.*): //p' | head -1 | tr -d '\n' > "$PW_FILE" )
sed -i 's/\(SHOWN ONCE[^)]*)\): .*/\1: [REDACTED]/' "$INSTALL_ERR"

expect_eq "install.sh exits 0" 0 "$install_rc"
if (( install_rc != 0 )); then
  printf '  --- install.sh stderr (tail, password redacted) ---\n' >&2
  tail -30 "$INSTALL_ERR" >&2
  report_summary; exit 1
fi

if [[ -s "$PW_FILE" ]]; then ok "one-time password captured off-argv into tmpfs 0600"; else
  bad "could not capture the one-time password from install.sh stderr"; report_summary; exit 1; fi

PORT=$(sed -n 's/^VIDE_PORT=//p' "/etc/vide/$IT_USER.env" | head -1)
if [[ -n "$PORT" ]]; then ok "port recorded in /etc/vide/$IT_USER.env ($PORT)"; else
  bad "no port recorded"; report_summary; exit 1; fi

# stdout is a machine contract: the Caddy snippet, and nothing else, lands there.
expect_contains "install.sh stdout carries the Caddy snippet" "reverse_proxy 127.0.0.1:$PORT" "$(cat "$INSTALL_OUT")"
expect_contains "the snippet names the requested FQDN" "$FQDN" "$(cat "$INSTALL_OUT")"

# ---- 3. systemd state --------------------------------------------------------

echo
echo "systemd"
expect_eq "unit is enabled"  "enabled" "$(systemctl is-enabled "code-server@$IT_USER.service" 2>&1)"
expect_eq "unit is active"   "active"  "$(systemctl is-active  "code-server@$IT_USER.service" 2>&1)"
expect_eq "OOMScoreAdjust set on the unit" "500" "$(systemctl show -p OOMScoreAdjust --value "code-server@$IT_USER.service")"
# …and the kernel actually applied it to the live process, not just parsed the unit.
mainpid=$(systemctl show -p MainPID --value "code-server@$IT_USER.service")
expect_eq "the kernel applied oom_score_adj to the live process" "500" \
  "$(cat "/proc/$mainpid/oom_score_adj" 2>/dev/null)"
expect_eq "unit runs as the target user" "$IT_USER" "$(systemctl show -p User --value "code-server@$IT_USER.service")"
# journalctl -u must return the container's own PID 1 journal, not silence. Match on
# the launcher's syslog identifier, NOT the unit name: journald labels lines with the
# *process* (`code-server-launch[PID]`), so grepping for "code-server@ittest" would
# fail even on a perfectly healthy unit — as it did on this suite's first real run.
journal=$(journalctl -u "code-server@$IT_USER.service" --no-pager -n 20 2>&1)
if [[ -n "$journal" && "$journal" != *"No entries"* ]]; then
  ok "journalctl -u returns this unit's own journal"
else
  bad "journalctl -u returned nothing for code-server@$IT_USER"
fi
expect_contains "the IDE logged its listening address" "127.0.0.1:$PORT" "$journal"

# ---- 4. the bind is loopback-only (the core security contract) ---------------

echo
echo "network exposure"
listeners=$(ss -Htln "sport = :$PORT" 2>/dev/null)
expect_contains "listener is on 127.0.0.1:$PORT" "127.0.0.1:$PORT" "$listeners"
if [[ "$listeners" == *"0.0.0.0:$PORT"* || "$listeners" == *"[::]:$PORT"* ]]; then
  bad "code-server is bound to a wildcard address — it would be public behind any NAT"
else
  ok "no wildcard (0.0.0.0 / [::]) bind on $PORT"
fi

# ---- 5. the IDE actually answers, and actually authenticates ------------------
#
# This is the assertion the project has never once made: a real HTTP session
# against a real code-server with the real generated password.

echo
echo "code-server HTTP"
expect_ok "/healthz answers within 15s" retry_until 15 curl -fsS --max-time 2 "http://127.0.0.1:$PORT/healthz"

JAR_GOOD="$WORK/jar.good"; JAR_BAD="$WORK/jar.bad"; JAR_OLD="$WORK/jar.old"

# Unauthenticated root must redirect to the login page, never serve the IDE.
expect_eq "unauthenticated GET / redirects (302)" "302" "$(http_code -c "$JAR_BAD" "http://127.0.0.1:$PORT/")"

# The password goes to curl as FILE CONTENT (--data-urlencode name@file), never on
# argv. It is base64 and contains '+', '/' and '=', so it must be urlencoded.
# code-server checks Origin against Host for CSRF, so send a matching Origin.
curl -s -o /dev/null -c "$JAR_GOOD" --max-time 10 \
  -H "Origin: http://127.0.0.1:$PORT" \
  --data-urlencode "password@$PW_FILE" \
  "http://127.0.0.1:$PORT/login" 2>/dev/null || true
expect_eq "authenticated GET / serves the IDE (200)" "200" "$(http_code -b "$JAR_GOOD" "http://127.0.0.1:$PORT/")"

# Negative control: a wrong password must NOT yield a session. Without this, the
# assertion above would pass even if code-server were serving everyone.
printf 'not-the-password' > "$SECRET_DIR/wrong"
curl -s -o /dev/null -c "$JAR_BAD" --max-time 10 \
  -H "Origin: http://127.0.0.1:$PORT" \
  --data-urlencode "password@$SECRET_DIR/wrong" \
  "http://127.0.0.1:$PORT/login" 2>/dev/null || true
expect_ne "a wrong password does NOT authenticate" "200" "$(http_code -b "$JAR_BAD" "http://127.0.0.1:$PORT/")"

cp "$JAR_GOOD" "$JAR_OLD"   # kept for the rotate-invalidation assertion below

# ---- 6. the workspace toolchain, as the non-root user, through a LOGIN shell --
#
# The axis every historical bug lived on. code-server runs on its own bundled Node,
# so all of this is invisible to /healthz.

echo
echo "workspace toolchain (as '$IT_USER', login shell)"
node_v=$(as_user 'node --version' 2>&1)
expect_contains "user can run node" "v" "$node_v"
node_major=${node_v#v}; node_major=${node_major%%.*}
if [[ "$node_major" =~ ^[0-9]+$ ]] && (( node_major >= 26 )); then
  ok "node major >= 26 (got $node_v)"
else
  bad "node major < 26 or unparseable (got '$node_v')"
fi
expect_ok "user can run npm"  as_user 'npm --version'
expect_ok "user can run npx"  as_user 'npx --version'
expect_ok "user can run pnpm" as_user 'pnpm --version'

# PNPM_HOME must come from the profile.d drop-in, i.e. only in a LOGIN shell.
# The pair of assertions is what proves the drop-in — not some ambient env — is
# the source. A `pnpm add -g` that works only for root is the bug this catches.
expect_ne "login shell exports PNPM_HOME" "" "$(as_user 'printf %s "${PNPM_HOME:-}"')"
expect_eq "non-login shell does NOT (so the drop-in is provably the source)" "" \
  "$(as_user_nologin 'printf %s "${PNPM_HOME:-}"' 2>/dev/null)"

# The whole point of PNPM_HOME: `pnpm add -g` must work AS THE USER and land a shim
# on that user's PATH. The shared /opt/pnpm is root-owned, so a wrong global home
# is EACCES; a wrong PATH subdir makes the shim invisible. Both were real bugs.
if as_user 'pnpm add -g cowsay' >/dev/null 2>&1; then
  ok "user can 'pnpm add -g' into their own global home"
  shim=$(as_user 'command -v cowsay' 2>/dev/null)
  expect_ne "the global shim lands on the user's PATH" "" "$shim"
  expect_ok "the globally installed binary actually runs" as_user 'cowsay ok'
else
  bad "user cannot 'pnpm add -g' (EACCES on the shared pnpm home?)"
fi

# The traversal failure that toolchain_report was built to detect: root can reach
# /opt/nvm, a regular user cannot. Assert the user's own view directly.
expect_ok "user can execute /usr/local/bin/node by absolute path" as_user 'test -x /usr/local/bin/node'

# ---- 7. secret handling on disk ----------------------------------------------

echo
echo "secrets on disk"
CFG="/home/$IT_USER/.config/code-server/config.yaml"
expect_eq "config.yaml mode is 0600" "600"      "$(stat -c '%a' "$CFG" 2>/dev/null)"
expect_eq "config.yaml owned by the user" "$IT_USER" "$(stat -c '%U' "$CFG" 2>/dev/null)"
# Assert these by GREPPING THE FILE, not by feeding `$(cat "$CFG")` into
# expect_contains — whose failure branch echoes up to 200 chars of the haystack, and
# the stored `hashed-password` is itself a replayable session token
# (coder/code-server#7696). grep names the fact ("present?/absent?") without ever
# printing the config's contents. The needle for the plaintext check is read FROM a
# file (grep -f), so the password never enters argv either.
expect_ok   "only an argon2id hash is stored"        grep -q 'hashed-password: "\$argon2id' "$CFG"
expect_fail "the plaintext password is NOT on disk"  grep -qFf "$PW_FILE" "$CFG"
expect_ok   "a per-instance cookie-suffix is set"    grep -q "cookie-suffix: vide-$IT_USER-" "$CFG"
expect_ok   "bind-addr is loopback"                  grep -q "bind-addr: 127.0.0.1:$PORT" "$CFG"

# ---- 7b. branding actually landed in the served tree -------------------------
# branding.apply runs in EVERY install path and was observed by no black-box row
# at all: nothing in any tier matched favicon|font|workbench|settings.json. Its
# unit tests could only ever pin the constants against themselves, and every
# failure inside the module downgrades to a warning — so it could have been
# entirely non-functional on real boxes and nothing here would have said so.
# These rows are the only assertions in the repo that observe the RESULT.
CS_MEDIA=$(as_user 'echo "$HOME"/.local/lib/code-server-*/src/browser/media' 2>/dev/null)
# Content, not existence: upstream code-server SHIPS favicon.svg in this
# directory, so `test -s` passes on a tree branding never touched — a vacuous
# row of exactly the kind these five exist to replace. The mark's colour is
# VIDE's and appears in no upstream asset.
expect_ok "the VIDE mark REPLACED upstream's favicon" \
  as_user "grep -q '2F7A70' '$CS_MEDIA/favicon.svg'"
expect_ok "the webfont reached the served media dir" \
  as_user "ls '$CS_MEDIA'/JetBrainsMono-*.woff2 >/dev/null 2>&1"
expect_ok "the OFL licence travelled with the faces" \
  as_user "test -s '$CS_MEDIA/OFL.txt'"
CS_WB=$(as_user 'echo "$HOME"/.local/lib/code-server-*/lib/vscode/out/vs/code/browser/workbench/workbench.html' 2>/dev/null)
expect_ok "workbench.html carries the VIDE block" \
  as_user "grep -q 'VIDE branding: begin' '$CS_WB'"
# seed_user_settings writes ONCE and never converges, so a wrong seed is
# permanent per instance and fixable only by hand — worth a row of its own.
expect_ok "the user settings seed landed" \
  as_user 'test -s "$HOME/.local/share/code-server/User/settings.json"'

# ---- 8. doctor is green on a healthy box -------------------------------------

echo
echo "vide doctor"
expect_rc "doctor exits 0 when healthy" 0 vide doctor
expect_rc "doctor --quiet exits 0 when healthy" 0 vide doctor --quiet
expect_contains "ls lists the instance" "$IT_USER" "$(vide ls 2>&1)"

# ---- 9. NEGATIVE CONTROL: the traversal regression, and the self-heal ---------
#
# Without this, every green above could be vacuous. Break world-traversability the
# way a hardened host's umask would, and demand that doctor goes RED. Then demand
# that `vide toolchain` heals it without the network — the durability claim in
# README.md:75-82, never once tested.

echo
echo "negative control: traversal regression + self-heal"
chmod 700 /opt/nvm
doctor_out=$(vide doctor 2>&1); doctor_rc=$?
expect_ne "doctor goes RED when /opt/nvm is not world-traversable" "0" "$doctor_rc"
expect_contains "doctor names the user-view traversal failure" "PERM" "$doctor_out"

vide toolchain >/dev/null 2>&1
toolchain_rc=$?
expect_eq "'vide toolchain' converges (network-free re-heal)" 0 "$toolchain_rc"
expect_rc "doctor is green again after the re-heal" 0 vide doctor
expect_ok "the user can reach node again" as_user 'test -x /usr/local/bin/node'

# ---- 10. idempotence: converging must not disturb a live session --------------

echo
echo "idempotence"
mainpid_before=$(systemctl show -p MainPID --value "code-server@$IT_USER.service")
cfg_before=$(sha256sum "$CFG" | cut -d' ' -f1)
VIDE_CODE_SERVER_PIN_LATEST=1 "$REPO/install.sh" --user "$IT_USER" --fqdn "$FQDN" >/dev/null 2>&1
rerun_rc=$?
mainpid_after=$(systemctl show -p MainPID --value "code-server@$IT_USER.service")
cfg_after=$(sha256sum "$CFG" | cut -d' ' -f1)

expect_eq "a second install.sh exits 0"                 0 "$rerun_rc"
expect_eq "converge did NOT restart the live instance"  "$mainpid_before" "$mainpid_after"
expect_eq "converge did NOT rotate the password"        "$cfg_before" "$cfg_after"
expect_eq "the session from before the converge still works" "200" "$(http_code -b "$JAR_GOOD" "http://127.0.0.1:$PORT/")"

# ---- 10b. version reproducibility: only `vide upgrade` moves a version --------
#
# The production worry is drift: a box whose code-server silently changes under
# the user because some later converge re-resolved "latest". VIDE's answer is the
# presence short-circuit in ensure_code_server — an existing install is left
# alone no matter what version the caller asks for — and this proves it end to
# end, including that PIN_LATEST resolved a REAL tag rather than quietly falling
# back to "installer picks latest" (resolve_latest_version returns '' on any
# failure by design, so an unpinned run looks identical unless you check).

echo
echo "version reproducibility"
pinned=$(grep -ho 'version [0-9][0-9.]*' "$INSTALL_OUT" "$INSTALL_ERR" 2>/dev/null \
  | head -1 | cut -d' ' -f2)
expect_ne_empty() { if [[ -n "$2" ]]; then ok "$1"; else bad "$1 (empty — PIN_LATEST silently resolved nothing)"; fi; }
# local to this section: the tier's vocabulary has no absence assertion yet
expect_absent() { if [[ "$3" != *"$2"* ]]; then ok "$1"; else bad "$1 (unexpected '$2')"; fi; }
expect_ne_empty "PIN_LATEST resolved a concrete tag, not a silent fallback" "$pinned"
installed=$(as_user 'code-server --version 2>/dev/null' | head -1 | cut -d' ' -f1)
expect_eq "the installed binary really is that version" "$pinned" "$installed"

# A converge that ASKS for a different version must still not move it: the
# short-circuit, not the caller's restraint, is what keeps a box reproducible.
VIDE_CODE_SERVER_VERSION=4.0.0 "$REPO/install.sh" --user "$IT_USER" --fqdn "$FQDN" \
  >"$WORK/pin2.out" 2>"$WORK/pin2.err"
pin2_rc=$?
expect_eq "a converge carrying a conflicting version pin exits 0" 0 "$pin2_rc"
expect_eq "…and the installed version did NOT move" "$installed" \
  "$(as_user 'code-server --version 2>/dev/null' | head -1 | cut -d' ' -f1)"
# …and it did not move because the converge deliberately declined to reinstall,
# which is a different claim from "the download happened to be a no-op".
expect_contains "…because it declined to reinstall, and said so" \
  "leaving version as-is" "$(cat "$WORK/pin2.out" "$WORK/pin2.err")"
expect_absent "…never invoking the installer for an existing install" \
  "installing code-server (standalone, version 4.0.0" "$(cat "$WORK/pin2.out" "$WORK/pin2.err")"

# ---- 10c. port exhaustion is a HOST-state refusal, not a crash ----------------
#
# ports.py's allocator is thoroughly unit-tested (lowest-free, skip-recorded,
# exhaustion -> StateError, lock timeout). What no tier checked is whether that
# exception survives the trip out to the shell as the DOCUMENTED code: a
# monitoring script or an orchestrator distinguishes "this host is full" (75,
# retry elsewhere) from "you typed it wrong" (64) or a generic crash (1) by
# exit code alone. Squeeze the range down to the single port the live instance
# already holds, then ask for a second one.

echo
echo "port exhaustion"
IT_USER2="${IT_USER}2"
useradd -m -s /bin/bash "$IT_USER2" 2>/dev/null || true
exhausted_before=$(ls -1 /etc/vide/*.env 2>/dev/null | wc -l)
VIDE_PORT_BASE="$PORT" VIDE_PORT_MAX="$PORT" \
  "$REPO/install.sh" --user "$IT_USER2" --fqdn "$FQDN" \
  >"$WORK/full.out" 2>"$WORK/full.err"
full_rc=$?
expect_eq "a full port range exits EX_STATE(75), not 1 and not 64" 75 "$full_rc"
expect_contains "…and says which range is exhausted" "$PORT" \
  "$(cat "$WORK/full.out" "$WORK/full.err")"
expect_eq "…leaving no half-made instance record behind" \
  "$exhausted_before" "$(ls -1 /etc/vide/*.env 2>/dev/null | wc -l)"
expect_absent "…and no unit for the refused user" "code-server@$IT_USER2" \
  "$(systemctl list-unit-files --no-legend 2>/dev/null)"
# The live instance must be untouched by someone else's failed allocation.
expect_eq "…and the running instance is undisturbed" "active" \
  "$(systemctl is-active "code-server@$IT_USER.service" 2>&1)"

# ---- 11. destructive verbs: argv is the only bypass, and it fails closed ------
#
# tests/unit/test_harness_guards.py greps for this statically. Here it is proven
# end to end, with no
# TTY — the state a cron job or a piped script is actually in.

echo
echo "destructive-verb guards (no TTY)"
expect_rc "destroy without --yes fails closed (EX_USAGE)" 64 vide destroy "$IT_USER"
expect_eq "…and the instance survived" "active" "$(systemctl is-active "code-server@$IT_USER.service" 2>&1)"

# The whole reason confirm_destructive refuses to consult the environment: .env is
# `set -a`-sourced by BOTH entry points, so an env-level "assume yes" set to automate
# the idempotent installer would silently waive destroy's only guard.
expect_rc "VIDE_ASSUME_YES=1 does NOT waive the guard" 64 env VIDE_ASSUME_YES=1 vide destroy "$IT_USER"
expect_eq "…and the instance still survived" "active" "$(systemctl is-active "code-server@$IT_USER.service" 2>&1)"

# ---- 12. rotate is a real kill switch ----------------------------------------

echo
echo "rotate invalidates live sessions"
ROTATE_ERR="$WORK/rotate.err"
vide --yes rotate "$IT_USER" >/dev/null 2>"$ROTATE_ERR"
rotate_rc=$?
expect_eq "rotate --yes exits 0" 0 "$rotate_rc"
( umask 077; grep -F 'SHOWN ONCE' "$ROTATE_ERR" | sed -n 's/.*): //p' | head -1 | tr -d '\n' > "$PW2_FILE" )
sed -i 's/\(SHOWN ONCE[^)]*)\): .*/\1: [REDACTED]/' "$ROTATE_ERR"
expect_ok "rotate emitted a new one-time password" test -s "$PW2_FILE"
expect_fail "the new password differs from the old" cmp -s "$PW_FILE" "$PW2_FILE"

expect_ok "the unit came back up" retry_until 20 curl -fsS --max-time 2 "http://127.0.0.1:$PORT/healthz"
# The old cookie is the thing that must die. code-server's stored hash doubles as a
# replayable session token (coder/code-server#7696), so rotate is the ONLY revocation.
expect_ne "the pre-rotate session is now rejected" "200" "$(http_code -b "$JAR_OLD" "http://127.0.0.1:$PORT/")"

JAR_NEW="$WORK/jar.new"
curl -s -o /dev/null -c "$JAR_NEW" --max-time 10 \
  -H "Origin: http://127.0.0.1:$PORT" \
  --data-urlencode "password@$PW2_FILE" \
  "http://127.0.0.1:$PORT/login" 2>/dev/null || true
expect_eq "the new password authenticates" "200" "$(http_code -b "$JAR_NEW" "http://127.0.0.1:$PORT/")"

# ---- 13. destroy removes the instance, and only the instance -----------------

echo
echo "destroy"
expect_rc "destroy --yes exits 0" 0 vide --yes destroy "$IT_USER"
expect_ne "the unit is no longer active" "active" "$(systemctl is-active "code-server@$IT_USER.service" 2>&1)"
expect_fail "the port record is gone"    test -f "/etc/vide/$IT_USER.env"
expect_fail "code-server is uninstalled" test -x "/home/$IT_USER/.local/bin/code-server"
# destroy must NEVER touch the user's data. This is the promise in `vide help`.
expect_ok  "the user's \$HOME survived"  test -d "/home/$IT_USER"

report_summary; exit $?
