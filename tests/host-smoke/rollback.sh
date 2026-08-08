#!/usr/bin/env bash
# The rollback gate: does docs/rollback.md tell the truth?
#
# Why it exists: that document makes three checkable promises about the worst
# moment in an operator's week — a release has gone wrong and they are undoing
# it. Every other claim VIDE makes has a tier; the one procedure reached for
# under failure had none, which is the wrong way round.
#
# The three promises, each a section below:
#   §2  "a reverted tree re-converges cleanly: nothing is regenerated, no
#        password rotates, no session drops"
#   §3  "git revert undoes code, not system state" — provisioning survives it,
#        and you undo that with the pre-revert tree's own verbs
#   §4  the SSO rollback shape: destroy + password reinstall, $HOME survives,
#        a new password is shown once
#
# NOT covered here, deliberately: promise §2's "no session drops" half in SSO
# MODE. Proving it live needs a browser, real Google credentials and a re-paste
# of the operator Caddyfile, to exercise a code path already pinned twice — the
# sso-mode gate ("a live session survives a converge (200)") and live-fleet §3
# (proxy MainPID + proxy.env sha256 unchanged across an instance upgrade).
# revert+converge IS a converge. What this tier adds is the PASSWORD-mode half,
# where "no password rotates" is the equivalent claim and needs no human.
#
# WHERE IT RUNS: any disposable box with git and the repo. It does NOT need the
# host-smoke fleet, and it does not need a pristine box — it installs one
# dedicated instance of its own. It never touches the checkout it lives in: the
# revert happens in a throwaway clone, because a tier that dirties the operator's
# working tree to test rollback would be its own worst finding.
#
# ROLLBACK CONTRACT: like the rest of host-smoke this MUTATES THE HOST (creates
# a user, installs and destroys an instance) and does not clean up. Rollback is
# the baseline snapshot restore.
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---- refusals ------------------------------------------------------------------
if [[ -f /run/.containerenv || -f /.dockerenv ]]; then
  printf 'FATAL: rollback asserts REAL-host behavior (systemd units, real users).\n' >&2
  exit 78   # EX_CONFIG
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'FATAL: rollback needs root (creates a user, installs a unit): sudo %s\n' "$0" >&2
  exit 77
fi
if [[ "${VIDE_DISPOSABLE_BOX:-}" != 1 ]]; then
  printf 'FATAL: refusing — this run mutates the host (creates a user, installs\n' >&2
  printf '       and destroys an instance; no cleanup). If this box is disposable\n' >&2
  printf '       and a baseline snapshot exists, re-run with VIDE_DISPOSABLE_BOX=1.\n' >&2
  exit 78
fi

U=rbtest
HOME_DIR=/home/$U
PRECIOUS=$HOME_DIR/PRECIOUS.txt
PRECIOUS_TEXT="the user's work, which a rollback must never eat"

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
expect_empty() { # <name> <actual> — the ABSENCE assertions this tier needs
  if [[ -z "$2" ]]; then ok "$1"; else bad "$1 (expected nothing, got '$2')"; fi
}
retry_until() { # <seconds> <cmd...> — bounded; a timeout is a FINDING
  local deadline=$(( SECONDS + $1 )); shift
  while (( SECONDS < deadline )); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

WORK=$(mktemp -d)

# The revert clone is DURABLE on purpose, and this is the one non-obvious thing
# in this tier. install_flow.link_cli points /usr/local/bin/vide at
# <repo>/vide — deliberately, so a rollback flip between two trees needs no
# cleanup. The corollary is that the box's `vide` command is exactly as durable
# as the tree it was installed from. An earlier draft of this tier installed
# from a mktemp clone and deleted it on exit, which left the box with a dangling
# CLI and made the tier unable to re-run itself. So: a stable path, cleared at
# the start of each run and LEFT BEHIND at the end.
#
# It must ALSO be root-owned all the way up, and that half was missing until
# 2026-07-31: this was /var/tmp/vide-rollback-clone, and /var/tmp is 1777. The
# checkout gate refuses a tree under a world-writable ancestor with exit 78 —
# correctly, since anyone could swap what root is about to execute — so this tier
# could not pass on any stock box, while the gate it was tripping is one of the
# things this tier exists to exercise. /opt is 0755 root:root and durable, and it is
# where README.md already tells operators to keep the real clone.
CLONE=/opt/vide-rollback-clone
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'trap - INT;  cleanup; kill -INT  $$' INT
trap 'trap - TERM; cleanup; kill -TERM $$' TERM

# git refuses to commit without an identity, and a disposable box rarely has one.
GIT=(git -c "user.name=VIDE rollback gate" -c "user.email=rollback@vide.invalid" \
         -c "commit.gpgsign=false")

hashed() { grep -o 'hashed-password:.*' "$HOME_DIR/.config/code-server/config.yaml" 2>/dev/null; }
mainpid() { systemctl show -p MainPID --value "code-server@$U" 2>/dev/null; }

echo "== 0. preconditions =="

expect_ok "the repo under test is a git checkout" test -d "$REPO/.git"
# Reverting a merge needs -m and is a different procedure, so assert we are
# testing the case the doc describes. Do NOT require a parent: a published tree
# is legitimately a single ROOT commit (one word from rev-list --parents), which
# `git revert` handles fine. Only a merge (three or more words) is out of scope.
# Pinning "exactly one parent" here made this tier fail the moment the history
# was squashed for release — an assumption about the repo's shape masquerading
# as an assumption about the procedure.
parents=$(git -C "$REPO" rev-list --parents -n 1 HEAD | wc -w)
expect_ok "HEAD is not a merge, as the doc's procedure assumes" \
  test "$parents" -le 2

rm -rf "$CLONE"
git clone -q "$REPO" "$CLONE" 2>/dev/null
expect_ok "a working clone is available (the operator's tree stays clean)" test -d "$CLONE/.git"
head_before=$(git -C "$CLONE" rev-parse HEAD)

id "$U" >/dev/null 2>&1 || useradd -m "$U"
expect_ok "the gate's own user exists" id "$U"
# Re-runnability: §1 asserts a FIRST install (a password shown once), which a
# converge legitimately does not do. A previous run leaves the instance behind —
# by the rollback contract above, this tier cleans up nothing — so clear only
# THIS gate's own instance before starting. Drive it with the CLONE's own shim,
# never the installed `vide`: that symlink may point into a tree a previous run
# left behind, and a housekeeping step must not depend on the very thing whose
# durability §1 is about to assert. $HOME is left alone — §4 asserts it survives,
# and wiping it here would make that assertion vacuous.
if [[ -f "/etc/vide/$U.env" ]]; then
  "$CLONE/vide" --yes destroy "$U" >/dev/null 2>&1
fi
expect_ok "the gate starts from no instance of its own" bash -c "[[ ! -f /etc/vide/$U.env ]]"
printf '%s\n' "$PRECIOUS_TEXT" > "$PRECIOUS"
chown "$U:$U" "$PRECIOUS"

# ---- 1. install the instance the rollback will be performed on -----------------
echo
echo "== 1. a password-mode instance to roll back =="

"$CLONE/install.sh" --no-gui --user "$U" </dev/null >"$WORK/install1.out" 2>"$WORK/install1.err"
install1_rc=$?
expect_eq "the first install exits 0" 0 "$install1_rc"
expect_contains "…and shows the password ONCE (the password-mode contract)" \
  "SHOWN ONCE" "$(cat "$WORK/install1.err")"
retry_until 30 systemctl is-active --quiet "code-server@$U"
expect_ok "the instance is active" systemctl is-active --quiet "code-server@$U"

# The design that makes a rollback flip cleanup-free, pinned so it cannot drift
# silently: the box's CLI is a symlink to the tree that installed it. Anyone
# rolling back by cloning elsewhere — or deleting the old checkout — inherits a
# dangling `vide` and must re-run install.sh from the new path.
expect_eq "the box's vide CLI points at the tree it was installed from" \
  "$CLONE/vide" "$(readlink /usr/local/bin/vide 2>/dev/null)"

hash_before=$(hashed)
pid_before=$(mainpid)
env_before=$(sha256sum "/etc/vide/$U.env" | cut -d' ' -f1)
expect_ok "a hashed password was recorded" test -n "$hash_before"
expect_ok "the instance has a live MainPID" bash -c "[[ -n '$pid_before' && '$pid_before' != 0 ]]"

# Doctor's verdict BEFORE the revert, so §2 can assert the rollback made nothing
# WORSE instead of demanding a box with nothing else wrong with it. The header
# above promises this tier needs neither the fleet nor a pristine box; a row
# requiring a globally green `vide doctor` contradicts that promise and, on
# 2026-08-01, was the tier's single red — on a box whose doctor had already
# exited 69 before the tier started, on SSO-plane lines this tier never touches.
# A rollback gate may not require the rest of the box to be healthy; it may only
# require that IT did not damage anything. Sampled here rather than at §0 because
# §1's install is part of the state under test.
vide doctor >/dev/null 2>&1; doctor_before=$?
printf '  info doctor exits %s before the revert (the baseline §2 compares to)\n' \
  "$doctor_before"

# ---- 2. THE promise: revert the code, re-converge, disturb nothing -------------
echo
echo "== 2. 'a reverted tree re-converges cleanly' =="

# Revert HEAD, not a hardcoded sha: the realistic case is undoing what was just
# shipped, and a pinned sha would rot the tier within a week.
"${GIT[@]}" -C "$CLONE" revert --no-edit HEAD >"$WORK/revert.out" 2>&1
revert_rc=$?
expect_eq "git revert HEAD succeeds on a clean tree" 0 "$revert_rc"
expect_ne "…and the tree really moved" "$head_before" "$(git -C "$CLONE" rev-parse HEAD)"

"$CLONE/install.sh" --no-gui --user "$U" </dev/null >"$WORK/install2.out" 2>"$WORK/install2.err"
converge_rc=$?
expect_eq "the re-converge onto the reverted tree exits 0" 0 "$converge_rc"

# The three things the doc promises are NOT regenerated. Each is the operator's
# actual fear in a rollback: losing the password, dropping every live session,
# and silently re-writing the instance record.
expect_eq "no password rotates (the hash is byte-identical)" "$hash_before" "$(hashed)"
expect_eq "no session drops (the instance was never restarted)" "$pid_before" "$(mainpid)"
expect_eq "the instance record is untouched" "$env_before" \
  "$(sha256sum "/etc/vide/$U.env" | cut -d' ' -f1)"
expect_eq "the converge emits no shown-once password of any kind" 0 \
  "$(grep -cF 'SHOWN ONCE' "$WORK/install2.err")"
vide doctor >/dev/null 2>&1; doctor_after=$?
expect_eq "doctor did not get worse: the revert damaged nothing" \
  "$doctor_before" "$doctor_after"

# ---- 3. the doc's own warning, which is the easy half to get wrong -------------
echo
echo "== 3. 'git revert undoes code, not system state' =="

# The warning exists because an operator who reverts and walks away believes the
# box is back. It is not: everything the reverted tree PROVISIONED is still here.
# If this section ever goes red, the doc is over-promising and must be corrected
# — the box being clean is NOT the good outcome here.
expect_ok "the instance record provisioned by the pre-revert tree SURVIVES the revert" \
  test -f "/etc/vide/$U.env"
expect_ok "…and so does the running unit" systemctl is-active --quiet "code-server@$U"
expect_ok "…and so does the user" id "$U"

# ---- 4. the verbs the doc names as the way to actually undo it -----------------
echo
echo "== 4. destroy + reinstall: the SSO-rollback shape, walked in password mode =="

vide --yes destroy "$U" >"$WORK/destroy.out" 2>&1
destroy_rc=$?
expect_eq "vide destroy exits 0" 0 "$destroy_rc"
expect_ok "the record is gone" bash -c "[[ ! -f /etc/vide/$U.env ]]"
expect_ok "the unit is stopped" bash -c "! systemctl is-active --quiet code-server@$U"
# The one thing destroy must never touch, stated twice in the doc.
expect_ok "\$HOME survives a destroy" test -f "$PRECIOUS"
expect_eq "…byte-for-byte" "$PRECIOUS_TEXT" "$(cat "$PRECIOUS")"

"$CLONE/install.sh" --no-gui --user "$U" </dev/null >"$WORK/install3.out" 2>"$WORK/install3.err"
reinstall_rc=$?
expect_eq "the password-mode reinstall exits 0" 0 "$reinstall_rc"
expect_contains "a NEW password is generated and shown once" \
  "SHOWN ONCE" "$(cat "$WORK/install3.err")"
retry_until 30 systemctl is-active --quiet "code-server@$U"
expect_ne "…and it really is new (the hash changed)" "$hash_before" "$(hashed)"
expect_ok "\$HOME still survives the reinstall" test -f "$PRECIOUS"

echo
echo "(the operator's checkout at $REPO was never modified: the revert ran in"
echo " $CLONE — left in place, because the box's vide symlink now"
echo " points into it)"
expect_empty "the tier left the operator's working tree clean" \
  "$(git -C "$REPO" status --porcelain)"

report_summary
