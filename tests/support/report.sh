# shellcheck shell=bash
# tests/support/report.sh — the ONE reporting vocabulary, shared by every shell
# gate in the repo, so there is a single test dialect and a single PASS=/FAIL=
# line that a human (or a parser) reads the same way everywhere.
#
# Deliberately holds NO assertion helper. Each gate asserts in its own idiom —
# black-box over argv and exit codes for the container tiers, HTTP status for the
# SSO gate, systemd state for host-smoke — and a shared `check` would only work by
# assuming one of them. Shared VOCABULARY, not shared semantics.
# Only the counters and the verdict line are shared.
[[ -n "${_VIDE_REPORT_SH:-}" ]] && return 0
_VIDE_REPORT_SH=1

PASS=0 FAIL=0

ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }

# report_summary — print the tally; RETURN 0 iff green. Callers end with
# `report_summary` (or `report_summary; exit $?`), never `exit "$(report_summary)"`,
# which would swallow the tally into a command substitution.
report_summary() {
  printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
  (( FAIL == 0 ))
}
