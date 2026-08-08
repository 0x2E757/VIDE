#!/usr/bin/env bash
# VIDE bootstrap shim. The implementation is Python (src/vide/); this file
# exists because bootstrapping a language needs a language that is already
# there — and because this exact path is deployed contract: the arbiter drives
# "$REPO/install.sh", and operator muscle memory is `sudo ./install.sh`.
#
# Fresh debian:13 / ubuntu:24.04 images ship NO python3, so the shim installs
# it (the full `python3` metapackage, NOT python3-minimal: Debian's minimal
# stdlib subset is documented as boot-only and lacks modules VIDE needs).
# Rollback is `git revert` + a re-run of this script — see docs/rollback.md.
set -euo pipefail

here="$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)"

# ---- the checkout is root-equivalent -----------------------------------------
# Everything below this line executes out of "$here" as root, and .env is
# root-equivalent in full: two installer URLs are fetched-and-executed as root by
# design, and every key in the file is injected into the environment every root
# child inherits. So whoever can write this tree owns the operator's next
# `sudo ./install.sh`.
#
# The authoritative check is Python (preflight.checkout_gate). It cannot be the
# ONLY one: python3 runs FROM "$here/src", so a gate living there would be
# reading its own attacker's code. This coarse half must therefore happen before
# the exec, and — deliberately — before the .env read below: a gate that took
# its policy out of the file it is judging would not be a gate, which is also
# why `dry` here comes from argv and the process environment only.
#
# The block between the two markers below is DUPLICATED VERBATIM into `vide`, and
# a test compares the two byte for byte. Duplicated and not sourced: a helper file
# would live in the tree being judged, which is the same objection this comment
# opens with. Edit one, run the tier, and it will tell you about the other.
# >>> VIDE-CHECKOUT-GATE (byte-identical in install.sh and vide)
gate_dry=0
[[ "${VIDE_DRY_RUN:-}" == 1 ]] && gate_dry=1
for a in "$@"; do [[ "$a" == --dry-run ]] && gate_dry=1; done

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  trusted=(0)
  [[ -n "${SUDO_UID:-}" ]] && trusted+=("$SUDO_UID")

  # Echoes a reason when a third party could write <path>; silent when safe.
  # NOT a bare group-writable refusal: Debian and Ubuntu default to umask 002
  # AND user-private groups, so a plain `git clone` is 0775 alice:alice and a
  # naive check would refuse this file's own documented invocation. A private
  # group (gid == owner, no supplementary members) is the one safe case; every
  # other group-writable tree is refused here and resolved exactly by the
  # Python gate.
  _untrusted() {
    local p=$1 st u g m t ok=0 members
    st=$(stat -c '%u %g %a' "$p" 2>/dev/null) || return 0
    read -r u g m <<<"$st"
    for t in "${trusted[@]}"; do [[ "$u" == "$t" ]] && ok=1; done
    if (( ! ok )); then
      printf 'is owned by uid %s, which is not root and not the sudo caller' "$u"
      return 0
    fi
    if (( (8#$m) & 0002 )); then
      printf 'is world-writable (mode %s)' "$m"
      return 0
    fi
    if (( (8#$m) & 0020 )); then
      members=$(getent group "$g" 2>/dev/null | cut -d: -f4)
      if [[ "$g" != "$u" || -n "$members" ]]; then
        printf 'is group-writable (mode %s) by a group that is not private to its owner' "$m"
        return 0
      fi
    fi
    return 0
  }

  gate_paths=()
  # Ancestors: a 0755 tree inside a 0777 directory can be renamed out from
  # under root, so /tmp/vide is refused however tidy the tree itself is.
  p="$here"
  while [[ "$p" != "/" ]]; do gate_paths+=("$p"); p=$(dirname -- "$p"); done
  gate_paths+=("/")
  for n in install.sh vide .env; do
    [[ -e "$here/$n" ]] && gate_paths+=("$here/$n")
  done
  # WALK src and units; never a list of them. The list had three holes at once —
  # `src/vide` missing from the Python half, `src/vide/tui` missing from BOTH
  # (it is imported as root on every wizard install), and `__pycache__` from
  # either — because an enumeration has to be extended whenever a subpackage is
  # added and nobody adding one is thinking about this file. The predicate is
  # unchanged; only the path set grows, so a stock 0775 alice:alice clone still
  # passes exactly as before.
  while IFS= read -r p; do gate_paths+=("$p"); done < <(
    find -P "$here/src" "$here/units" 2>/dev/null)

  for p in "${gate_paths[@]}"; do
    why=$(_untrusted "$p")
    if [[ -n "$why" ]]; then
      if (( gate_dry )); then
        printf 'WARN  preflight (dry-run): untrusted checkout: %s %s\n' "$p" "$why" >&2
      else
        printf 'ERROR refusing to run from an untrusted checkout: %s %s.\n' "$p" "$why" >&2
        printf 'ERROR VIDE executes this tree as root. Move the clone somewhere only root can write (e.g. /opt/vide-src).\n' >&2
        exit 78
      fi
    fi
  done
  # A symlinked .env says nothing about who can repoint it.
  if [[ -L "$here/.env" ]]; then
    if (( gate_dry )); then
      printf 'WARN  preflight (dry-run): untrusted checkout: %s/.env is a symlink\n' "$here" >&2
    else
      printf 'ERROR refusing to run from an untrusted checkout: %s/.env is a symlink.\n' "$here" >&2
      exit 78
    fi
  fi
fi
# <<< VIDE-CHECKOUT-GATE

# Exact-match scan only: the shim must never disagree with the Python parser
# about any other flag, so it consumes nothing and prefix-matches nothing.
#
# The dry decision must ALSO see a `.env` row: Python resolves VIDE_DRY_RUN as
# argv > env > .env (empty env falls through), and a shim that only reads the
# process env would apt-get install python3 — a real mutation — while the
# Python half of the very same run previews. Mirrors config.py's precedence
# and parse_env_text's tolerances (export prefix, spaces, quotes, last row
# wins) for this ONE key; only the exact value 1 enables.
dry=0
dry_src="${VIDE_DRY_RUN:-}"
if [[ -z "$dry_src" && -f "$here/.env" ]]; then
  # `export ` with SPACES only: parse_env_text strips the literal prefix
  # "export " (never a tab), so an `export<TAB>` row is junk-keyed and
  # IGNORED by Python — matching it here would re-open the very divergence
  # this block closes (last-row-wins on a row Python does not see).
  row="$(grep -E '^[[:space:]]*(export +)?VIDE_DRY_RUN[[:space:]]*=' "$here/.env" 2>/dev/null | tail -n 1)" || row=""
  val="${row#*=}"
  val="${val#"${val%%[![:space:]]*}"}"   # ltrim
  val="${val%"${val##*[![:space:]]}"}"   # rtrim
  case "$val" in 1|'"1"'|"'1'") dry_src=1 ;; esac
fi
[[ "$dry_src" == 1 ]] && dry=1
for a in "$@"; do [[ "$a" == --dry-run ]] && dry=1; done

if ! command -v python3 >/dev/null 2>&1; then
  if (( dry )); then
    # A preview must not mutate: narrate the bootstrap and stop cleanly.
    printf 'WARN  DRY-RUN MODE ACTIVE — no changes will be made (VIDE_DRY_RUN=1)\n' >&2
    printf 'INFO  [dry-run] python3 not found; a real run would: apt-get install -y python3\n' >&2
    printf 'INFO  [dry-run] cannot preview the Python steps without python3 — stopping here\n' >&2
    exit 0
  fi
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { printf 'ERROR must run as root — re-run with: sudo %s\n' "$0" >&2; exit 77; }
  # The authoritative distro/arch gate lives in Python preflight; this is only
  # "can apt even exist here" — on a non-apt box, refuse before touching anything.
  command -v apt-get >/dev/null 2>&1 || { printf 'ERROR no apt-get: VIDE targets Debian/Ubuntu\n' >&2; exit 78; }
  printf 'INFO  installing python3 (VIDE bootstrap)\n' >&2
  export DEBIAN_FRONTEND=noninteractive
  # apt chatter goes to STDERR: stdout is the machine channel (it carries the
  # Caddy snippet; `sudo ./install.sh > snippet.conf` must stay clean). The
  # parity diff caught this leaking before the arbiter ever could.
  apt-get update -qq >&2
  apt-get install -y python3 >&2
fi

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
  || { printf 'ERROR VIDE needs Python >= 3.10 (found: %s)\n' "$(python3 -V 2>&1)" >&2; exit 78; }

# -B for the same reason as the `vide` shim: never write .pyc files. A poisoned
# __pycache__ left behind while the tree was briefly writable is loaded in
# preference to the reviewed .py (PEP 552 validates against the source's mtime
# and size, carried in the .pyc's own header — both forgeable by whoever could
# write the tree). This stops the artifact being CREATED; only removing it stops
# one already there being read, which is what the gate's remedy says.
exec python3 -B "$here/src/vide/__main__.py" install "$@"
