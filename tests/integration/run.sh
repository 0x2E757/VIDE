#!/usr/bin/env bash
# tests/integration/run.sh — the ONLY host-touching file of the integration tier.
#
#   tests/integration/run.sh                 # Debian, ~5-8 min
#   tests/integration/run.sh --distro all    # Debian + Ubuntu
#   tests/integration/run.sh --rebuild       # force image rebuild
#   tests/integration/run.sh --keep          # leave the container up for triage
#
# Its entire job is: build a throwaway systemd image, run in-container.sh inside it,
# relay the verdict, and guarantee teardown. It performs NO VIDE logic itself.
#
# SECURITY POSTURE — see README.md in this directory for the full threat model.
#   * Prefers ROOTLESS podman: a container escape lands on an unprivileged host
#     uid, not root. Verified: rootless + --systemd=always boots a real systemd
#     PID 1 on cgroup v2, so no privilege escalation is needed.
#   * NEVER --privileged, NEVER --network=host, NEVER -p/--publish. The container
#     runs a real code-server with a real password; publishing it would put an IDE
#     with a shell on whatever interface podman binds. The login assertion reaches
#     it from INSIDE the container's own netns instead.
#   * The repo is mounted read-only, so a test can never mutate the working tree.
#   * Everything VIDE writes (/opt/nvm, /opt/pnpm, /usr/local/bin, /etc/vide, the
#     systemd unit) lands on the container's ephemeral overlay and dies with it.
set -uo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
LABEL=vide-itest
DISTROS=(debian)
REBUILD=0
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --distro) shift
      case "${1:-}" in
        debian|ubuntu) DISTROS=("$1") ;;
        all)           DISTROS=(debian ubuntu) ;;
        *) printf 'unknown --distro: %s (debian|ubuntu|all)\n' "${1:-}" >&2; exit 64 ;;
      esac ;;
    --rebuild) REBUILD=1 ;;
    --keep)    KEEP=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 64 ;;
  esac
  shift
done

command -v podman >/dev/null 2>&1 || {
  printf 'podman is required: apt-get install -y podman uidmap passt\n' >&2
  exit 69   # EX_UNAVAILABLE
}
# Rootless podman talks to its own runtime dir; a non-login shell may not have it.
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
export XDG_RUNTIME_DIR

# REFUSE to run as root by default. The whole containment argument of this harness
# is "rootless podman, so an escape from the untrusted `curl|sh` installers it runs
# (nvm, get.pnpm.io, code-server.dev) lands on an unprivileged uid, not host root."
# As root, podman is ROOTFUL and that guarantee is void — on a box operated as root,
# which a throwaway test VM usually is, a mere warning makes rootful the default, which
# is exactly the posture the harness claims to avoid. Fail closed; require a typed,
# per-invocation opt-in for anyone who genuinely has no unprivileged user. The opt-in
# is an env var, not a flag, so it cannot be set once in a shared config and forgotten.
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  if [[ "${VIDE_ITEST_ALLOW_ROOTFUL:-}" != 1 ]]; then
    printf 'refusing to run as root: podman would be ROOTFUL, so a container escape from the\n' >&2
    printf 'untrusted upstream installers would land on HOST ROOT, voiding this suite'"'"'s whole\n' >&2
    printf 'containment premise. Run as an unprivileged user with subuid/subgid set (see\n' >&2
    printf 'tests/integration/README.md). To override deliberately: VIDE_ITEST_ALLOW_ROOTFUL=1\n' >&2
    exit 77   # EX_NOPERM
  fi
  printf 'WARN  VIDE_ITEST_ALLOW_ROOTFUL=1: running ROOTFUL — a container escape lands on\n' >&2
  printf 'WARN  host root. Acceptable only on disposable infrastructure, never a prod box.\n' >&2
fi

cgv=$(podman info --format '{{.Host.CgroupsVersion}}' 2>/dev/null)
[[ "$cgv" == v2 ]] || {
  printf 'this harness needs cgroup v2 (got: %s) — systemd in the container will not boot cleanly\n' "${cgv:-unknown}" >&2
  exit 69
}

# Teardown is unconditional: a killed run must not leave a systemd container (or a
# live code-server) behind on the host. The label sweep catches containers orphaned
# by an earlier SIGKILL, which no EXIT trap could have cleaned up.
containers=()
cleanup() {
  (( KEEP )) && { printf 'kept: %s (remove with: podman rm -f %s)\n' "${containers[*]:-none}" "${containers[*]:-}" >&2; return; }
  local c
  for c in "${containers[@]:-}"; do [[ -n "$c" ]] && podman rm -f "$c" >/dev/null 2>&1; done
  podman ps -aq --filter "label=$LABEL=1" 2>/dev/null | while read -r orphan; do
    [[ -n "$orphan" ]] && podman rm -f "$orphan" >/dev/null 2>&1
  done
}
trap cleanup EXIT
trap 'trap - INT;  cleanup; kill -INT  $$' INT
trap 'trap - TERM; cleanup; kill -TERM $$' TERM

# stale_image <image> <containerfile> — true if the image is missing, or older than
# its Containerfile. Without this, editing a Containerfile was silently ignored until
# someone remembered `--rebuild`, so a test could run against a stale base and mislead.
#
# Convergence note: a genuine content EDIT busts podman's layer cache, so the rebuilt
# image gets a fresh `.Created` and the next run skips — converges. A content-free
# `touch` does NOT: the all-cache-hit rebuild reuses layers and freezes `.Created` at
# the original build, so every run rebuilds. That over-rebuild is a cache hit (~1-3s
# of a ~50s test) and always in the SAFE direction, so it is accepted rather than
# chased with content-hash tag keying (which would leak accumulating image tags).
stale_image() {
  local img=$1 cf=$2 b c
  podman image exists "$img" 2>/dev/null || return 0
  # `.Created.Unix` gives epoch seconds straight from podman's time.Time. Do NOT parse
  # `{{.Created}}` through `date -d`: its trailing "... +0000 UTC" is not a format GNU
  # date accepts, so that comparison silently failed and rebuilt on every run.
  b=$(podman image inspect -f '{{.Created.Unix}}' "$img" 2>/dev/null) || return 0
  c=$(stat -c %Y "$cf" 2>/dev/null) || return 0
  # Any non-numeric result (unreadable timestamp) fails the arithmetic test's guard and
  # rebuilds — the safe direction. `-gt` on validated integers only.
  [[ "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ ]] || return 0
  (( c > b ))
}

overall=0
for distro in "${DISTROS[@]}"; do
  image="vide-itest:$distro"
  containerfile="$REPO_DIR/tests/integration/Containerfile.$distro"
  printf '\n=== %s ===\n' "$distro" >&2

  if (( REBUILD )) || stale_image "$image" "$containerfile"; then
    printf 'building %s …\n' "$image" >&2
    podman build -q -t "$image" -f "$REPO_DIR/tests/integration/Containerfile.$distro" \
      "$REPO_DIR/tests/integration" >/dev/null || { printf 'image build failed\n' >&2; overall=1; continue; }
  fi

  # --systemd=always: podman mounts the tmpfs systemd needs and delegates a writable
  # cgroup subtree, which is what makes `systemctl enable --now` and `journalctl -u`
  # truthful inside. No --privileged is required for this on cgroup v2.
  cid=$(podman run -d \
        --label "$LABEL=1" \
        --systemd=always \
        --cgroupns=private \
        --hostname "vide-itest-$distro" \
        -v "$REPO_DIR:/vide:ro" \
        -e VIDE_IN_THROWAWAY_CONTAINER=1 \
        "$image" 2>&1)
  # shellcheck disable=SC2181
  if (( $? != 0 )); then printf 'container start failed: %s\n' "$cid" >&2; overall=1; continue; fi
  containers+=("$cid")

  podman exec "$cid" /vide/tests/integration/in-container.sh
  rc=$?
  if (( rc == 0 )); then
    printf '=== %s: PASS ===\n' "$distro" >&2
  else
    printf '=== %s: FAIL (rc=%d) ===\n' "$distro" "$rc" >&2
    overall=1
  fi
done

exit "$overall"
