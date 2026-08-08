#!/usr/bin/env bash
# The dedicated-'vide' journey gate: bare-root install on a minimal image
# where the sudo PACKAGE is absent while the sudo GROUP exists — the exact
# deceptive fixture that let the live smoke §1 walk die at visudo while every
# hermetic tier stayed green (the arbiter and parity both pre-create a
# --user target and never take the vide branch, so the whole journey went
# unexercised while looking covered).
#
# Deliberately NOT under tests/integration/ — that directory is byte-frozen
# (the parity tier set the precedent and the reasoning: the acceptance gate's
# authority is its immutability). This is the follow-up the arbiter's own
# README names as the vide-fallback coverage gap.
#
# Cost: one full network install (~4-6 min). Run when users.py or the vide
# branch of install_flow.py changes, and before release — not per commit.
#
# Needs: rootless podman + the vide-itest:debian image (built by the arbiter).
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
export XDG_RUNTIME_DIR

if [[ ${EUID:-$(id -u)} -eq 0 && "${VIDE_ITEST_ALLOW_ROOTFUL:-}" != 1 ]]; then
  echo "refusing rootful podman (same policy as tests/integration/run.sh)" >&2
  exit 77
fi

IMG=vide-itest:debian
podman image exists "$IMG" || { echo "build the arbiter image first: tests/integration/run.sh" >&2; exit 69; }

CID=""
cleanup() { [[ -n "$CID" ]] && podman rm -f "$CID" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

CID=$(podman run -d --label vide-itest=1 --systemd=always --cgroupns=private \
      -v "$REPO:/vide:ro" -e VIDE_IN_THROWAWAY_CONTAINER=1 "$IMG") || exit 1

podman exec "$CID" bash -c '
  for i in $(seq 60); do
    s=$(systemctl is-system-running 2>/dev/null)
    case "$s" in running|degraded) exit 0;; esac; sleep 1
  done; exit 1' || { echo "systemd never settled" >&2; exit 1; }

podman exec "$CID" /vide/tests/vide-branch/in-container.sh
