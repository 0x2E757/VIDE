#!/usr/bin/env bash
# The sso-mode gate: the acceptance contract for passwordless Google SSO —
# unix-socket instances behind ONE VIDE-managed oauth2-proxy, with a
# PER-INSTANCE email whitelist enforced through Caddy's forward_auth.
#
# Deliberately NOT under tests/integration/ — that directory is byte-frozen and
# its authority IS its immutability (the parity and vide-branch tiers set the
# precedent). sso-mode has no bash referent: the old shell could never pass it,
# so it is not arbitration, it is a new standing gate.
#
# What makes this gate honest: it runs a REAL oauth2-proxy (installed through
# VIDE's own install path, never pre-baked), a REAL Caddy playing the operator,
# and a fake-but-real-RS256 OIDC provider (tests/sso-mode/fake-idp.py) so a
# LOGIN ACTUALLY COMPLETES. Without a completed login, "non-whitelisted email is
# refused", "revoke works" and "rotate-sso kills live cookies" are all
# unassertable — the entire authz boundary would ship on a human's word.
#
# CADENCE:
#   WHILE THE SSO SLICE IS UNDER CONSTRUCTION: run PER COMMIT, alongside unit +
#   prove-teeth. This is the period of highest regression density and this gate
#   is the only thing with teeth on the authz boundary.
#   AFTER the slice is declared done: decay to the vide-branch policy — run when
#   src/vide/sso.py, oauth2proxy.py, caddy.py, registry.py, the unit/launcher
#   templates, the secrets intake, or anything under tests/sso-mode/ changes,
#   and before every release.
# Cost: one full network install + oauth2-proxy + caddy fetch (~6-9 min).
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

podman exec "$CID" /vide/tests/sso-mode/in-container.sh
