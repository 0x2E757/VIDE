#!/usr/bin/env bash
# Artifact-shape gate: install in one container and diff every durable artifact
# — after normalizing legitimate nondeterminism (port, argon2 hash, cookie
# suffix) — against golden/durable-artifacts.txt, the frozen reference shape of
# a password-mode install. Capture and re-bless history lives in
# golden/PROVENANCE.md. The password-mode artifacts are byte-frozen; the unit
# (last on 2026-07-31, twice: for the socket-symlink guard and then for the
# socket-directory freeze that replaced it as the control), the launcher and the
# user-settings-seed sections have legitimately moved. Both 2026-07-31 blesses
# were taken from OBSERVED container installs — the first of those runs also
# confirmed the 2026-07-30 settings-seed hunk, which until then had been DERIVED
# from DEFAULT_SETTINGS rather than captured.
#
# The arbiter asserts BEHAVIOR; this pins SHAPE. A field-set or permission
# difference is a finding even when the arbiter is green. There is no bless
# flag: a red hunk is investigated, and only a manually-verified upstream or
# deliberate shape change may update the golden (procedure in PROVENANCE.md).
#
# Deliberately NOT under tests/integration/ — that directory is byte-frozen
# (the acceptance gate's authority is its immutability) and its static guards
# glob "$_IT_DIR"/*.sh.
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

GOLDEN="$REPO/tests/parity/golden/durable-artifacts.txt"
[[ -s "$GOLDEN" ]] || { echo "golden fixture missing: $GOLDEN" >&2; exit 70; }

CID=
cleanup() { [[ -n "$CID" ]] && podman rm -f "$CID" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

boot() { # start the container, wait for systemd
  CID=$(podman run -d --label vide-itest=1 --systemd=always --cgroupns=private \
        -v "$REPO:/vide:ro" -e VIDE_IN_THROWAWAY_CONTAINER=1 "$IMG")
  podman exec "$CID" bash -c '
    for i in $(seq 60); do
      s=$(systemctl is-system-running 2>/dev/null)
      case "$s" in running|degraded) exit 0;; esac; sleep 1
    done; exit 1'
}

install_python() {
  podman exec "$CID" bash -c "
    useradd -m -s /bin/bash ittest
    VIDE_CODE_SERVER_PIN_LATEST=1 /vide/install.sh --user ittest >/tmp/out.log 2>/tmp/err.log
    rc=\$?; echo rc=\$rc; exit \$rc"
}

# Frozen normalization: this function produced the golden; any edit to it
# invalidates golden/durable-artifacts.txt and requires the documented re-bless
# (golden/PROVENANCE.md). The in-container payload (the single-quoted script)
# is byte-for-byte the one that harvested the golden; only the exec wrapper
# changed with the move to a single container.
harvest() { # normalized artifact dump to stdout
  podman exec "$CID" bash -c '
    port=$(sed -n "s/^VIDE_PORT=//p" /etc/vide/ittest.env)
    echo "=== port-record ==="
    sed "s/=$port\$/=PORT/" /etc/vide/ittest.env
    echo "=== config.yaml (normalized) ==="
    sed -e "s/127.0.0.1:$port/127.0.0.1:PORT/" \
        -e "s|hashed-password: \".*\"|hashed-password: \"HASH\"|" \
        -e "s|cookie-suffix: vide-ittest-.*|cookie-suffix: vide-ittest-RAND|" \
        /home/ittest/.config/code-server/config.yaml
    echo "=== config.yaml stat ==="
    stat -c "%a %U:%G" /home/ittest/.config/code-server/config.yaml
    # seed_user_settings writes this ONCE and never converges, so a wrong seed
    # is permanent per instance and can only be fixed by hand — the highest
    # consequence durable artifact VIDE emits, and the only one that sat
    # outside this gate.
    echo "=== user settings seed ==="
    cat /home/ittest/.local/share/code-server/User/settings.json 2>/dev/null || echo "(absent)"
    echo "=== unit file ==="
    cat /etc/systemd/system/code-server@.service
    echo "=== launcher ==="
    cat /usr/local/lib/vide/code-server-launch
    stat -c "%a %U:%G" /usr/local/lib/vide/code-server-launch
    echo "=== profile.d ==="
    cat /etc/profile.d/vide-pnpm.sh
    stat -c "%a %U:%G" /etc/profile.d/vide-pnpm.sh
    echo "=== bin layout ==="
    for b in node npm npx pnpm; do
      if [ -L /usr/local/bin/$b ]; then echo "$b: symlink"; else
        echo "$b: file $(stat -c %a /usr/local/bin/$b)"; fi
    done
    echo "=== opt perms ==="
    stat -c "%a" /opt/nvm /opt/pnpm
    echo "=== guard exit code ==="
    vide destroy ittest </dev/null >/dev/null 2>&1; echo "destroy-no-yes=$?"
    echo "=== snippet (normalized) ==="
    # Compare the CONTRACT portion of stdout — the snippet — not raw stdout:
    # bash leaked ensure_prereqs apt chatter onto stdout (incidental noise the
    # arbiter never pinned); the Python executor routes mutation stdout to
    # stderr, deliberately IMPROVING on that. A raw diff would flag the
    # improvement as drift.
    sed -n "/# --- VIDE per-instance/,\$p" /tmp/out.log \
      | sed "s/127.0.0.1:$port/127.0.0.1:PORT/"
    echo "=== SHOWN-ONCE count ==="
    grep -c "SHOWN ONCE" /tmp/err.log'
}

echo "booting one container (python install vs bash-era golden)..." >&2
boot || { echo "container never reached running/degraded" >&2; exit 1; }

echo "installing via Python (network, minutes)..." >&2
install_python >&2 || {
  echo "python install failed — tail of the container's err.log:" >&2
  podman exec "$CID" tail -n 20 /tmp/err.log >&2
  exit 1
}

harvest > /tmp/vide-parity-B.txt

if diff -u "$GOLDEN" /tmp/vide-parity-B.txt; then
  echo "PARITY: zero artifact differences after normalization"
else
  echo "PARITY BROKEN — every hunk above is a finding" >&2
  exit 1
fi
