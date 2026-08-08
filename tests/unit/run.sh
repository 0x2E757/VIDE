#!/usr/bin/env bash
# The unit tier, one command, no root, no network, <5s.
set -euo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 "$REPO/tests/unit/run.py"
