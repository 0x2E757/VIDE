"""VIDE entry point. The `vide` and `install.sh` shims exec this file
directly, so it must bootstrap sys.path itself (direct-file execution puts
src/vide/ on the path, not src/). `python3 -m vide` also lands here.
"""
from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

# Direct-file execution (the shims exec this file) puts the PACKAGE DIR
# ITSELF on sys.path[0] — which lets `import secrets`/`import errors` inside
# the package resolve to vide/*.py as top-level modules and SHADOW the stdlib
# (secrets.py then dies on its own relative imports). Scrub the package dir
# out and put src/ in, so `vide.*` resolves properly. resolve() first — the
# shims are reached through the /usr/local/bin/vide symlink.
_HERE = Path(__file__).resolve().parent   # src/vide
_SRC = _HERE.parent                       # src
sys.path[:] = [p for p in sys.path if p and Path(p).resolve() != _HERE]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# `vide ls | head` must die 141 like bash, not spew a BrokenPipeError
# traceback: Python ignores SIGPIPE by default; restore the OS default.
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

from vide.cli import main               # noqa: E402
from vide.errors import CommandFailed, VideError  # noqa: E402
from vide.reporter import Reporter      # noqa: E402

REPO_DIR = _SRC.parent


def _run() -> int:
    argv = sys.argv[1:]
    try:
        return main(argv, REPO_DIR)
    except VideError as e:
        # Operator-grade message, no traceback in the normal case; the code IS
        # the contract. --debug re-raises for the full stack.
        Reporter().err(str(e))
        if "--debug" in argv or os.environ.get("VIDE_DEBUG") == "1":
            raise
        return int(e.code)
    except CommandFailed as e:
        # set -e parity: exit with the FAILING CHILD's status (apt's, etc.).
        Reporter().err(str(e))
        return e.returncode
    except KeyboardInterrupt:
        # Die WIFSIGNALED like bash (status 128+SIGINT), not a traceback.
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGINT)
        return 130  # unreachable; belt for exotic signal dispositions


if __name__ == "__main__":
    raise SystemExit(_run())
