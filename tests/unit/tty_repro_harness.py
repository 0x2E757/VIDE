"""Reproduces the kernel fact behind the live smoke §1 hang: a ticking child
in a non-foreground process group that tcsetattr's its tty stdin draws an
unconditional SIGTTOU stop (apt's StopPtyMagic shape, Debian #555632), and
the Executor poll loop then waits on the stopped child forever.

Deliberately NOT a test_* module — run.py discovery skips it; TestTickingSpawn
runs it as a SUBPROCESS with an external watchdog timeout, because a
regression here HANGS: the kill switch must live outside the hung process.
Standalone check: `setsid python3 tty_repro_harness.py` (TIOCSCTTY needs a
session leader with no controlling tty) — exits 0 promptly on a stop-proof
executor and never returns on the pre-fix one.

Linux-only (TIOCSCTTY, /proc). The caller must start us with
start_new_session=True: a session leader with no controlling terminal can
acquire the FRESH pty via TIOCSCTTY, so the runner's own terminal is never
touched (the TestGlobalFlagsReachInstall lesson).
"""
from __future__ import annotations

import fcntl
import os
import sys
import termios
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from vide.executor import Executor  # noqa: E402
from vide.reporter import Reporter  # noqa: E402


def main() -> int:
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.dup2(slave, 0)  # stdin IS our controlling tty — the wizard's situation
    ex = Executor(dry_run=False, reporter=Reporter(stream=sys.stderr),
                  tick=lambda: time.sleep(0.01))
    # The apt shape: touch the terminal ONLY if stdin is one. A child that
    # never sees a tty exits 0 instantly; an inherited-tty child in a
    # background pgrp stops in state T and the run() below never returns.
    ex.run([sys.executable, "-c",
            "import os, termios\n"
            "if os.isatty(0):\n"
            "    termios.tcsetattr(0, termios.TCSANOW, termios.tcgetattr(0))\n"])
    # master stays open until exit ON PURPOSE: closing it while the slave is
    # our controlling tty raises SIGHUP against our own foreground pgrp.
    del master
    return 0


if __name__ == "__main__":
    sys.exit(main())
