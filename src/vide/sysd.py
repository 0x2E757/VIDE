"""Install the template unit + launcher; per-instance lifecycle.

The two files under units/ ship BYTE-IDENTICAL and the launcher stays a shell
script: it must source /etc/profile.d/vide-pnpm.sh (POSIX sh), porting it to
Python would put a python3 runtime dep inside every unit start, and its
FILENAME is the journald syslog identifier operators grep.
"""
from __future__ import annotations

import filecmp
from pathlib import Path

from . import contract
from .config import Config
from .executor import Executor
from .reporter import Reporter


def install_launcher(cfg: Config, ex: Executor) -> None:
    ex.ensure_dir(Path(cfg.launcher).parent, mode=0o755, owner=("root", "root"))
    ex.run(["install", "-m", "0755", "-o", "root", "-g", "root",
            str(cfg.repo_dir / "units/code-server-launch"), str(cfg.launcher)])


def install_unit(cfg: Config, ex: Executor, rep: Reporter) -> None:
    install_launcher(cfg, ex)
    src = cfg.repo_dir / "units/code-server@.service"
    # Only rewrite + daemon-reload when the shipped unit actually differs, so
    # converging an unrelated user doesn't churn the shared template. The
    # comparison is READ-ONLY, so it runs in dry-run too and the preview shows
    # the REAL conditional outcome (absent unit => differs => both listed).
    existed = Path(cfg.unit_path).is_file()
    if existed and filecmp.cmp(src, cfg.unit_path, shallow=False):
        rep.debug("template unit unchanged; skipping daemon-reload")
        return
    ex.run(["install", "-m", "0644", "-o", "root", "-g", "root",
            str(src), str(cfg.unit_path)])
    ex.run(["systemctl", "daemon-reload"])
    # …and SAY so. A converge deliberately restarts no instance — installing user
    # B must not drop A, C and D — so a template change is LATENT: it applies to
    # each instance at its next restart, which on an unattended box means all of
    # them at once, at the next reboot. That is tolerable only if the operator was
    # told, because the current template FAILS the start when it cannot freeze the
    # socket directory. The warning lives here rather than at the two call sites so
    # the password and SSO paths cannot drift apart. Gated on the unit having
    # EXISTED, because a first install has nothing to restart — enable_start is
    # about to start the only instance there is, on the new template — and a
    # warning printed where no action is possible is how a warning gets ignored
    # on the day it matters. Which instances predate the change is NOT recorded,
    # here or anywhere: systemd does not keep the unit text a running instance
    # started from, so nothing can observe it after the fact. The message says so
    # rather than pointing at a doctor row that does not exist.
    # …and not under --dry-run, where nothing was written and no restart is owed.
    # Its named twin excludes the preview for the same reason: a dry run that
    # prints an action item the operator cannot act on teaches them the preview
    # says things that are not true.
    if existed and not ex.dry_run:
        rep.warn(contract.MSG_TEMPLATE_RESTART_PENDING)


def enable_start(ex: Executor, user: str) -> None:
    ex.run(["systemctl", "enable", "--now", f"code-server@{user}.service"])


def stop_instance(ex: Executor, user: str) -> None:
    ex.run(["systemctl", "stop", f"code-server@{user}.service"])


def disable_instance(ex: Executor, user: str) -> None:
    ex.run(["systemctl", "disable", f"code-server@{user}.service"])


def restart_instance(ex: Executor, user: str) -> None:
    ex.run(["systemctl", "restart", f"code-server@{user}.service"])
