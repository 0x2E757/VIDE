"""Confirmation policy — the one place destructive intent is checked.

The case law this file encodes:
- The ONLY bypass for destructive verbs is per-invocation argv --yes. There is
  deliberately no env waiver: `.env` is shared by both entry points, so an
  env-level "skip confirmations" set to automate the idempotent installer
  would silently waive `vide destroy`'s only guard. Config and control must
  not share a channel — structurally, Config has no such field to read.
- TTY presence is probed by OPENING /dev/tty, never by stat: the device node
  is 0666 even in a process with NO controlling terminal (podman exec, cron,
  systemd), where open() fails ENXIO. The -r test passed there and the guard
  then died raw with exit 1 instead of the documented EX_USAGE. Fail closed,
  with the remediation in the message.
- The ROOT-instance challenge (typed ROOT) is never waived by --yes; its only
  non-interactive opt-in is VIDE_CONFIRM_ROOT=ROOT, read from PROCESS ENV
  ONLY — never from .env (stricter than bash's accidental set -a behavior;
  the fail-closed direction).
"""
from __future__ import annotations

import os
import re
from typing import Callable, Mapping, TextIO

from .errors import NoPermError, UsageError
# ROOT_BANNER moved to prompter.py (one source, two renderers: this module's
# plain-path banner + the wizard's decision-point screen); re-exported here
# so existing importers keep working.
from .prompter import ROOT_BANNER  # noqa: F401
from .reporter import Reporter


def _open_tty() -> tuple[TextIO, TextIO]:
    return open("/dev/tty", "w"), open("/dev/tty", "r")


class Confirmer:
    def __init__(self, *, yes_argv: bool, environ: Mapping[str, str],
                 reporter: Reporter,
                 tty_opener: Callable[[], tuple[TextIO, TextIO]] = _open_tty) -> None:
        self._yes = yes_argv           # from argv parsing ONLY — no env fallback exists
        self._env = environ
        self._rep = reporter
        self._open = tty_opener

    def confirm_destructive(self, prompt: str) -> bool:
        if self._yes:
            return True
        try:
            w, r = self._open()
        except OSError:
            raise UsageError("destructive action needs confirmation: pass --yes "
                             "on the command line, or run on a TTY") from None
        with w, r:
            w.write(f"{prompt} [y/N] ")
            w.flush()
            ans = r.readline()
        # Strip stray whitespace/CR: a terminal or SSH client can deliver
        # 'y ' or 'y\r', and silently rejecting a deliberate yes is a rotten
        # failure mode when the alternative is retyping a destructive command.
        ans = re.sub(r"[\r\n\t ]", "", ans)
        return ans.lower() in ("y", "yes")

    def confirm_root_instance(self) -> None:
        self._rep.banner(ROOT_BANNER)
        # A ROOT instance is NEVER waved through by the generic --yes flag.
        if self._env.get("VIDE_CONFIRM_ROOT") == "ROOT":
            self._rep.warn("VIDE_CONFIRM_ROOT=ROOT set — proceeding with root instance")
            return
        try:
            w, r = self._open()
        except OSError:
            raise UsageError("root instance needs interactive confirmation "
                             "(or VIDE_CONFIRM_ROOT=ROOT)") from None
        with w, r:
            w.write("Type ROOT to proceed: ")
            w.flush()
            # rstrip("\r\n"): belt-and-suspenders for CR-bearing input. The
            # normal path rarely sees it (the tty line discipline maps CR->NL
            # and text-mode open() adds universal-newlines translation) — this
            # covers readers WITHOUT that translation (an injected tty_opener,
            # a raw-ish line discipline), where a trailing "\r" would refuse a
            # correctly typed ROOT. Nothing else is stripped: "root", " ROOT"
            # etc. still refuse — the ceremony tests INTENT, not line endings.
            ans = r.readline().rstrip("\r\n")
        if ans != "ROOT":
            raise UsageError("root instance not confirmed")


def require_root(dry_run: bool, reporter: Reporter, hint_argv: str) -> None:
    """Root gate. Under dry-run it warns so a preview runs anywhere — skipping
    an ASSERTION, never a mutation (the bash allowlisted exactly this)."""
    if os.geteuid() == 0:
        return
    if dry_run:
        reporter.warn("[dry-run] not running as root; a real run requires root (sudo)")
        return
    raise NoPermError(f"must run as root — re-run with: sudo {hint_argv}")
