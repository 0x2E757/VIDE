"""TUI gate: is this invocation allowed (and able) to open the wizard?

Import rules (pinned by I7): this file is imported to DECIDE whether curses
is usable, so it must itself be importable everywhere — curses only inside
functions, guarded. The sibling modules (session/widgets/screens) may import
curses at module level because they load only after probe() passed.

Two failure classes, deliberately distinct:
- DEGRADE (no _curses extension — python3-minimal-only boxes): fall to the
  plain flow silently-ish; the operator asked for nothing exotic.
- UNUSABLE (a real terminal that cannot host curses: TERM unset/dumb/missing
  from terminfo, zero size): STOP with the reason and a ready-to-paste
  --no-gui command. A broken terminal on an interactive session should be
  told, not guessed around — silent fallback is reserved for redirected
  streams (scripted intent).
"""
from __future__ import annotations

import os


class TuiUnavailable(Exception):
    def __init__(self, reason: str, *, degrade: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.degrade = degrade  # True → plain fallback; False → stop + advice


def wizard_eligible(stdin_tty: bool, stdout_tty: bool, no_gui: bool) -> bool:
    """The pure gate: BOTH stdio fds must be real terminals (a redirected
    stdout means `> snippet.conf` intent; a piped stdin means scripting), and
    --no-gui is the explicit off switch. stderr is deliberately NOT required
    (`2>err.log` may still open the wizard — the replay then lands in the
    log, which is correct). /dev/tty is NOT consulted: it exists in exactly
    the redirected cases this gate must exclude."""
    return stdin_tty and stdout_tty and not no_gui


def probe(term: str) -> None:
    """Raise TuiUnavailable when curses cannot start. setupterm is the ONLY
    safe probe order: C initscr() on a bad TERM prints 'Error opening
    terminal' and exit(1)s the whole process — it must never be reached
    before setupterm succeeded here."""
    try:
        import curses
    except ImportError:
        raise TuiUnavailable("this Python lacks the curses module "
                             "(python3-minimal-only box?)", degrade=True) from None
    # fd 1 LITERALLY, not sys.stdout.fileno(): the gate is about the
    # process's stdout descriptor (already isatty-checked by the caller),
    # and the sys.stdout OBJECT gets swapped by the session later.
    try:
        curses.setupterm(fd=1)
    except curses.error:
        raise TuiUnavailable(
            f"terminal type {term or '(unset TERM)'!r} is not usable (missing "
            "from terminfo? try: TERM=xterm-256color)") from None
    if curses.tigetstr("cup") is None:
        raise TuiUnavailable(
            f"terminal type {term!r} lacks cursor addressing (TERM=dumb?)")
    try:
        size = os.get_terminal_size(1)
    except OSError:
        raise TuiUnavailable("cannot determine the terminal size") from None
    # 80x24 is the wizard's layout floor (session.MIN_COLS/MIN_LINES): a
    # FIXED-geometry terminal below it (narrow serial console) must get the
    # refusal + paste-ready --no-gui twin here, not an inescapable in-session
    # "enlarge to continue" screen it can never satisfy. Runtime shrink of a
    # resizable terminal stays an in-session concern.
    if size.columns < 80 or size.lines < 24:
        raise TuiUnavailable(f"terminal too small for the wizard "
                             f"({size.columns}x{size.lines}; need 80x24)")
