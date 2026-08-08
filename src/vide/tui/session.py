"""The curses session: terminal ownership, fd-level log capture, the exit
funnel. This module owns every byte that must survive the wizard:

- While curses is on screen, the REAL fd 2 is dup2-captured into an UNLINKED
  regular temp file — a file, deliberately NOT a pipe: a pipe with no reader
  deadlocks a chatty child (apt) at 64 KiB, a file has no limit and needs no
  drain thread; unlinked means no on-disk artifact survives the process.
  Because the capture is at the fd, Executor's child-stdout→fd-2 routing and
  every C-level/grandchild write land in it with zero Executor changes, and
  the Reporter (which holds the sys.stderr OBJECT, whose writes go to fd 2)
  needs no tee. One fd = one ordering.
- Python-level stdout (the Caddy snippet) is captured by swapping the
  sys.stdout OBJECT; fd 1 itself stays the terminal — it is curses' canvas
  (curses.newterm does not exist on the 3.10 floor, so curses cannot be
  pointed anywhere else).
- The exit funnel runs on EVERY exit (success, VideError, Ctrl-C, SIGTERM):
  endwin → restore fds → replay the whole capture to the real stderr →
  deferred notes (summary) → deferred SECRETS → buffered stdout (snippet)
  to the real stdout. Secrets never enter the capture or the pane; they are
  handed to defer_secret() and exist nowhere else (see prompter.py).

This is the one tui module sanctioned by I3 to touch print/sys.stdout: the
post-endwin funnel IS its job.
"""
from __future__ import annotations

import curses
import io
import locale
import os
import re
import signal
import sys
import tempfile
import time
from typing import IO, Callable, TextIO

MIN_COLS, MIN_LINES = 80, 24
PANE_LINES = 6
# Re-exported so the composition root (cli) can catch rendering failures
# without importing curses itself (I7 confines that to tui/).
CursesError = curses.error
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]")
_SPINNER = "|/-\\"


class StdioCapture:
    """The fd/stream half of the session, curses-free and unit-testable on
    its own: fd-2 dup2 into the unlinked temp file, the sys.stdout object
    swap, the pump (pane lines), and the exit funnel."""

    def __init__(self) -> None:
        self._saved_fd2 = -1
        self._file: IO[bytes] | None = None
        self._read_off = 0
        self._partial = b""
        self.lines: list[str] = []
        self._notes: list[str] = []     # post-endwin, before secrets (summary)
        self._secrets: list[str] = []   # post-endwin, last before the prompt
        self._stdout_buf: io.StringIO | None = None
        self._real_stdout: TextIO | None = None

    def start(self) -> None:
        self._file = tempfile.TemporaryFile(prefix="vide-tui.")
        sys.stderr.flush()
        self._saved_fd2 = os.dup(2)
        os.dup2(self._file.fileno(), 2)
        self._real_stdout = sys.stdout
        self._stdout_buf = io.StringIO()
        sys.stdout = self._stdout_buf

    def stop_and_replay(self) -> None:
        """Restore the real fds, then the funnel, in the scannable-scrollback
        order: log replay first, durable notes and SECRETS last (closest to
        the prompt); the machine channel (snippet) to the real stdout."""
        if self._saved_fd2 >= 0:
            sys.stderr.flush()
            os.dup2(self._saved_fd2, 2)
            os.close(self._saved_fd2)
            self._saved_fd2 = -1
        if self._real_stdout is not None:
            sys.stdout = self._real_stdout
            self._real_stdout = None
        # EIO-defensive: an ssh drop leaves a hung-up pty and every write
        # raises — cleanup must still finish.
        try:
            self._funnel()
        except OSError:
            pass
        f, self._file = self._file, None
        if f is not None:
            f.close()

    def _funnel(self) -> None:
        f = self._file
        if f is not None:
            try:
                self.pump()  # fold the unread tail so the count is honest
            except OSError:
                pass  # a stale count must never cost the notes/secrets below
            # fstat AFTER pump: a straggler child still holding the dup2'd
            # descriptor can append at any moment — a size snapshotted before
            # the fold would silently drop its bytes from the replay, right
            # under the "nothing was lost" banner. Guarded like the pump: a
            # failing stat costs the replay, never the notes/secrets below.
            try:
                size = os.fstat(f.fileno()).st_size
            except OSError:
                size = 0
            if size:
                n = len(self.lines) + (1 if self._partial else 0)
                sys.stderr.write(f"---- wizard log, replayed ({n} "
                                 f"line{'s' if n != 1 else ''}; "
                                 "nothing was lost, only deferred) ----\n")
                sys.stderr.flush()
                off = 0
                while off < size:
                    data = os.pread(f.fileno(), 1 << 16, off)
                    if not data:
                        break
                    off += len(data)
                    os.write(2, data)
                sys.stderr.write("---- end of replay ----\n")
        for line in self._notes:
            sys.stderr.write(line if line.endswith("\n") else line + "\n")
        for line in self._secrets:
            sys.stderr.write(line if line.endswith("\n") else line + "\n")
        sys.stderr.flush()
        out = self._stdout_buf.getvalue() if self._stdout_buf is not None else ""
        if out:
            sys.stdout.write(out)
            sys.stdout.flush()

    def pump(self) -> bool:
        """Fold new capture bytes into display lines. os.pread — the write
        offset is shared by every writer on the dup2'd description, so the
        reader must not move it. Returns True when new lines appeared."""
        f = self._file
        if f is None:
            return False
        size = os.fstat(f.fileno()).st_size
        grew = False
        while self._read_off < size:
            data = os.pread(f.fileno(), 1 << 16, self._read_off)
            if not data:
                break
            self._read_off += len(data)
            self._partial += data
            grew = True
        if not grew:
            return False
        # \r is a line boundary too (apt/dpkg progress redraws) — the pane
        # shows the LAST state of such a line; the replay keeps raw bytes.
        norm = self._partial.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        parts = norm.split(b"\n")
        self._partial = parts.pop()
        for p in parts:
            self.lines.append(_ANSI_RE.sub("", p.decode("utf-8", errors="replace")))
        return True

    def defer_note(self, text: str) -> None:
        self._notes.append(text)

    def defer_secret(self, line: str) -> None:
        """The ONLY place a secret waits: a Python list, never the capture
        file, never the pane, never a curses cell."""
        self._secrets.append(line)


class Session:
    def __init__(self, *, dry_run: bool = False) -> None:
        self.scr: "curses.window | None" = None
        self.dry_run = dry_run
        # wired by the composition root: kills the Executor's current child
        self.on_abort: Callable[[], None] | None = None
        self.too_small = False          # set by _draw_chrome; widgets go inert
        self._abort_pending = False
        self._in_abort_modal = False    # set ONLY around the abort-ask modal
        self._cap = StdioCapture()
        self._old_handlers: dict[int, object] = {}
        self._status = ""               # current activity, drawn in the header
        self._status_t0 = 0.0
        self._spin = 0

    # ---- lifecycle -----------------------------------------------------------

    def __enter__(self) -> "Session":
        try:
            # required for ncursesw multibyte I/O; a broken forwarded LANG is
            # common over ssh — degrade to C rather than crash.
            locale.setlocale(locale.LC_ALL, "")
        except locale.Error:
            locale.setlocale(locale.LC_ALL, "C")
        # Everything from the capture on is under the try: a failure half-way
        # (even the microsecond ^C window before our handler lands) must not
        # leave fd 2 pointing into the unlinked file for the rest of the
        # process — __main__'s error line would vanish into it.
        try:
            self._cap.start()
            self._install_signals()
            self.scr = curses.initscr()
            curses.noecho()
            # cbreak, NOT raw: ISIG stays on — the operator must keep ^C even
            # while a child wedges (children sit in their own process group,
            # so the terminal SIGINT reaches only us).
            curses.cbreak()
            self.scr.keypad(True)
            try:
                curses.start_color()
                curses.use_default_colors()
            except curses.error:
                pass
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            self.scr.timeout(100)  # the tick heartbeat: getch blocks ≤100 ms
            self._set_bracketed_paste(True)
        except BaseException:
            self._teardown()
            raise
        return self

    def _set_bracketed_paste(self, on: bool) -> None:
        """Enable/disable terminal bracketed-paste mode (?2004) so a paste
        arrives wrapped in ESC[200~…ESC[201~ — the widgets parser then keeps a
        pasted newline from self-submitting a field. EIO-defensive like the
        funnel: a hung-up pty must not turn this into a crash."""
        import os as _os
        try:
            _os.write(1, b"\x1b[?2004h" if on else b"\x1b[?2004l")
        except OSError:
            pass

    def __exit__(self, et: object, ev: object, tb: object) -> None:
        self._teardown()
        return None  # never swallow the in-flight exception

    def _teardown(self) -> None:
        # Order is the whole point: endwin FIRST (terminal sane), then the
        # funnel onto a normal screen, and only THEN the original signal
        # dispositions — a reflexive ^C (or a SIGTERM) during the replay must
        # not truncate it mid-way and eat the deferred one-time password, so
        # the funnel runs with INT/TERM/HUP held ignored.
        if self.scr is not None:
            self._set_bracketed_paste(False)   # before endwin: leave the shell clean
            try:
                curses.endwin()
            except curses.error:
                pass
            self.scr = None
        held: dict[int, object] = {}
        for num in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                held[num] = signal.signal(num, signal.SIG_IGN)
            except (TypeError, ValueError, OSError):
                pass
        try:
            self._cap.stop_and_replay()
        finally:
            if self._old_handlers:
                self._restore_signals()  # the pre-session originals
            else:
                # teardown before _install_signals ran: just undo the holds
                for num, h in held.items():
                    try:
                        signal.signal(num, h)  # type: ignore[arg-type]
                    except (TypeError, ValueError, OSError):
                        pass

    # ---- deferred delivery (delegated) ----------------------------------------

    def defer_note(self, text: str) -> None:
        self._cap.defer_note(text)

    def defer_secret(self, line: str) -> None:
        self._cap.defer_secret(line)

    @property
    def _lines(self) -> list[str]:
        return self._cap.lines

    # ---- signals ---------------------------------------------------------------

    def _install_signals(self) -> None:
        self._old_handlers = {
            signal.SIGINT: signal.getsignal(signal.SIGINT),
            signal.SIGHUP: signal.getsignal(signal.SIGHUP),
            signal.SIGTERM: signal.getsignal(signal.SIGTERM),
        }
        signal.signal(signal.SIGINT, self._on_sigint)
        # ssh drop / kill: DIE, through the exit funnel (no daemonizing —
        # recovery is converge idempotence; a never-shown password is
        # recovered with `vide rotate`). SIGWINCH/SIGTSTP stay with ncurses.
        signal.signal(signal.SIGHUP, self._on_fatal)
        signal.signal(signal.SIGTERM, self._on_fatal)

    def _restore_signals(self) -> None:
        for num, h in self._old_handlers.items():
            try:
                signal.signal(num, h)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                pass
        self._old_handlers = {}

    def _on_sigint(self, signum: int, frame: object) -> None:
        if self._in_abort_modal:
            raise KeyboardInterrupt  # second ^C: leave NOW (funnel still runs)
        self._abort_pending = True   # first ^C: ask, don't yank

    def _on_fatal(self, signum: int, frame: object) -> None:
        raise SystemExit(128 + signum)

    # ---- the tick (Executor heartbeat) ----------------------------------------

    def tick(self) -> None:
        """Runs while a child works: pump the capture into the pane, repaint,
        service one key, honor a pending ^C. Blocks ≤100 ms in getch — this
        pacing is what the Executor's poll loop relies on."""
        self._service_abort(during_exec=True)
        self._draw_chrome()
        assert self.scr is not None
        ch = self.scr.getch()
        if ch == curses.KEY_RESIZE:
            self._on_resize()
        elif ch in (ord("l"), ord("L")):
            self.log_view(during_exec=True)

    def _service_abort(self, *, during_exec: bool) -> None:
        if not self._abort_pending or self._in_abort_modal:
            return
        self._abort_pending = False
        msg = ("Abort install? The running step will be killed; completed "
               "steps are safe to re-run (converge). [y/N]" if during_exec else
               "Abort install? Completed steps remain; re-running converges. [y/N]")
        # The flag is scoped to THIS modal only: a second ^C while it is open
        # means leave-now; a first ^C inside any OTHER modal (ROOT challenge,
        # destroy confirm) re-enters here and asks first, like everywhere.
        self._in_abort_modal = True
        try:
            confirmed = self.modal_confirm(msg)
        finally:
            self._in_abort_modal = False
        if confirmed:
            if during_exec and self.on_abort is not None:
                self.on_abort()
            raise KeyboardInterrupt

    def check_abort(self) -> None:
        """Question screens call this between keys (their getch is blocking-
        with-timeout too, so a ^C never waits on user input)."""
        self._service_abort(during_exec=False)

    # ---- chrome ----------------------------------------------------------------

    def _pump(self) -> None:
        self._cap.pump()

    def set_status(self, text: str) -> None:
        if text != self._status:
            self._status_t0 = time.monotonic()  # elapsed counter per phase
        self._status = text

    def _draw_chrome(self) -> None:
        # Pump on EVERY repaint, not only in tick(): a dry-run walk never
        # spawns and hence never ticks, so without this the pane sits frozen
        # at emptiness while the narration piles up in the capture. First
        # statement — even the too-small freeze must not stall the offset.
        self._pump()
        assert self.scr is not None
        scr = self.scr
        h, w = scr.getmaxyx()
        if h < MIN_LINES or w < MIN_COLS:
            # A real freeze: too_small also makes the widget loops inert, so
            # keys cannot blindly drive an invisible screen.
            self.too_small = True
            scr.erase()
            put(scr, 0, 0, f"terminal too small: need {MIN_COLS}x{MIN_LINES}, "
                           f"have {w}x{h} - enlarge to continue (Ctrl-C aborts)")
            scr.refresh()
            return
        self.too_small = False
        self._spin = (self._spin + 1) % len(_SPINNER)
        badge = " [DRY-RUN]" if self.dry_run else ""
        elapsed = f" ({int(time.monotonic() - self._status_t0)}s)" if self._status_t0 else ""
        head = f" VIDE install{badge}  {self._status}{elapsed} {_SPINNER[self._spin]}"
        put(scr, 0, 0, head.ljust(w - 1), curses.A_REVERSE)
        pane_top = h - PANE_LINES - 1
        put(scr, pane_top, 0, "-" * (w - 1), 0)
        put(scr, pane_top, 2, " log (l = full view) ", 0)
        for i, line in enumerate(self._lines[-PANE_LINES:]):
            # a WARN scrolling by unseen during a 3-minute apt run is the
            # pane's main risk — emphasize, since color is gone (non-tty fd).
            attr = curses.A_BOLD if line.startswith(("WARN", "ERROR")) else 0
            put(scr, pane_top + 1 + i, 0, line.ljust(w - 1)[:w - 1], attr)
        # blank any leftover pane rows
        for i in range(len(self._lines[-PANE_LINES:]), PANE_LINES):
            put(scr, pane_top + 1 + i, 0, " " * (w - 1))
        scr.refresh()

    def body_extent(self) -> tuple[int, int, int]:
        """(first_row, last_row, width) of the interaction region."""
        assert self.scr is not None
        h, w = self.scr.getmaxyx()
        return 1, max(2, h - PANE_LINES - 2), w

    def clear_body(self) -> None:
        assert self.scr is not None
        top, bottom, w = self.body_extent()
        for y in range(top, bottom + 1):
            put(self.scr, y, 0, " " * (w - 1))

    def _on_resize(self) -> None:
        curses.update_lines_cols()
        assert self.scr is not None
        self.scr.erase()
        self._draw_chrome()

    # ---- interactions the session itself owns -----------------------------------

    def log_view(self, *, during_exec: bool = False) -> None:
        """Full-screen view of everything captured so far — a live monitor,
        not a snapshot: it pumps every iteration and tail-follows while the
        view sits at the end (entered from tick() during apt, new lines keep
        arriving). `during_exec` keeps the abort modal's copy honest."""
        assert self.scr is not None
        scr = self.scr
        self._pump()
        follow = True
        off = max(0, len(self._lines) - (scr.getmaxyx()[0] - 2))
        while True:
            self._pump()
            h, w = scr.getmaxyx()
            page = h - 2
            if follow:
                off = max(0, len(self._lines) - page)
            scr.erase()
            put(scr, 0, 0, f" log - {len(self._lines)} lines"
                           f"{' (following)' if follow else ''}  "
                           "(arrows/PgUp/PgDn/Home/End, q = back)".ljust(w - 1),
                curses.A_REVERSE)
            for i, line in enumerate(self._lines[off:off + page]):
                put(scr, 1 + i, 0, line[:w - 1])
            scr.refresh()
            ch = scr.getch()
            if ch in (ord("q"), ord("Q"), 27):
                break
            if ch == curses.KEY_RESIZE:
                curses.update_lines_cols()
                continue
            if ch == curses.KEY_UP:
                off, follow = max(0, off - 1), False
            elif ch == curses.KEY_DOWN:
                off = min(max(0, len(self._lines) - page), off + 1)
                follow = off >= max(0, len(self._lines) - page)
            elif ch == curses.KEY_PPAGE:
                off, follow = max(0, off - page), False
            elif ch == curses.KEY_NPAGE:
                off = min(max(0, len(self._lines) - page), off + page)
                follow = off >= max(0, len(self._lines) - page)
            elif ch == curses.KEY_HOME:
                off, follow = 0, False
            elif ch == curses.KEY_END:
                follow = True
            self._service_abort(during_exec=during_exec)
        scr.erase()
        self._draw_chrome()

    def modal_confirm(self, prompt: str) -> bool:
        """Centered [y/N] modal; default N. Runs its own key loop, so it also
        works while a child is running (the child keeps writing to the
        capture; the pane resumes on return)."""
        ans = self.modal_input(prompt, visible=True, one_key="yn")
        return ans.lower() in ("y", "yes")

    def modal_input(self, prompt: str, *, visible: bool = True,
                    one_key: str = "") -> str:
        """The generic channel the Confirmer speaks through: show `prompt`,
        collect one line (visible — challenges are not secrets; masked entry
        is the password widget's job, in widgets.py). `one_key` restricts to
        single-key answers (y/n)."""
        assert self.scr is not None
        scr = self.scr
        try:
            buf = ""
            while True:
                # a first ^C inside any non-abort modal asks first, like
                # everywhere (the abort modal itself is guarded by the flag)
                self._service_abort(during_exec=False)
                self._pump()
                h, w = scr.getmaxyx()
                lines = [ln for chunk in prompt.splitlines() for ln in _wrap(chunk, w - 6)]
                box_h = len(lines) + 4
                top = max(1, (h - box_h) // 2)
                left = 2
                for i in range(box_h):
                    put(scr, top + i, left, " " * (w - 4), curses.A_REVERSE)
                for i, ln in enumerate(lines):
                    put(scr, top + 1 + i, left + 2, ln, curses.A_REVERSE)
                put(scr, top + box_h - 2, left + 2,
                     "> " + (buf if visible else "*" * len(buf)) + " ",
                     curses.A_REVERSE | curses.A_BOLD)
                scr.refresh()
                ch = scr.getch()
                if ch == -1:
                    continue
                if ch == curses.KEY_RESIZE:
                    self._on_resize()
                    continue
                if one_key and 0 < ch < 256 and chr(ch).lower() in one_key:
                    return chr(ch)
                if one_key and ch in (10, 13, 27, curses.KEY_ENTER):
                    return ""  # Enter/Esc on a y/N modal = the default (N)
                if ch in (10, 13, curses.KEY_ENTER):
                    return buf
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    buf = buf[:-1]
                elif ch == 21:  # Ctrl-U
                    buf = ""
                elif 32 <= ch < 127:
                    buf += chr(ch)
        finally:
            scr.erase()
            self._draw_chrome()

    def channel_opener(self) -> tuple[TextIO, TextIO]:
        """Confirmer's tty_opener, curses-backed: writes accumulate the prompt
        text; the first readline() renders it as a modal and returns the
        typed answer. Same-strength human-at-the-terminal proof as /dev/tty —
        which must NEVER be touched while curses owns the screen."""
        return _channel(self)


def _channel(session: Session) -> tuple[TextIO, TextIO]:
    w = io.StringIO()

    class _Reader(io.TextIOBase):
        def readline(self, size: int = -1) -> str:  # type: ignore[override]
            prompt = w.getvalue()
            w.seek(0)
            w.truncate()
            return session.modal_input(prompt.strip() or "confirm:") + "\n"

    return w, _Reader()


def _wrap(text: str, width: int) -> list[str]:
    if width < 8:
        return [text]
    out, cur = [], ""
    for word in text.split():
        if cur and len(cur) + 1 + len(word) > width:
            out.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}" if cur else word
    if cur or not out:
        out.append(cur)
    return out


def put(win: "curses.window", y: int, x: int, text: str, attr: int = 0) -> None:
    """Clipped, encoding-defensive addstr — EVERY draw in the package routes
    through here. curses encodes str with the window's locale-derived codec:
    under the C fallback that is ASCII, and one em dash (in a literal or in
    pumped child output) would otherwise crash the screen with
    UnicodeEncodeError. Fold instead of ever raising."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    n = max(0, w - x - (1 if y == h - 1 else 0))
    try:
        win.addnstr(y, x, text, n, attr)
    except UnicodeEncodeError:
        try:
            win.addnstr(y, x, text.encode("ascii", "replace").decode(), n, attr)
        except curses.error:
            pass
    except curses.error:
        pass


