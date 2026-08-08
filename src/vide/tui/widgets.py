"""Reusable curses widgets: menu, text field, masked password field.

Rendering rules (from the platform plan): ASCII everywhere in DRAWN strings —
no Unicode glyphs, no literal box-drawing (a C-locale console over serial
must render identically; session.put also folds defensively); state is
carried by markers and A_REVERSE, never color alone (TERM=vt100 has none).
Nothing is truncated silently: long titles and long menus scroll/clamp with
visible markers, and a too-small terminal makes the loops inert (keys must
not blindly drive an invisible screen).
"""
from __future__ import annotations

import curses

from .session import Session, put

# Bracketed-paste sentinels (the terminal wraps a paste in ESC[200~ … ESC[201~
# when mode ?2004 is enabled — session does that on entry). Parsing them is what
# stops a pasted trailing newline from self-submitting a half-entered secret,
# and stops the '[200~' bytes from silently entering a MASKED field where the
# operator can't see the corruption.
_PASTE_START = "[200~"
_PASTE_END = "[201~"


def filter_paste_text(raw: str) -> str:
    """Keep only printable ASCII; CR/LF are STRIPPED (a paste must never submit
    — the operator reviews, then presses Enter), and >127 stays dropped, the
    same policy as typed input."""
    return "".join(c for c in raw if 32 <= ord(c) < 127)


def _read_key(session: Session):
    """Return an int keycode, or a ("paste", text) tuple for a bracketed paste.
    On ESC, poll follow-up bytes (already buffered in the paste burst, so the
    100 ms timeout returns them at once): a CSI ending in 200~ opens a paste
    collected up to ESC[201~; any other CSI is discarded whole (stray sequence
    bytes never leak into a buffer); a lone ESC is discarded."""
    assert session.scr is not None
    scr = session.scr
    ch = scr.getch()
    if ch != 27:
        return ch
    # accumulate the CSI introducer after ESC
    seq = ""
    for _ in range(8):
        c = scr.getch()
        if c == -1:
            return -1  # lone ESC (or a torn sequence) — ignore, don't wedge
        seq += chr(c) if 0 <= c < 256 else ""
        if seq.endswith(_PASTE_START):
            break
        if len(seq) >= 5:
            return -1  # some other CSI — discard whole
    else:
        return -1
    # collect the paste payload until ESC[201~
    payload = ""
    while True:
        c = scr.getch()
        if c == -1:
            break  # unterminated paste burst — take what we have, fail safe
        if c == 27:
            tail = ""
            for _ in range(5):
                t = scr.getch()
                if t == -1:
                    break
                tail += chr(t) if 0 <= t < 256 else ""
                if tail.endswith(_PASTE_END):
                    return ("paste", filter_paste_text(payload))
            payload += tail  # a bare ESC inside the paste — keep filtering
        elif 0 <= c < 256:
            payload += chr(c)
    return ("paste", filter_paste_text(payload))


def _keys_hint(session: Session, text: str) -> None:
    assert session.scr is not None
    _, w = session.scr.getmaxyx()
    top, bottom, _w = session.body_extent()
    put(session.scr, bottom, 0, text.ljust(w - 1), curses.A_REVERSE)


def _swallow_inert(session: Session, ch: int) -> bool:
    """True when the key must be ignored: the too-small freeze screen is a
    real freeze — only resize (and ^C via the abort flag) get through."""
    if not session.too_small:
        return False
    if ch == curses.KEY_RESIZE:
        session._on_resize()
    return True


def _quit_confirm(session: Session) -> None:
    if session.modal_confirm("Quit the installer? Completed steps remain; "
                             "re-running converges. [y/N]"):
        raise KeyboardInterrupt


def menu(session: Session, title: str, options: list[tuple[str, str]],
         default: int = 0) -> int:
    """Arrow/Enter menu over (label, description) rows; returns the index.
    q quits with confirmation (same funnel as ^C); there is no Esc-'back' —
    the journey has no back across executed steps. Digits 1..9 jump-select."""
    assert session.scr is not None
    scr = session.scr
    sel = max(0, min(default, len(options) - 1))
    title_lines = title.splitlines()
    while True:
        session.check_abort()
        session.clear_body()
        top, bottom, w = session.body_extent()
        rows = bottom - top - 1                      # usable body rows
        # clamp the title so the options are ALWAYS visible; mark the cut
        max_title = max(1, rows - len(options) - 2)
        shown_title = title_lines[:max_title]
        if len(title_lines) > max_title:
            shown_title[-1] = shown_title[-1][: max(0, w - 14)] + "  [...more]"
        y = top + 1
        for ln in shown_title:
            put(scr, y, 2, ln, curses.A_BOLD)
            y += 1
        y += 1
        # scroll the option window around the selection when it overflows
        opt_rows = max(1, bottom - y)
        first = max(0, min(sel - opt_rows + 1, len(options) - opt_rows)) \
            if sel >= opt_rows else 0
        visible = options[first:first + opt_rows]
        for i, (label, desc) in enumerate(visible):
            idx = first + i
            marker = ">" if idx == sel else " "
            attr = curses.A_REVERSE if idx == sel else 0
            more = ""
            if i == 0 and first > 0:
                more = " ^"
            if i == len(visible) - 1 and first + opt_rows < len(options):
                more = " v"
            put(scr, y + i, 2, f" {marker} {label} ", attr)
            if desc:
                put(scr, y + i, 6 + len(label),
                    f" - {desc}{more}"[: max(0, w - 8 - len(label))])
        _keys_hint(session, " up/down move . Enter select . l log . q quit . Ctrl-C abort")
        session._draw_chrome()
        ch = _read_key(session)
        if isinstance(ch, tuple):
            continue  # a paste onto a MENU is discarded — it must never drive it
        if ch == -1 or _swallow_inert(session, ch):
            continue
        if ch == curses.KEY_RESIZE:
            session._on_resize()
        elif ch in (curses.KEY_UP, ord("k")):
            sel = (sel - 1) % len(options)
        elif ch in (curses.KEY_DOWN, ord("j")):
            sel = (sel + 1) % len(options)
        elif ord("1") <= ch <= ord("9") and ch - ord("1") < len(options):
            sel = ch - ord("1")
        elif ch in (10, 13, curses.KEY_ENTER):
            return sel
        elif ch in (ord("l"), ord("L")):
            session.log_view()
        elif ch in (ord("q"), ord("Q")):
            _quit_confirm(session)


def text_field(session: Session, title: str, prompt: str, initial: str = "",
               hint: str = "Enter accepts . Ctrl-U clears") -> str:
    """One-line visible input, prefilled."""
    return _field(session, title, prompt, initial, mask=False, hint=hint)


def password_field(session: Session, title: str, prompt: str) -> str:
    """One-line masked input: echoes bullets, the value never touches the
    session capture/pane, and there is no paste-guard theater — a paste is
    just a burst of keys."""
    return _field(session, title, prompt, "", mask=True,
                  hint="typing is hidden . Enter accepts . Ctrl-U clears")


def _field(session: Session, title: str, prompt: str, initial: str, *,
           mask: bool, hint: str) -> str:
    assert session.scr is not None
    scr = session.scr
    buf = initial
    title_lines = title.splitlines()
    while True:
        session.check_abort()
        session.clear_body()
        top, bottom, w = session.body_extent()
        max_title = max(1, (bottom - top - 1) - 3)
        shown_title = title_lines[:max_title]
        if len(title_lines) > max_title:
            shown_title[-1] = shown_title[-1][: max(0, w - 14)] + "  [...more]"
        y = top + 1
        for ln in shown_title:
            put(scr, y, 2, ln, curses.A_BOLD)
            y += 1
        y += 1
        shown = ("*" * len(buf)) if mask else buf
        put(scr, y, 2, f"{prompt}: ")
        put(scr, y, 4 + len(prompt), shown + "_", curses.A_REVERSE)
        _keys_hint(session, f" {hint} . Ctrl-C abort")
        session._draw_chrome()
        ch = _read_key(session)
        if isinstance(ch, tuple):        # ("paste", text): append, NEVER submit
            buf += ch[1]
            continue
        if ch == -1 or _swallow_inert(session, ch):
            continue
        if ch == curses.KEY_RESIZE:
            session._on_resize()
        elif ch in (10, 13, curses.KEY_ENTER):
            return buf
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            buf = buf[:-1]
        elif ch == 21:  # Ctrl-U
            buf = ""
        elif 32 <= ch < 127:
            buf += chr(ch)
        # >127: multibyte input is deliberately dropped — passwords and
        # usernames on the target distros are ASCII; accepting locale-
        # dependent bytes into a MASKED field invites unreproducible secrets.
