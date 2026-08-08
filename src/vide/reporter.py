"""Logging: always stderr; stdout is reserved for machine-readable output.

One emitter, one shape: level tag
padded ('INFO ' and 'WARN ' carry a trailing space; 'ERROR'/'DEBUG' do not),
ANSI color only when stderr is a tty and NO_COLOR is unset/empty. Color wraps
ONLY the level tag — a code bleeding into the message would corrupt the
arbiter's `sed 's/.*): //p'` password capture.
"""
from __future__ import annotations

import os
import sys
from typing import TextIO


class Reporter:
    def __init__(self, *, debug: bool = False, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._debug_on = debug
        # bash: [[ -t 2 && -z ${NO_COLOR:-} ]] — empty NO_COLOR counts as unset.
        try:
            isatty = self._stream.isatty()
        except (AttributeError, ValueError):
            isatty = False
        self._color = isatty and not os.environ.get("NO_COLOR")

    def _log(self, level: str, color: str, msg: str) -> None:
        line = f"\033[{color}m{level}\033[0m {msg}" if self._color else f"{level} {msg}"
        # flush per line: subprocess output interleaves on the same fd.
        print(line, file=self._stream, flush=True)

    def info(self, msg: str) -> None:
        self._log("INFO ", "0;34", msg)

    def warn(self, msg: str) -> None:
        self._log("WARN ", "1;33", msg)

    def err(self, msg: str) -> None:
        self._log("ERROR", "1;31", msg)

    def debug(self, msg: str) -> None:
        if self._debug_on:
            self._log("DEBUG", "0;90", msg)

    def banner(self, text: str) -> None:
        """A verbatim multi-line block to stderr (the exposure/root banners)."""
        print(text, file=self._stream, flush=True)
