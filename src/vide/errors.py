"""Exit codes + the exception hierarchy.

The codes are modelled on sysexits.h and are EXTERNAL CONTRACT: the arbiter
asserts 64 on the destructive-verb guards and 69 from `doctor --quiet`; the
README documents the full table. Values may never change.
"""
from __future__ import annotations

import enum


class Ex(enum.IntEnum):
    USAGE = 64        # bad invocation / missing required arg
    DATAERR = 65      # bad input data (reserved; no code path emits it today)
    UNAVAILABLE = 69  # a required service/dependency is unavailable
    SOFTWARE = 70     # internal error
    STATE = 75        # host state problem (lock, no free port, ...)
    NOPERM = 77       # needs privilege it does not have
    CONFIG = 78       # misconfiguration (unsupported OS, bad sudoers, ...)


class VideError(Exception):
    """The `die` of the bash implementation: message to stderr, exit with code."""

    code: Ex = Ex.SOFTWARE

    def __init__(self, message: str) -> None:
        super().__init__(message)


class UsageError(VideError):
    code = Ex.USAGE


class UnavailableError(VideError):
    code = Ex.UNAVAILABLE


class SoftwareError(VideError):
    code = Ex.SOFTWARE


class StateError(VideError):
    code = Ex.STATE


class NoPermError(VideError):
    code = Ex.NOPERM


class ConfigError(VideError):
    code = Ex.CONFIG


class CommandFailed(Exception):
    """A mutating child exited non-zero. bash's `set -e` exits with the FAILING
    COMMAND'S status (e.g. apt's), not a sysexit — the top-level handler exits
    with `returncode` to preserve that."""

    def __init__(self, argv: tuple[str, ...], returncode: int) -> None:
        self.argv = argv
        self.returncode = returncode
        super().__init__(f"command failed (rc={returncode}): {' '.join(argv)}")
