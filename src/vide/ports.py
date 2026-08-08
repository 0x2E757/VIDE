"""The per-instance loopback port registry: read, allocate under a lock.

The lock is fcntl.flock — the SAME flock(2) family as util-linux flock(1), so a
shell script or an operator taking `flock` on this file contends with VIDE
correctly. (fcntl.lockf is POSIX record locks, a DIFFERENT family: two holders
across the families each believe they own the lock, and two ports get allocated
at once. Do not switch.)
"""
from __future__ import annotations

import fcntl
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import contract, system
from .config import Config
from .errors import StateError
from .executor import Executor
from .reporter import Reporter

_PORT_RE = re.compile(r"^VIDE_PORT=(\d+)", re.M)


def get_port(state_dir: Path, user: str) -> int | None:
    """The persisted port, or None if not recorded."""
    try:
        text = (state_dir / f"{user}.env").read_text()
    except OSError:
        return None
    m = _PORT_RE.search(text)
    return int(m.group(1)) if m else None


def recorded_ports(state_dir: Path) -> set[int]:
    out: set[int] = set()
    for envf in state_dir.glob("*.env"):
        try:
            m = _PORT_RE.search(envf.read_text())
        except OSError:
            continue
        if m:
            out.add(int(m.group(1)))
    return out


def choose_port(used: set[int], base: int, maximum: int) -> int | None:
    """Lowest free candidate, pure. The live-listener check is the caller's."""
    for p in range(base, maximum + 1):
        if p not in used:
            return p
    return None


@contextmanager
def _port_lock(state_dir: Path, timeout: float) -> Iterator[None]:
    # 0600, for the reason sso._sso_lock spells out: flock(2) grants LOCK_EX on
    # a read-only fd, so a laxer mode lets ANY local user wedge every port
    # allocation for the whole timeout. The two locks are the same hazard and
    # must not disagree about it.
    fd = os.open(state_dir / ".portlock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:  # flock(1) has -w; fcntl.flock has no timeout — poll LOCK_NB
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StateError(
                        f"could not acquire lock {state_dir}/.portlock within "
                        f"{timeout:.0f}s") from None
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)  # closing releases the flock


def _fleet_port(cfg: Config) -> set[int]:
    """The shared SSO proxy's port, so the allocator never hands it to an
    instance.

    READ THIS BEFORE CREDITING IT WITH ANYTHING. It is **self-collision hygiene
    and not a security control**, and that stays true even though the port is now
    genuinely reserved. What reserves it is units/oauth2-proxy.socket, which binds
    the address as PID 1 from sockets.target and keeps holding it while the proxy
    is stopped, restarting or crash-looping; nothing in this function contributes
    to that. On a box where that unit is `active (listening)` the OS itself would
    refuse the allocator anyway — `system.listening_ports()` already contains the
    port — so this is belt to that unit's braces, on the boxes that have it.

    On a box that has NOT migrated yet, the old sentence still applies in full:
    any local account can bind 127.0.0.1:<fleet port> the moment oauth2-proxy is
    not holding it, and answer the forward_auth sub-request for every instance on
    the box. A converge installs and enables the socket unit but never restarts
    the gate, so that is every pre-existing box until its first `upgrade-sso`.
    proxy_health reports which side of that line a box is on.

    What this does close is VIDE handing the fleet's own authorization port to an
    instance and breaking authentication for every OTHER instance. At the shipped
    defaults it can never fire — the allocator range is 9797-9996 and the fleet
    port is 4180 — so it exists for the box where VIDE_PORT_BASE / VIDE_PORT_MAX /
    VIDE_SSO_PROXY_PORT have been moved into overlap, which `.env` permits.

    Local import: registry imports ports and sso imports registry, so a
    module-level import here is a live cycle. Catching everything is deliberate
    too — claim_port runs on password-mode boxes with no SSO at all, and
    fleet_port raises on a damaged pin, so an unguarded call would turn a password
    install into a hard failure over a row it never reads. Fail closed on the
    PORT, never on the install.

    And on that failure it reserves NOTHING rather than falling back to
    cfg.sso_proxy_port. Two reasons, and the second is the better one: reading
    that attribute here would make this a second reader of a fleet pin, which the
    I10 census exists to refuse and did refuse when this was first written that
    way — and a damaged pin means the fleet port is not a thing this box knows, so
    excluding a guessed one is worse than excluding none."""
    from . import sso as vide_sso
    try:
        return {vide_sso.fleet_port(cfg)}
    except Exception:
        return set()


def claim_port(cfg: Config, ex: Executor, rep: Reporter, user: str) -> int:
    """Reuse the persisted port if present, else allocate the lowest free port
    >= base under the lock and persist it."""
    existing = get_port(cfg.state_dir, user)
    if existing is not None:
        return existing
    # Value-producer: the caller consumes the return, so a preview must yield
    # something usable; it narrates once and returns the base (bash parity).
    #
    # (see _fleet_port for what its contribution to `used` does and does not buy)
    if ex.narrate(f"would allocate a free loopback port (>={cfg.port_base}) for {user}"):
        return cfg.port_base
    ex.ensure_dir(cfg.state_dir, mode=0o755, owner=("root", "root"))
    with _port_lock(cfg.state_dir, cfg.lock_timeout):
        again = get_port(cfg.state_dir, user)  # re-check under the lock
        if again is not None:
            return again
        used = recorded_ports(cfg.state_dir) | system.listening_ports() | _fleet_port(cfg)
        while True:
            p = choose_port(used, cfg.port_base, cfg.port_max)
            if p is None:
                raise StateError(
                    f"no free loopback port in range {cfg.port_base}-{cfg.port_max}")
            if system.port_free(p):
                ex.atomic_write(cfg.state_dir / f"{user}.env",
                                contract.PORT_RECORD.format(port=p),
                                mode=0o644, owner=("root", "root"))
                return p
            used.add(p)
