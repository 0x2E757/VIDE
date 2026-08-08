"""The instance registry is DERIVED FROM THE SYSTEM (unit files + /etc/vide),
never from the repo — which is exactly what lets bash and Python manage the
same box interchangeably and makes rollback a symlink flip, not a migration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import contract, ports, system
from .config import Config

# `(.+)` — at least one character — NOT `(.*)`. The glob 'code-server@*.service'
# also matches the bare TEMPLATE unit `code-server@.service`, whose instance
# part is empty; `.*` captured that and emitted an empty line, which sorted
# FIRST and made doctor's firstuser empty — silently skipping the user-view
# traversal check, doctor's whole reason to exist. Regression-pinned.
_UNIT_RE = re.compile(r"^code-server@(.+)\.service$")


def list_instances(cfg: Config) -> list[str]:
    found: set[str] = set()
    for argv in (["systemctl", "list-unit-files", "code-server@*.service", "--no-legend"],
                 ["systemctl", "list-units", "--all", "code-server@*.service", "--no-legend"]):
        out = system.query(argv)
        if out.returncode != 0:
            continue
        for line in out.stdout.splitlines():
            cols = line.split()
            if not cols:
                continue
            # list-units decorates failed units with a leading ● glyph.
            name = cols[1] if cols[0] in ("●", "*", "x") and len(cols) > 1 else cols[0]
            m = _UNIT_RE.match(name)
            if m:
                found.add(m.group(1))
    for envf in Path(cfg.state_dir).glob("*.env"):
        found.add(envf.stem)
    return sorted(found)


def instance_active(user: str) -> bool:
    return system.query(["systemctl", "is-active", "--quiet",
                         f"code-server@{user}.service"]).returncode == 0


def instance_port(cfg: Config, user: str) -> str:
    p = ports.get_port(cfg.state_dir, user)
    return str(p) if p is not None else "?"


@dataclass(frozen=True, slots=True)
class Binding:
    """How an instance is reachable: a loopback TCP port (password mode) or a
    unix socket (sso mode). Replaces the bare 'port or ?' so every consumer
    (ls/status/info/health/probe/snippet) dispatches on mode without re-parsing
    <user>.env. The tcp branch of every consumer must reproduce today's bytes —
    that is the frozen-arbiter no-diff proof."""

    kind: str                       # "tcp" | "unix" | "unknown"
    port: int | None = None
    socket: Path | None = None

    @classmethod
    def tcp(cls, port: int) -> "Binding":
        return cls("tcp", port=port)

    @classmethod
    def unix(cls, sock: Path) -> "Binding":
        return cls("unix", socket=sock)

    @classmethod
    def unknown(cls) -> "Binding":
        return cls("unknown")

    @property
    def display(self) -> str:
        """The `ls` PORT-column token. Digits for tcp (byte-identical to today),
        a distinct greppable token for a socket, '?' only for a torn record."""
        if self.kind == "tcp" and self.port is not None:
            return str(self.port)
        if self.kind == "unix":
            return contract.LS_BIND_SOCKET
        return "?"


def instance_mode(cfg: Config, user: str) -> str | None:
    """None if there is no record; 'sso' iff VIDE_MODE=sso; else 'password'.
    ABSENCE of VIDE_MODE = password, so every record written before this slice
    stays valid unmodified."""
    from .config import parse_env_file
    envf = Path(cfg.state_dir) / f"{user}.env"
    if not envf.exists():
        return None
    return "sso" if parse_env_file(envf).get("VIDE_MODE") == "sso" else "password"


def instance_binding(cfg: Config, user: str) -> Binding:
    from .config import parse_env_file
    envf = Path(cfg.state_dir) / f"{user}.env"
    rec = parse_env_file(envf) if envf.exists() else {}
    if rec.get("VIDE_MODE") == "sso":
        sock = rec.get("VIDE_SOCKET") or str(system.socket_path(user))
        return Binding.unix(Path(sock))
    p = ports.get_port(cfg.state_dir, user)
    return Binding.tcp(p) if p is not None else Binding.unknown()


def instance_version(user: str) -> str:
    home = system.user_home(user)
    if home is None:
        return "?"
    binpath = home / ".local/bin/code-server"
    if not system.probe_as(user, ["test", "-x", str(binpath)]):
        return "?"
    out = system.query_as(user, [str(binpath), "--version"])
    if out.returncode != 0 or not out.stdout:
        return "?"
    first = out.stdout.splitlines()[0].split()
    return first[0] if first else "?"


def instance_health(cfg: Config, user: str) -> bool | None:
    """True healthy, False unhealthy, **None when it cannot be observed**.

    The third state is not tidiness. The socket's directory is root-owned by
    design (see the freeze in units/code-server@.service), so a non-root caller
    gets EACCES and `socket_stat` maps that to None — indistinguishable from
    "the socket is gone" unless somebody says which. `vide status` is documented
    as runnable without sudo, so collapsing the two made a perfectly healthy SSO
    instance report `unreachable` to every non-root operator. It is narrowed to
    exactly the case that cannot be seen: a stat that succeeds still answers, so
    nothing else changes."""
    b = instance_binding(cfg, user)
    if b.kind == "tcp" and b.port is not None:
        return system.healthz(b.port)
    if b.kind == "unix" and b.socket is not None:
        # The socket must both answer AND carry the authz-policy perms — root's
        # HTTP probe bypasses 0660, so the stat is the caddy-can-connect check.
        st = system.socket_stat(b.socket)
        if st is None and not system.is_root():
            return None
        if st is None or not st.is_socket or st.mode != 0o660:
            return False
        return system.healthz_unix(str(b.socket))
    return False
