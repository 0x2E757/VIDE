"""Per-user standalone code-server install & explicit upgrade.

Install and upgrade are DECOUPLED: a normal install never chases "latest" for
an already-installed user, so adding user B never restarts user A's session.
`vide upgrade` is the explicit lever, and only that unit is restarted (by the
caller).
"""
from __future__ import annotations

from pathlib import Path

from .config import Config
from .errors import StateError
from .executor import Executor
from .reporter import Reporter
from . import branding, net, system


def _home(user: str) -> Path:
    home = system.user_home(user)
    if home is None:
        # Missing-user placeholder. Installs only reach it on a dry run (a real
        # install died earlier at the missing-user gate); `vide upgrade` has no
        # such gate and instead fails just below at the no-install probe.
        return Path(f"/home/{user}")
    return home


def code_server_version(cfg: Config, ex: Executor) -> str:
    """The version to install. Precedence: explicit pin wins; else opt-in
    resolve-and-pin latest; else empty (installer picks latest itself). A
    preview must not reach the network."""
    if cfg.code_server_version:
        return cfg.code_server_version
    if not cfg.code_server_pin_latest:
        return ""
    if ex.dry_run:
        return ""
    return net.resolve_latest_version(cfg)


def ensure_code_server(cfg: Config, ex: Executor, rep: Reporter, user: str) -> str:
    """Install standalone under ~<user>/.local IF absent; if already installed,
    leave the version untouched (use `vide upgrade`). The presence probe is an
    observe — it always runs, and MainPID stability across converges depends
    on it short-circuiting here.

    Returns a display string for the summary — what the flow already knows,
    deliberately NOT a `code-server --version` spawn (a ~1s node startup on
    every converge just to decorate a no-op finish would be theater)."""
    home = _home(user)
    if system.probe_as(user, ["test", "-x", str(home / ".local/bin/code-server")]):
        rep.info(f"code-server already installed for '{user}' — leaving version "
                 f"as-is (use 'vide upgrade {user}' to bump)")
        return "existing (unchanged)"
    ver = code_server_version(cfg, ex)
    rep.info(f"installing code-server (standalone{f', version {ver}' if ver else ''}, "
             f"else latest) for '{user}'")
    _install_code_server(cfg, ex, rep, user, home, ver)
    return ver or "latest"


def _install_code_server(cfg: Config, ex: Executor, rep: Reporter, user: str,
                         home: Path, ver: str) -> None:
    args = ["--method", "standalone"]
    if ver:
        args += ["--version", ver]
    # Runs AS the target user from a user-readable temp (the executor chmods
    # the downloaded script 0644 — root's 0600 mktemp is unreadable by the
    # target user, the shipped EACCES bug), with env HOME=<their home>.
    ex.run_setup_script(cfg.code_server_installer_url, "VIDE_CODE_SERVER_INSTALLER_URL",
                        ["sh"], args=args, as_user=user, home=str(home))
    # THE choke point for anything that patches the vendored tree: an upgrade
    # replaces that tree wholesale, and this is the one function both install
    # and upgrade go through. Branding lives here so it cannot be silently
    # reverted by the next `vide upgrade`. It is best-effort inside — see
    # branding.apply — so a failure here never fails an install.
    branding.apply(ex, rep, user)
    branding.seed_user_settings(ex, rep, user)


def upgrade_code_server(cfg: Config, ex: Executor, rep: Reporter, user: str) -> None:
    """The explicit, decoupled upgrade lever. Reinstalls latest for ONE user;
    the caller restarts only that unit."""
    home = _home(user)
    if not ex.dry_run and not system.probe_as(
            user, ["test", "-x", str(home / ".local/bin/code-server")]):
        raise StateError(f"'{user}' has no code-server install to upgrade")
    rep.warn(f"upgrading code-server for '{user}' to latest — this WILL restart "
             "the instance and drop its live session")
    _install_code_server(cfg, ex, rep, user, home, code_server_version(cfg, ex))
