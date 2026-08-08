"""Target-user resolution, dedicated-user creation, login password, sudoers."""
from __future__ import annotations

from pathlib import Path

from . import secrets as vsecrets, system
from .config import Config
from .errors import ConfigError
from .executor import Executor
from .reporter import Reporter


def resolve_target_user(vide_user: str, sudo_user: str, euid: int,
                        allow_root: bool, current_user: str) -> str:
    """Precedence: VIDE_USER > sudo-invoking non-root user > (root -> fallback
    'vide' unless VIDE_ALLOW_ROOT=1) > current non-root user. Pure."""
    if vide_user:
        return vide_user
    if sudo_user and sudo_user != "root":
        return sudo_user
    if euid == 0:
        return "root" if allow_root else "vide"
    return current_user


def is_root_fallback(vide_user: str, sudo_user: str, euid: int, allow_root: bool) -> bool:
    """True when we silently fell back to 'vide' from a bare root invocation
    (used to print the explanatory warning)."""
    return not vide_user and not allow_root and euid == 0 and not sudo_user


def ensure_user(ex: Executor, rep: Reporter, user: str) -> None:
    """Create the dedicated account if missing (real home, bash shell so the
    IDE terminal works, sudo group). Idempotent."""
    if system.user_exists(user):
        rep.debug(f"user '{user}' already exists")
        return
    rep.info(f"creating dedicated user '{user}' (home, /bin/bash, sudo group)")
    ex.run(["useradd", "-m", "-s", "/bin/bash", "-G", "sudo", user])


def set_user_password(cfg: Config, ex: Executor, rep: Reporter, user: str) -> str | None:
    """Generate & set a login password so "sudo WITH password" can actually
    authenticate (a fresh useradd account is locked, '!'). Marker-guarded so a
    re-run never rotates a saved credential. Returns the plaintext for the
    CALLER to announce (None when kept/previewed) — the SHOWN-ONCE line must
    not originate here: in wizard mode the Reporter stream is the on-screen
    log pane, and a secret through it would be displayed mid-run and replayed
    later."""
    marker = Path(cfg.state_dir) / f"{user}.pwset"
    if marker.is_file():
        rep.debug(f"login password for '{user}' already provisioned")
        return None
    # Secret path: a preview must not generate/print a real credential.
    if ex.narrate(f"generate login password for '{user}', set via chpasswd, print "
                  "once (only an empty marker is stored, never the plaintext)"):
        return None
    pw = vsecrets.gen_password()
    # stdin-fed, never argv: /proc/<pid>/cmdline is world-readable.
    ex.run(["chpasswd"], input_text=f"{user}:{pw}\n")
    ex.ensure_dir(cfg.state_dir, mode=0o755, owner=("root", "root"))
    # Store ONLY a marker, never the plaintext: /etc/shadow already holds the
    # hash, and keeping the login/sudo password in cleartext at rest is a
    # needless risk.
    ex.atomic_write(marker, "", mode=0o600, owner=("root", "root"))
    return pw


def install_sudoers(ex: Executor, rep: Reporter, user: str) -> None:
    """timestamp_timeout=0 so a hijacked live session can't reuse a warm sudo
    timestamp. Validated with visudo BEFORE activation — a malformed sudoers
    file can lock sudo box-wide."""
    dropin = f"/etc/sudoers.d/vide-{user}"
    content = f"Defaults:{user} timestamp_timeout=0\n"
    visudo = system.visudo_cmd()
    if visudo is None:
        # The sequencer installs the sudo package before this step; standalone
        # honesty still needs both halves: a preview proceeds (a real run
        # installs sudo first), a real run fails NAMING the actual cause —
        # the old copy blamed "validation" when the binary did not exist.
        if not ex.narrate(f"validate sudoers drop-in for '{user}' with visudo "
                          "(not present in this preview; a real run installs "
                          "the 'sudo' package first)"):
            raise ConfigError("visudo not found — the 'sudo' package is required "
                              f"for the dedicated '{user}' user's password-sudo")
    else:
        # visudo -cf is read-only VALIDATION, so it runs in dry-run too — a
        # preview that skipped it could not tell you the drop-in is malformed.
        # Validate via stdin (`visudo -cf -`), which keeps this observe-only.
        check = system.query([visudo, "-cf", "-"], input_text=content)
        if check.returncode != 0:
            detail = (check.stderr or check.stdout).strip() or "no output"
            raise ConfigError(f"generated sudoers drop-in for '{user}' failed "
                              f"visudo validation (rc {check.returncode}): {detail}")
    ex.atomic_write(Path(dropin), content, mode=0o440, owner=("root", "root"))
