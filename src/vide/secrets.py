"""All secret generation/hashing.

Threat context: behind a
loopback reverse proxy code-server sees every request as 127.0.0.1, so its
built-in brute-force limiter is blind — password ENTROPY is the only auth
control VIDE itself owns. And code-server's stored `hashed-password` value
doubles as a replayable session cookie (coder/code-server#7696), so
config.yaml is secret-equivalent to a live bearer token: 0600, per-instance
cookie-suffix, and `vide rotate` as the only revocation.

The module name cannot shadow stdlib `secrets` — but ONLY because __main__.py
scrubs the package dir off sys.path before importing anything (direct-file
execution puts it there, and `import secrets` would then find THIS file as a
top-level module). That scrub is load-bearing; a unit test pins it.
"""
from __future__ import annotations

import base64
import secrets as _stdlib_secrets
from pathlib import Path

from . import contract, system
from .config import Config
from .errors import ConfigError, SoftwareError, StateError
from .executor import Executor
from .reporter import Reporter
from . import ports


def gen_password() -> str:
    """128-bit random password (16 bytes, base64 — same shape as
    `openssl rand -base64 16`). 128 bits keeps online guessing infeasible even
    with the throttle blind. Never persisted in plaintext."""
    return base64.b64encode(_stdlib_secrets.token_bytes(16)).decode()


def gen_cookie_secret() -> str:
    """The oauth2-proxy cookie secret: 32 random bytes as URL-safe base64
    WITHOUT padding (43 chars). This is the one encoding rotation can never get
    wrong. oauth2-proxy's SecretBytes tries base64.RawURLEncoding.DecodeString
    first and uses the decoded bytes iff the length is 16/24/32 — a 43-char
    url-safe no-pad string ALWAYS decodes to exactly 32 bytes, so it
    deterministically becomes an AES-256 key. The rejected alternatives both
    fail silently: raw 32 bytes can hold NUL/newline/quote bytes an env-file
    round-trip corrupts, and a raw 32-CHAR base64 string decodes to 24 bytes
    (still a valid length) and is reinterpreted as a different key. A failed
    proxy restart after rotation is a fleet-wide outage, so this determinism is
    load-bearing, not cosmetic."""
    return base64.urlsafe_b64encode(_stdlib_secrets.token_bytes(32)).decode().rstrip("=")


def hash_password(plaintext: str) -> str:
    """argon2id encoded hash string code-server stores verbatim. Uses the
    Debian `argon2` binary (offline apt dep). Plaintext is piped via STDIN,
    never passed as argv (which shows in /proc); the random salt is not secret
    and rides argv as bash did."""
    salt = _stdlib_secrets.token_bytes(16).hex()  # 128-bit salt
    out = system.query(["argon2", salt, "-id", "-e"], input_text=plaintext)
    if out.returncode != 0 or not out.stdout.strip():
        raise SoftwareError("argon2 hashing failed")
    return out.stdout.strip()


def gen_cookie_suffix(user: str) -> str:
    """Distinct cookie namespace per instance so a hash/cookie leaked from one
    instance can't be replayed against a sibling subdomain. Random tail removes
    name-guessability."""
    return contract.COOKIE_SUFFIX.format(user=user, rand=_stdlib_secrets.token_bytes(6).hex())


def _config_paths(cfg: Config, ex: Executor, user: str) -> tuple[Path, Path]:
    home = system.user_home(user)
    if home is None:
        # A preview of a not-yet-created user has no home to resolve.
        if ex.dry_run:
            home = Path(f"/home/{user}")
        else:
            raise ConfigError(f"cannot resolve home for user '{user}'")
    cfgdir = home / ".config/code-server"
    return cfgdir, cfgdir / "config.yaml"


def _write_config(ex: Executor, user: str, cfgdir: Path, cfg_path: Path, port: int,
                  password: str | None = None) -> str:
    """The SINGLE config.yaml emitter, shared by ensure_config (fresh) and
    rotate_config (regenerate), so a new field can never be added to one path
    and forgotten on the other. Returns the one-time plaintext for the caller
    to announce. `password` carries an operator-supplied plaintext (wizard
    typed / --password-stdin); None means generate — the default and the only
    path the arbiter ever sees.

    Reached ONLY on a real-run mutation path: both callers narrate-return
    under dry-run — and ensure_config evaluates its never-regenerate guard —
    BEFORE calling here."""
    ex.ensure_dir_as_user(user, cfgdir, mode=0o700)
    pw = password if password is not None else gen_password()
    hashed = hash_password(pw)
    suffix = gen_cookie_suffix(user)
    content = (
        f"bind-addr: 127.0.0.1:{port}\n"
        "auth: password\n"
        f'hashed-password: "{hashed}"\n'
        f"cookie-suffix: {suffix}\n"
        "cert: false\n"
    )
    ex.write_as_user(user, cfg_path, content, mode=0o600)
    return pw


def config_provisioned(cfg: Config, ex: Executor, user: str) -> bool:
    """The never-regenerate guard, shared with the install sequencer (which
    must know whether a password question even applies BEFORE asking it).
    Observe-family probes always run (missing user/file probes False), so no
    dry-run tag is needed — the data-branch speaks for itself."""
    _, cfg_path = _config_paths(cfg, ex, user)
    return (system.probe_as(user, ["test", "-f", str(cfg_path)])
            and system.probe_as(user, ["grep", "-q", "^hashed-password:", str(cfg_path)]))


def has_password_config(cfg: Config, user: str) -> bool:
    """Total, Executor-free twin of config_provisioned for the resolve phase,
    which is structurally denied an Executor. Answers the one thing the password
    question needs: does this user's config.yaml already carry a hashed-password?
    A user who does not exist yet (the 'vide' fallback is created in APPLY, after
    this question is resolved) has no home and therefore no config -> False (ask).
    Never raises: an unresolvable home is 'no config', not an error. Semantics
    are identical to config_provisioned on every reachable path."""
    home = system.user_home(user)
    if home is None:
        return False
    cfg_path = home / ".config/code-server/config.yaml"
    return (system.probe_as(user, ["test", "-f", str(cfg_path)])
            and system.probe_as(user, ["grep", "-q", "^hashed-password:", str(cfg_path)]))


def ensure_config(cfg: Config, ex: Executor, rep: Reporter, user: str, port: int,
                  password: str | None = None) -> str | None:
    """Write config.yaml as the user, 0600, with a freshly generated (or
    operator-supplied) password (hashed) and cookie-suffix. Guarded: if a
    hashed-password already exists, do nothing — NEVER silently rotate a saved
    credential. The only path that regenerates is `vide rotate`.

    Returns the plaintext when one was GENERATED, None otherwise (kept
    existing, dry-run, or operator-supplied — the operator already knows
    theirs). The CALLER announces it: the SHOWN-ONCE line must not originate
    here because in wizard mode the Reporter stream is a buffered log pane —
    a password routed through it would be painted on screen mid-run and
    replayed later. Presentation owns presentation."""
    cfgdir, cfg_path = _config_paths(cfg, ex, user)
    if config_provisioned(cfg, ex, user):
        rep.info(f"config for '{user}' already provisioned; keeping existing "
                 f"password (regenerate with: vide rotate {user})")
        return None
    # Secret path: a preview must not generate a real credential (which it
    # would then print but never install).
    if ex.narrate(f"generate 128-bit password + argon2id hash + cookie-suffix; "
                  f"write {cfg_path} (0600, owner {user}); bind 127.0.0.1:{port}"):
        return None
    pw = _write_config(ex, user, cfgdir, cfg_path, port, password)
    return None if password is not None else pw


def sso_config_provisioned(cfg: Config, ex: Executor, user: str) -> bool:
    """The SSO never-regenerate guard: a config.yaml exists with `auth: none`."""
    _, cfg_path = _config_paths(cfg, ex, user)
    return (system.probe_as(user, ["test", "-f", str(cfg_path)])
            and system.probe_as(user, ["grep", "-q", "^auth: none", str(cfg_path)]))


def ensure_sso_config(cfg: Config, ex: Executor, rep: Reporter, user: str) -> None:
    """The socket-mode config.yaml: `auth: none` (the unix socket's perms ARE
    the authz policy — spike Q1) and no password/cookie material at all. The
    binding is carried by the launcher flags (--socket), not config.yaml, so
    /etc/vide/<user>.env stays the single binding authority. Idempotent."""
    cfgdir, cfg_path = _config_paths(cfg, ex, user)
    if sso_config_provisioned(cfg, ex, user):
        rep.info(f"sso config for '{user}' already provisioned; keeping it")
        return
    if ex.narrate(f"write {cfg_path} (0600, owner {user}): auth: none, unix socket"):
        return
    ex.ensure_dir_as_user(user, cfgdir, mode=0o700)
    ex.write_as_user(user, cfg_path, "auth: none\ncert: false\n", mode=0o600)


def rotate_config(cfg: Config, ex: Executor, rep: Reporter, user: str) -> str | None:
    """The kill switch: regenerate password + hash + cookie-suffix, rewrite the
    config preserving the port, and (caller) restart the unit. The ONLY
    sanctioned break from never-regenerate. Returns the new plaintext (None
    under dry-run); the caller announces it — same reasoning as
    ensure_config."""
    cfgdir, cfg_path = _config_paths(cfg, ex, user)
    port = ports.get_port(cfg.state_dir, user)
    if port is None:
        raise StateError(f"no recorded port for '{user}'; is it a VIDE instance?")
    if ex.narrate(f"rotate password + cookie-suffix for '{user}', rewrite "
                  f"{cfg_path} (0600), restart unit"):
        return None
    return _write_config(ex, user, cfgdir, cfg_path, port)
