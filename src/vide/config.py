"""The Setting schema: ONE source for defaults, `.env`, and (later) --help.

Precedence: argv > process env > `.env` > default, with EMPTY values falling
through to the next source (bash `: "${VIDE_X:=default}"` treats empty as
unset, and `VIDE_USER=` behaves as unset via `[[ -n ]]`).

DIVERGENCE from bash, documented: bash `set -a; . .env` OVERWROTE the process
environment, so `.env` accidentally beat env. That order was an artifact of the
sourcing mechanism, not a promise (nothing pinned it); per-invocation intent
beating persisted state is the fail-safer direction and the dotenv convention.

The parser is KEY=VALUE only — no shell expansion ($VAR, $(cmd) stay literal).
An operator `.env` relying on expansion breaks; documented in the README.

STRUCTURALLY ABSENT, forever: any row for --yes or any "assume yes"-style
confirm waiver. `.env` is config; control levers are argv-only. VIDE_CONFIRM_ROOT is read
from PROCESS ENV ONLY by the Confirmer — never from `.env` (stricter than
bash's accidental set -a behavior; fail-closed direction; also documented).
tests/unit/test_invariants.py pins both facts.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .errors import ConfigError


@dataclass(frozen=True, slots=True)
class Setting:
    field: str
    env: str
    default: str
    cast: Callable[[str], Any]
    doc: str


SCHEMA: tuple[Setting, ...] = (
    Setting("state_dir", "VIDE_STATE_DIR", "/etc/vide", Path,
            "root-owned per-instance state (<user>.env, <user>.pwset)"),
    Setting("port_base", "VIDE_PORT_BASE", "9797", int, "first loopback port to try"),
    Setting("port_max", "VIDE_PORT_MAX", "9996", int, "last loopback port to try"),
    Setting("nvm_version", "VIDE_NVM_VERSION", "v0.40.5", str, "pinned nvm installer tag"),
    Setting("nvm_dir", "VIDE_NVM_DIR", "/opt/nvm", Path,
            "world-traversable (NOT /root/.nvm — 0700 blocks other users)"),
    Setting("pnpm_home", "VIDE_PNPM_HOME", "/opt/pnpm", Path, "world-traversable pnpm home"),
    Setting("bin_dir", "VIDE_BIN_DIR", "/usr/local/bin", Path,
            "global bin dir for the node/npm/npx/pnpm symlinks"),
    Setting("node_major", "VIDE_NODE_MAJOR", "26", int, "minimum Node.js major for the workspace"),
    Setting("launcher", "VIDE_LAUNCHER", "/usr/local/lib/vide/code-server-launch", Path,
            "installed launcher wrapper path"),
    Setting("unit_path", "VIDE_UNIT_PATH", "/etc/systemd/system/code-server@.service", Path,
            "installed template unit path"),
    Setting("cli_link", "VIDE_CLI_LINK", "/usr/local/bin/vide", Path, "global CLI symlink"),
    Setting("lock_timeout", "VIDE_LOCK_TIMEOUT", "10", float, "seconds to wait for the port lock"),
    Setting("dry_run", "VIDE_DRY_RUN", "0", lambda v: v == "1",
            "1 = preview only, mutate nothing (fail-safe lever: env-settable)"),
    Setting("debug", "VIDE_DEBUG", "0", lambda v: v == "1",
            "1 = emit debug logs (fail-safe lever: env-settable)"),
    # Upstream installer URLs — overridable so a future URL move is a one-line
    # env fix (the ONLY breakage accepted over time), not a code edit. The nvm
    # URL default interpolates the RESOLVED nvm_version — see load_config.
    Setting("nvm_installer_url", "VIDE_NVM_INSTALLER_URL", "", str,
            "override when nvm's install.sh moves (default derives from nvm_version)"),
    Setting("pnpm_installer_url", "VIDE_PNPM_INSTALLER_URL",
            "https://get.pnpm.io/install.sh", str, "override when pnpm's installer moves"),
    Setting("code_server_installer_url", "VIDE_CODE_SERVER_INSTALLER_URL",
            "https://code-server.dev/install.sh", str, "override when code-server's installer moves"),
    Setting("code_server_version", "VIDE_CODE_SERVER_VERSION", "", str,
            "pin a specific code-server version (empty = latest)"),
    Setting("code_server_pin_latest", "VIDE_CODE_SERVER_PIN_LATEST", "0", lambda v: v == "1",
            "1 = resolve the current latest tag at install time and pin THAT"),
    Setting("code_server_releases_latest_url", "VIDE_CODE_SERVER_RELEASES_LATEST_URL",
            "https://github.com/coder/code-server/releases/latest", str,
            "the /releases/latest redirect used to resolve the latest tag"),
    Setting("dl_retries", "VIDE_DL_RETRIES", "3", int, "download attempts on transient faults"),
    Setting("dl_retry_delay", "VIDE_DL_RETRY_DELAY", "2", float, "base backoff seconds (linear)"),
    Setting("dl_connect_timeout", "VIDE_DL_CONNECT_TIMEOUT", "10", float,
            "per-attempt connect ceiling (seconds)"),
    Setting("dl_max_time", "VIDE_DL_MAX_TIME", "300", float, "per-attempt total ceiling (seconds)"),
    Setting("pnpm_profile", "VIDE_PNPM_PROFILE", "/etc/profile.d/vide-pnpm.sh", Path,
            "login-shell drop-in for the per-user pnpm global home"),
    Setting("pnpm_global_subdir", "VIDE_PNPM_GLOBAL_SUBDIR", ".local/share/pnpm", str,
            "per-user pnpm global home, relative to $HOME"),
    Setting("vide_user", "VIDE_USER", "", str, "explicit target OS user for this run"),
    Setting("fqdn", "VIDE_FQDN", "", str,
            "public FQDN for the Caddy snippet + transport probe"),
    Setting("allow_root", "VIDE_ALLOW_ROOT", "0", lambda v: v == "1",
            "1 = deliberately run a ROOT instance instead of the 'vide' fallback"),
    Setting("os_release_file", "VIDE_OS_RELEASE_FILE", "/etc/os-release", Path,
            "test seam for the distro gate"),
    Setting("uname_m", "VIDE_UNAME_M", "", str, "test seam for the arch gate"),
    Setting("toolchain_force", "VIDE_TOOLCHAIN_FORCE", "0", lambda v: v == "1",
            "1 = wipe + reinstall the shared toolchain (vide toolchain --force)"),
    # --- SSO (slice 2) ------------------------------------------------------
    # Auth mode is instance configuration that outlives the invocation (it is
    # persisted in the registry record), same category as VIDE_USER/VIDE_FQDN —
    # so it IS a Setting, not an argv-only control lever. Empty = the wizard
    # asks; the plain/arbiter default is password (byte-identical to today).
    # Converges are protected from a stale .env by the immutability StateError.
    Setting("auth", "VIDE_AUTH", "", str, "auth mode: 'password' | 'sso' (empty = ask/default password)"),
    Setting("sso_dir", "VIDE_SSO_DIR", "/etc/vide/sso", Path,
            "fleet-scoped SSO state home (proxy.env/toml, allowlists, caddy bodies)"),
    Setting("sso_parent_domain", "VIDE_SSO_PARENT_DOMAIN", "", str,
            "the shared *.domain the SSO cookie/redirect cover (persisted at first SSO install)"),
    Setting("sso_proxy_port", "VIDE_SSO_PROXY_PORT", "4180", int,
            "loopback port for the shared oauth2-proxy (outside the instance allocator range)"),
    Setting("sso_issuer_url", "VIDE_SSO_ISSUER_URL", "https://accounts.google.com", str,
            "OIDC issuer (override doubles as the fake-IdP test seam)"),
    Setting("oauth2_proxy_dir", "VIDE_OAUTH2_PROXY_DIR", "/opt/vide/oauth2-proxy", Path,
            "versioned oauth2-proxy binary dirs + the 'current' symlink live here"),
    Setting("oauth2_proxy_version", "VIDE_OAUTH2_PROXY_VERSION", "", str,
            "pin a specific oauth2-proxy version (empty = resolve latest at install)"),
    Setting("oauth2_proxy_releases_latest_url", "VIDE_OAUTH2_PROXY_RELEASES_LATEST_URL",
            "https://github.com/oauth2-proxy/oauth2-proxy/releases/latest", str,
            "the /releases/latest redirect used to resolve + warn-on-staleness"),
    Setting("oauth2_proxy_download_base", "VIDE_OAUTH2_PROXY_DOWNLOAD_BASE",
            "https://github.com/oauth2-proxy/oauth2-proxy/releases/download", str,
            "override when the release download layout moves"),
)

_FIELDS = tuple(s.field for s in SCHEMA)


class Config:
    """Resolved settings. Immutable (slots + a raising __setattr__); values are
    created once in __init__ from the schema — there is deliberately no `yes`
    attribute for anything to read.

    The annotation block below declares TYPES ONLY, for static checkers: the
    schema stays the single source of values, docs and env names, and
    tests/unit/test_config.py pins annotations == schema fields so the two
    cannot drift. (Bare annotations create no class attributes, so they
    coexist with __slots__.)"""

    state_dir: Path
    port_base: int
    port_max: int
    nvm_version: str
    nvm_dir: Path
    pnpm_home: Path
    bin_dir: Path
    node_major: int
    launcher: Path
    unit_path: Path
    cli_link: Path
    lock_timeout: float
    dry_run: bool
    debug: bool
    nvm_installer_url: str
    pnpm_installer_url: str
    code_server_installer_url: str
    code_server_version: str
    code_server_pin_latest: bool
    code_server_releases_latest_url: str
    dl_retries: int
    dl_retry_delay: float
    dl_connect_timeout: float
    dl_max_time: float
    pnpm_profile: Path
    pnpm_global_subdir: str
    vide_user: str
    fqdn: str
    allow_root: bool
    os_release_file: Path
    uname_m: str
    toolchain_force: bool
    auth: str
    sso_dir: Path
    sso_parent_domain: str
    sso_proxy_port: int
    sso_issuer_url: str
    oauth2_proxy_dir: Path
    oauth2_proxy_version: str
    oauth2_proxy_releases_latest_url: str
    oauth2_proxy_download_base: str
    repo_dir: Path

    __slots__ = _FIELDS + ("repo_dir",)

    def __init__(self, values: Mapping[str, Any], repo_dir: Path) -> None:
        for f in _FIELDS:
            object.__setattr__(self, f, values[f])
        object.__setattr__(self, "repo_dir", repo_dir)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Config is immutable")


def parse_env_text(text: str) -> dict[str, str]:
    """KEY=VALUE lines; tolerates `export ` prefixes, surrounding quotes,
    comments and blanks. NOT a shell: nothing expands. Malformed lines are
    silently skipped — the tolerant reader for `.env` and the at-rest
    EnvironmentFiles. The STRICT stdin reader (--sso-secrets-stdin) is a
    separate, refusing parser and must not delegate here."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if key:
            out[key] = val
    return out


def parse_env_file(path: Path) -> dict[str, str]:
    """parse_env_text over a file; missing/unreadable file → {}."""
    try:
        return parse_env_text(path.read_text())
    except OSError:
        return {}


def load_config(repo_dir: Path,
                argv_env: Mapping[str, str] | None = None,
                environ: Mapping[str, str] | None = None) -> Config:
    env = dict(os.environ if environ is None else environ)  # pre-injection snapshot
    dotenv = parse_env_file(repo_dir / ".env")

    # Children must still inherit .env-provided vars (bash exported them via
    # set -a; e.g. an operator's https_proxy in .env must reach urllib and the
    # upstream installers). Inject ONLY where the real environment doesn't
    # already have the key, preserving env > .env; resolution below uses the
    # pre-injection snapshot so the bookkeeping stays honest.
    if environ is None:
        for k, v in dotenv.items():
            # NEVER the ROOT waiver: `.env` is config; the typed-ROOT waiver
            # is a control lever read from PROCESS ENV ONLY (module docstring,
            # and the Confirmer reads os.environ — injecting the row here
            # would let a persisted line waive the ceremony for every future
            # run on the box, and hand the waiver to every child).
            if k == "VIDE_CONFIRM_ROOT":
                continue
            os.environ.setdefault(k, v)

    def resolve(s: Setting) -> Any:
        """Resolve one setting, and turn a bad value into a SENTENCE.

        Eight rows here cast with a bare `int`/`float`, and `ValueError` was
        mapped to nothing — so `VIDE_PORT_BASE=97 97` did not produce a refusal
        naming the row, it produced a Python traceback out of EVERY verb, on the
        exit code of an unhandled exception rather than the one the contract
        promises for a config error. That includes `vide doctor --quiet`, the
        documented cron hook: a typo in one `.env` line silently converted the
        box's monitoring into a mail every five minutes containing a stack trace.

        The row is named, the offending value is NOT echoed — `.env` also carries
        the installer URLs, and a config error should not become a way to get a
        value printed into a log by mistyping the key next to it."""
        for src, where in ((argv_env or {}, "the command line"),
                           (env, "the environment"), (dotenv, ".env")):
            v = src.get(s.env, "")
            if v != "":
                try:
                    return s.cast(v)
                except (ValueError, TypeError):
                    raise ConfigError(
                        f"{s.env} from {where} is not a valid "
                        f"{getattr(s.cast, '__name__', 'value')}") from None
        try:
            return s.cast(s.default)
        except (ValueError, TypeError):  # pragma: no cover - a defect in SCHEMA
            raise ConfigError(f"the built-in default for {s.env} is invalid — "
                              f"this is a bug in VIDE, not in your config") from None

    values = {s.field: resolve(s) for s in SCHEMA}

    # Derived default, and the ORDER matters: the nvm URL interpolates the
    # RESOLVED nvm_version, so it must be built after the whole schema has been
    # resolved — not from the raw default — unless the URL was set explicitly.
    if not values["nvm_installer_url"]:
        values["nvm_installer_url"] = (
            "https://raw.githubusercontent.com/nvm-sh/nvm/"
            f"{values['nvm_version']}/install.sh"
        )
    return Config(values, repo_dir)
