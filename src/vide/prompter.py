"""The Prompter port — every adaptive decision the install journey can ask.

This module is the single registry of ask-points (that enumerability is what
keeps `--no-gui` parity testable: a question added here without a
non-interactive twin fails a structural test, not a user in CI). Two rules,
both structural:

- The port is consumed ONLY by the install sequencer; domain modules never
  see it. Answers travel onward as plain function arguments.
- Answers are PER-INVOCATION INTENT — the same category as `--yes` — so they
  must never become Config fields: a `VIDE_REINSTALL=1` left in `.env` waving
  through a destructive choice on every converge is exactly the config-vs-
  control disease I6 exists to prevent.

`PlainPrompter` IS today's behavior: every method returns the silent
resolution the bash-era flow made, so the plain path (and the frozen arbiter)
is byte-identical whether or not a Prompter is in play. `deliver_secret`
exists because the wizard buffers stderr while curses owns the screen: a
SHOWN-ONCE password routed through the Reporter would be painted onto the log
pane mid-run AND replayed later. Plain mode emits the exact contract line at
the exact point it was always emitted; the TUI stashes it for after endwin().
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Protocol

from .errors import UsageError
from .reporter import Reporter


# Shown by BOTH front-ends (plain: Reporter.banner; wizard: the welcome
# screen) — one constant, two renderers, so the words cannot drift. Lives
# here because tui/ may import prompter but not install_flow.
#
# Mode-agnostic by design (the SSO slice): it states the truths that hold in
# BOTH modes (loopback bind, the perimeter is the operator's, CT logs make the
# name public). The mode-specific gate sentence moves to finish()'s facts, where
# the mode is known — a password promise on a passwordless install is exactly
# the copy drift the twin discipline exists to prevent.
EXPOSURE_BANNER = """
================= VIDE EXPOSURE WARNING =================
VIDE binds code-server to loopback ONLY (a local TCP port, or a local unix
socket under SSO). Everything that makes an instance reachable from the
internet — TLS, DNS, and the IP-WHITELIST — lives in YOUR Caddy/proxy. VIDE has
NOT and CANNOT verify it.

Behind that proxy sits a shell that can reach root via sudo. The subdomain
becomes public via Certificate-Transparency logs the moment a cert issues —
the name is not a secret. Verify your whitelist.
========================================================
"""


# Same one-source rule as EXPOSURE_BANNER: the Confirmer banners it on the
# plain path; the wizard renders it AT the decision point (the root menu
# branch) — warn where the hand hovers.
ROOT_BANNER = """
*** ROOT INSTANCE ***
You are creating a ROOT code-server instance. Compromise of this instance =
instant, UNCONTAINED root plus every credential on this box (cloud API keys,
SSH keys -> pivot to the whole account). Give its subdomain a TIGHTER whitelist
than any other instance."""


class InstanceAction(Enum):
    """What to do about a target user who ALREADY has an instance."""
    CONVERGE = "converge"      # today's semantics: re-assert, keep secrets
    UPGRADE = "upgrade"        # `vide upgrade` inline
    ROTATE = "rotate"          # `vide rotate` inline
    REINSTALL = "reinstall"    # destroy artifacts, then fresh install


@dataclass(frozen=True)
class InstanceFacts:
    user: str
    port: int | None
    active: bool
    version: str
    auth: str = "password"           # "password" | "sso"
    binding: str = ""                # display: "127.0.0.1:9797" or "socket /run/..."


@dataclass(frozen=True)
class SsoFacts:
    """Discovered SSO state behind the auth-mode question. `proxy_configured`
    degrades the wizard copy to 'join existing SSO' and skips the credential
    screens; `parent_domain` is the persisted shared domain (empty until the
    first SSO install)."""
    default: str                     # "password" | "sso"
    proxy_configured: bool
    parent_domain: str


@dataclass(frozen=True)
class SsoCredentials:
    client_id: str
    # repr suppressed: this object rides the InstallPlan, and a plan repr'd into
    # a traceback or debug log must never echo the GOCSPX- secret.
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class UserFacts:
    """Discovered state behind the target-user question. `user_exists` and
    `instances` are probe callables (data, not imports) so the TUI can decorate
    its menu and validate a typed name inline without importing a domain
    module — and so the PLAIN path, which never looks, never pays the
    systemctl queries (keeps I2 hermetic and the arbiter's converge cheap)."""
    default: str
    sudo_user: str
    current_user: str
    allow_root: bool
    instances: Callable[[], tuple[InstanceFacts, ...]]
    user_exists: Callable[[str], bool]


@dataclass(frozen=True)
class ToolchainFacts:
    node_version: str        # "v22.1.0" or "" when nothing satisfying exists
    node_bindir: str
    pnpm_ok: bool


@dataclass(frozen=True)
class InstallSummary:
    """What `finish()` shows; also everything the wizard needs to print the
    equivalent --no-gui command (the wizard is a command builder)."""
    user: str
    port: int | None
    fqdn: str
    version: str
    config_path: str
    toolchain: str
    action: InstanceAction
    dry_run: bool
    mode: str = "password"           # "password" | "sso"
    binding: str = ""                # "127.0.0.1:9797" or "socket /run/vide/u/..."
    whitelist: str = ""              # the initial allowed email (sso)
    parent_domain: str = ""          # the shared *.domain (sso)
    signout_url: str = ""            # the fleet-wide sign_out endpoint (sso)


class Asker(Protocol):
    """The solicitation surface — every ask-point, plus the re-ask capability.
    `resolve_plan` takes ONLY this: the plan phase asks and refuses, never
    mutates. This Protocol is the single enumerable registry of ask-points; the
    I9 invariant reads these names and asserts none appear in `apply_plan`."""
    #: Per-invocation intent from `--sso-reaffirm`, NOT a Config setting: it is
    #: a control lever, and a `.env` row that silently re-asked for the Google
    #: secret on every install would be the config-vs-control mistake I6 exists
    #: to prevent. It rides the Asker because that is already how argv-supplied
    #: SSO answers reach resolve (sso_client_id, sso_allow).
    sso_reaffirm: bool

    def acknowledge_exposure(self) -> None: ...
    def choose_target_user(self, facts: UserFacts) -> str: ...
    def existing_instance_action(self, inst: InstanceFacts) -> InstanceAction: ...
    def toolchain_reinstall(self, facts: ToolchainFacts, default: bool) -> bool: ...
    def password_choice(self, user: str) -> str | None: ...
    def choose_fqdn(self, default: str, *, required: bool = False) -> str: ...
    def auth_mode(self, facts: SsoFacts) -> str: ...
    def sso_parent_domain(self, default: str) -> str: ...
    def sso_credentials(self, default_client_id: str) -> SsoCredentials: ...
    def whitelist_email(self, user: str, default: str) -> str: ...

    def can_reask(self) -> bool:
        """True only for a live-human prompter: a DECLINED confirmation
        (mistyped ROOT, [y/N]=N on reinstall) then returns to the question
        instead of dying — changing your mind is not a failure. Scripted/
        plain runs answer False and keep today's die-with-the-error paths
        (a re-ask there would loop forever on the same scripted answer)."""
        ...


class Announcer(Protocol):
    """The delivery surface — output, never solicitation. `apply_plan` takes
    ONLY this: the apply phase announces (secrets, the summary) but cannot ask.
    Segregated from Asker so I9 can prove the mutation half solicits nothing."""
    def deliver_secret(self, line: str) -> None: ...
    def finish(self, summary: InstallSummary) -> None: ...


class Prompter(Asker, Announcer, Protocol):
    """Both halves — what a real front-end implements. Kept as one name so
    `run_install(..., prompter=)`, `PlainPrompter` and `TuiPrompter` need no
    signature change; the split is expressed by which HALF each phase accepts."""


MIN_PASSWORD_LEN = 8
WARN_PASSWORD_LEN = 16


def check_client_id(cid: str) -> str | None:
    """Google OAuth client-id shape (warn-only, never echoes the value)."""
    if not cid.endswith(".apps.googleusercontent.com"):
        return "that does not look like a Google OAuth client id (expected ...apps.googleusercontent.com)"
    return None


def check_client_secret(sec: str) -> str | None:
    """Google OAuth client-secret shape (warn-only, never echoes the value)."""
    if not sec.startswith("GOCSPX-"):
        return "that does not look like a Google OAuth client secret (expected a GOCSPX- prefix)"
    return None


def check_password(pw: str) -> str | None:
    """Operator-supplied password policy, shared by the wizard field and
    --password-stdin. Behind the loopback proxy code-server sees every client
    as 127.0.0.1, so its brute-force limiter is blind — entropy is the only
    auth control VIDE owns (secrets.py's threat note). <8 is refused; 8..15
    returns a warning the caller must surface; None means acceptable."""
    if len(pw) < MIN_PASSWORD_LEN:
        raise UsageError(f"password too short ({len(pw)} chars): the minimum is "
                         f"{MIN_PASSWORD_LEN} — behind the proxy, entropy is the "
                         "only brute-force control")
    if len(pw) < WARN_PASSWORD_LEN:
        return (f"password is short ({len(pw)} chars): behind the proxy "
                "code-server's rate limiter is blind — 16+ recommended")
    return None


def require_answer(value: str, flag: str) -> str:
    """The pinned --no-gui failure mode for a REQUIRED ask with no default:
    die EX_USAGE naming the exact flag — never fall back to a prompt a CI run
    would hang on. No password-mode ask needs it today; the SSO slice's
    client_id/secret will."""
    if not value:
        # THE REASON USED TO BE STATED AS A FACT ABOUT THE TERMINAL — "running
        # without a terminal, so there is nobody to ask" — and it is false on
        # the path this message is most often read from. `vide` prints a resume
        # command carrying --no-gui; the operator pastes it into the very
        # terminal they are sitting at, and gets told there isn't one. They then
        # go looking for a tty problem that does not exist. This helper cannot
        # tell the two causes apart (and must not start reading stdin to find
        # out), so it names the behaviour instead of guessing the cause.
        raise UsageError(f"missing required value: pass {flag} (this run does "
                         "not prompt — --no-gui, or no terminal to ask on)")
    return value


class PlainPrompter:
    """Today's silent resolutions, verbatim — the plain flow and the frozen
    arbiter run THROUGH these methods and must not be able to tell."""

    def __init__(self, rep: Reporter, *, password: str | None = None,
                 sso_secret: str | None = None, sso_client_id: str = "",
                 sso_allow: str = "", sso_reaffirm: bool = False) -> None:
        self._rep = rep
        self._password = password  # from --password-stdin, never argv/env
        self._sso_secret = sso_secret  # from --sso-secrets-stdin, never argv/env
        self._sso_client_id = sso_client_id  # from --sso-client-id (public, not secret)
        self._sso_allow = sso_allow  # from --sso-allow
        self.sso_reaffirm = sso_reaffirm  # from --sso-reaffirm

    def acknowledge_exposure(self) -> None:
        return None  # the banner already went to stderr; nothing to wait for

    def choose_target_user(self, facts: UserFacts) -> str:
        return facts.default

    def existing_instance_action(self, inst: InstanceFacts) -> InstanceAction:
        return InstanceAction.CONVERGE

    def toolchain_reinstall(self, facts: ToolchainFacts, default: bool) -> bool:
        return default

    def password_choice(self, user: str) -> str | None:
        return self._password

    def choose_fqdn(self, default: str, *, required: bool = False) -> str:
        # The plain path returns the default even when required; the sequencer's
        # require_answer names --fqdn if it is empty (nobody to inline-re-ask).
        return default

    def auth_mode(self, facts: SsoFacts) -> str:
        # The sequencer resolves cfg.auth (empty -> "password") into facts.default,
        # so a bare --no-gui run is byte-identical to the frozen password contract.
        return facts.default

    def sso_parent_domain(self, default: str) -> str:
        # Always derived (non-empty) from the required SSO fqdn by resolve_plan,
        # or supplied via --parent-domain; the plain path just echoes it. No
        # require_answer here: --parent-domain is never independently required,
        # so a guard on it could never fire and would only mislead the I-invariant
        # that maps every require_answer flag to a real ask.
        return default

    def sso_credentials(self, default_client_id: str) -> SsoCredentials:
        return SsoCredentials(
            client_id=require_answer(self._sso_client_id or default_client_id, "--sso-client-id"),
            client_secret=require_answer(self._sso_secret or "", "--sso-secrets-stdin"))

    def whitelist_email(self, user: str, default: str) -> str:
        return require_answer(self._sso_allow or default, "--sso-allow")

    def deliver_secret(self, line: str) -> None:
        self._rep.info(line)

    def finish(self, summary: InstallSummary) -> None:
        return None

    def can_reask(self) -> bool:
        return False
