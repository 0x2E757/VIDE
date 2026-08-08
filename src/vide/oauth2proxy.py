"""The durable-singleton oauth2-proxy lifecycle: acquire the binary (download →
sha256-verify → single-member extract → versioned dir → `current` symlink →
prune to N-1), render the config + secrets, install the hardened unit, and the
verbs rotate-sso / upgrade-sso plus doctor's proxy section.

Second VIDE-managed binary after code-server, but unlike code-server there is
NO upstream installer to delegate to — VIDE owns every step. The floor is a
CODE CONSTANT, never a config row: an operator must not be able to pin below
the CVE-2026-40575 fix.
"""
from __future__ import annotations

import enum
import hashlib
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Mapping, Sequence

from . import contract, net, system
from .config import Config, parse_env_text
from .errors import (CommandFailed, ConfigError, StateError, UnavailableError,
                     UsageError)
from .executor import Executor
from .reporter import Reporter

# CVE-2026-40575 / GHSA-7x63-xv5r-3p2x (X-Forwarded-Uri spoofing, CVSS 9.1) is
# fixed in 7.15.2. This is the minimum VIDE will install or certify — code
# constant, deliberately NOT a config row.
FLOOR = (7, 15, 2)

UNIT = "vide-oauth2-proxy.service"
#: The socket unit that RESERVES the fleet's authorization port. It binds as
#: PID 1 at sockets.target and the service inherits the descriptor, so this name
#: appears wherever the service's own state is not evidence about who holds the
#: address — which, after socket activation, is everywhere that matters.
SOCKET_UNIT = "vide-oauth2-proxy.socket"
#: Where installed units live. A module constant rather than three literals, and
#: the reason is testability rather than tidiness: _gate_inputs stats these paths
#: to decide whether the fleet's sole authorization gate restarts, so with the
#: literal inlined every verb-level test of that decision reads the machine
#: running the tier — the exact coupling the host-read seam exists to forbid, and
#: the one that made the "already migrated" row green on a box with no gate.
SYSTEMD_DIR = Path("/etc/systemd/system")
#: How long a caller waits for the shared proxy to answer after a restart.
#:
#: RE-ANCHORED. This was `StartLimitBurst x RestartSec + slack`, read off the
#: unit and pinned against it by a test — a derivation that no longer exists,
#: because the unit's start limiter is now OFF (a limiter that fires hands the
#: fleet's port away; the unit says why at length). There is no retry runway to
#: outlast any more: the proxy retries forever.
#:
#: So the number is now a DECISION rather than a derivation, and it is written as
#: one: RestartSec x an attempt count we are willing to wait for. The value is
#: deliberately unchanged, because what it has to cover did not change — a slow
#: resolver completing OIDC discovery on a cold boot. What changed is that
#: exceeding it no longer means the unit gave up; it means WE stopped watching.
#: Every caller must therefore say "not yet" rather than "failed" (see
#: proxy_ready's message and _verify_proxy_came_back's).
UNIT_RESTART_S = 5          # RestartSec= in units/oauth2-proxy.service, pinned by test
UNIT_RESTART_ATTEMPTS = 24  # how many of them we are willing to wait through
UNIT_RESTART_BUDGET_S = UNIT_RESTART_S * UNIT_RESTART_ATTEMPTS
#: Per-probe timeout for the POLL LOOPS, and it exists because socket activation
#: deleted the fast negative. With PID 1 holding the listener and nothing
#: accepting, connect(2) SUCCEEDS — the kernel completes the handshake into the
#: accept queue — so a probe against a down proxy no longer returns
#: ECONNREFUSED instantly, it blocks for the full timeout. At the module default
#: of 3s that turns a 120s budget into ~360s of wall clock, and inside
#: proxy_ready it re-freezes the curses pane that ex.idle exists to keep alive.
#: 1.0s is ~3 orders of magnitude of headroom for a static /ping handler over
#: loopback (the rendered config has cookie_refresh structurally absent, so the
#: proxy makes NO outbound call per request), and a single false negative costs
#: nothing because the loop retries for the whole budget.
PROXY_PING_TIMEOUT_S = 1.0
#: Caddy's default admin endpoint. Not configurable here on purpose: this is
#: upstream's default, and the check exists precisely to catch the box that
#: never moved it.
CADDY_ADMIN_PORT = 2019
PROXY_USER = "vide-oauth2"
PROXY_GROUP = "vide-proxy"
#: proxy.toml's posture, named once because three places now assert it: the two
#: writers and _repair_toml_posture. It is 0640 root:vide-oauth2 — readable by
#: the proxy that must load it, writable by nobody but root, and the WIDTH is
#: the security-relevant half: this file's trusted_proxy_ips line is the
#: CVE-2026-40575 mitigation and its guarantee rests on which keys are absent.
TOML_MODE = 0o640

_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}


def _parse_version(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in v.lstrip("v").split("."))
    except ValueError:
        raise ConfigError(f"unparseable oauth2-proxy version: {v!r}") from None


def _arch_asset(cfg: Config) -> str:
    m = system.uname_m(cfg.uname_m)
    if m not in _ARCH:
        raise ConfigError(f"unsupported arch for oauth2-proxy: {m}")
    return _ARCH[m]


def toml_path(cfg: Config) -> Path:
    return Path(cfg.sso_dir) / "proxy.toml"


def env_path(cfg: Config) -> Path:
    return Path(cfg.sso_dir) / "proxy.env"


def version_file(cfg: Config) -> Path:
    return Path(cfg.sso_dir) / "proxy.version"


def _versioned_bin(cfg: Config, ver: str) -> Path:
    return Path(cfg.oauth2_proxy_dir) / ver / "oauth2-proxy"


def current_link(cfg: Config) -> Path:
    return Path(cfg.oauth2_proxy_dir) / "current"


# ---- provisioning state -----------------------------------------------------
def provisioned(cfg: Config) -> bool:
    """Existence predicate: the three durable files are present. Kept as the
    'is a proxy visible?' signal for doctor/rotate/upgrade — but NOT trusted by
    the installer to decide whether credentials are needed (a torn proxy.env
    with an empty secret satisfies this yet must still be re-affirmed)."""
    return (toml_path(cfg).exists() and env_path(cfg).exists()
            and current_link(cfg).exists())


def credentials_recorded(cfg: Config) -> bool:
    """The recorded proxy.env carries a real IdP client AND a cookie secret.
    A three-file-but-empty-secret proxy reads provisioned() yet FALSE here."""
    env = parse_env_text(_read(env_path(cfg)))
    return bool(env.get("OAUTH2_PROXY_CLIENT_ID")
                and env.get("OAUTH2_PROXY_CLIENT_SECRET")
                and env.get("OAUTH2_PROXY_COOKIE_SECRET"))


def credentials_needed(cfg: Config) -> bool:
    """Must THIS run solicit the Google credentials? True unless a fully
    credentialed proxy is already recorded. Decided ONCE in resolve and consumed
    by apply, so 'the operator forgot the secret' and 'joining the existing
    proxy' can never collapse into the same silent exit 0.

    It answers THAT question and no other. It was once also read as "is the
    shared proxy finished?", which it cannot know: it goes False the moment
    proxy.env is complete, three steps before the unit is installed, enabled and
    joined to caddy. A failed enable then latched permanently — the install
    printed "Install complete" and every request 502'd, and no re-run could
    heal it because the predicate had already flipped. There is no second
    predicate now: converge_proxy runs unconditionally, so nothing branches on
    "finished" and nothing can latch it. Liveness is proxy_health's job, read
    from the running system rather than from recorded intent."""
    return not (provisioned(cfg) and credentials_recorded(cfg))


def installed_version(cfg: Config) -> str:
    return parse_env_text(_read(version_file(cfg))).get("VIDE_OAUTH2_PROXY_VERSION", "")


def _read(p: Path) -> str:
    try:
        return p.read_text()
    except OSError:
        return ""


# ---- version resolution -----------------------------------------------------
def resolve_version(cfg: Config) -> str:
    """Explicit pin wins; else resolve the latest tag via the /releases/latest
    redirect. Enforce the floor on BOTH — an operator may not pin below it."""
    ver = cfg.oauth2_proxy_version.strip().lstrip("v")
    if not ver:
        ver = net.resolve_latest_version(cfg, url=cfg.oauth2_proxy_releases_latest_url)
    if not ver:
        raise UnavailableError("could not resolve the latest oauth2-proxy version "
                               "(and none pinned via VIDE_OAUTH2_PROXY_VERSION)")
    if _parse_version(ver) < FLOOR:
        raise ConfigError(
            f"oauth2-proxy {ver} is below the security floor "
            f"{'.'.join(map(str, FLOOR))} (CVE-2026-40575) — refusing to install")
    return ver


# ---- binary acquisition -----------------------------------------------------
def install_version(cfg: Config, ex: Executor, rep: Reporter, ver: str) -> str:
    """Download the per-arch tarball + its sha256 companion, verify, extract the
    ONE known member (never extractall — sidesteps the tar-path-traversal class
    on Python 3.10), place 0755 root:root under a versioned dir. Returns the
    verified sha256 hex."""
    arch = _arch_asset(cfg)
    asset = f"oauth2-proxy-v{ver}.linux-{arch}.tar.gz"
    base = f"{cfg.oauth2_proxy_download_base}/v{ver}"
    member = f"oauth2-proxy-v{ver}.linux-{arch}/oauth2-proxy"

    if ex.narrate(f"would download + verify {asset} and install it to "
                  f"{_versioned_bin(cfg, ver)}"):
        return "dry-run"

    staging = Path(tempfile.mkdtemp(prefix="vide-o2p."))
    try:
        tgz = staging / asset
        sha = staging / f"{asset}-sha256sum.txt"
        ex.download(f"{base}/{asset}", tgz, "VIDE_OAUTH2_PROXY_DOWNLOAD_BASE")
        ex.download(f"{base}/{asset}-sha256sum.txt", sha, "VIDE_OAUTH2_PROXY_DOWNLOAD_BASE")
        want = _sha_for(sha.read_text(), asset)
        got = _hash_file(tgz)
        if got != want:
            raise UnavailableError(
                f"oauth2-proxy tarball sha256 mismatch (want {want}, got {got})")
        extracted = staging / "oauth2-proxy"
        _extract_member(tgz, member, extracted)
        ex.ensure_dir(Path(cfg.oauth2_proxy_dir), mode=0o755, owner=("root", "root"))
        ex.ensure_dir(_versioned_bin(cfg, ver).parent, mode=0o755, owner=("root", "root"))
        ex.run(["install", "-m", "0755", "-o", "root", "-g", "root",
                str(extracted), str(_versioned_bin(cfg, ver))])
        return got
    finally:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)


def _sha_for(sha_text: str, asset: str) -> str:
    """Pick the entry matching our asset from a sha256sum file (works for
    per-asset and combined files: `<hex>  <filename>` lines)."""
    for line in sha_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*").endswith(asset):
            return parts[0]
    # a per-asset file may carry only the hex + a different filename; if there is
    # exactly one line, trust its hash.
    lines = [ln for ln in sha_text.splitlines() if ln.split()]
    if len(lines) == 1:
        return lines[0].split()[0]
    raise UnavailableError(f"no sha256 entry for {asset} in the checksum file")


def _hash_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_member(tgz: Path, member: str, dest: Path) -> None:
    with tarfile.open(tgz, "r:gz") as tf:
        try:
            src = tf.extractfile(member)
        except KeyError:
            src = None
        if src is None:
            raise UnavailableError(
                f"expected member {member!r} not found in {tgz.name} — the release "
                "layout may have changed (override VIDE_OAUTH2_PROXY_DOWNLOAD_BASE)")
        with src, open(dest, "wb") as out:
            out.write(src.read())
    dest.chmod(0o755)


def flip_current(cfg: Config, ex: Executor, ver: str) -> None:
    """Atomic swap, not `ln -sfn`: that is unlink-then-symlink, so there is a
    window with no `current` at all — and `current` is the unit's ExecStart
    target. The window is sub-millisecond and upgrade_sso restarts immediately
    after, but the failure it opens (the proxy failing to exec) is a fleet-wide
    outage, which is the exact class prune() already reasons carefully about."""
    link = current_link(cfg)
    tmp = link.with_name(link.name + ".tmp")
    ex.run(["ln", "-sfn", ver, str(tmp)])
    ex.run(["mv", "-T", str(tmp), str(link)])


def prune(cfg: Config, ex: Executor) -> None:
    """Keep the `current` symlink target AND the next-highest OTHER version
    (the N-1 rollback lever); rm the rest. The current target is kept even on a
    pinned DOWNGRADE (where it is not the highest version) — deleting it would
    leave `current` dangling on the next restart, a fleet-wide outage. Integer-
    tuple compare, never string sort."""
    d = Path(cfg.oauth2_proxy_dir)
    if not d.is_dir():
        return
    cur = ""
    try:
        cur = (d / "current").resolve().name
    except OSError:
        pass
    others = sorted((p.name for p in d.iterdir()
                     if p.is_dir() and p.name[0].isdigit() and p.name != cur),
                    key=_parse_version, reverse=True)
    keep = {cur} | set(others[:1])   # current + one rollback
    for p in d.iterdir():
        if p.is_dir() and p.name[0].isdigit() and p.name not in keep:
            ex.run(["rm", "-rf", str(p)])


def record_version(cfg: Config, ex: Executor, ver: str, sha: str) -> None:
    ex.atomic_write(version_file(cfg),
                    f"VIDE_OAUTH2_PROXY_VERSION={ver}\nVIDE_OAUTH2_PROXY_SHA256={sha}\n",
                    mode=0o644, owner=("root", "root"))


# ---- identities + caddy group -----------------------------------------------
def ensure_identities(ex: Executor, rep: Reporter) -> None:
    if not system.group_exists(PROXY_GROUP):
        ex.run(["groupadd", "--system", PROXY_GROUP])
    if not system.user_exists(PROXY_USER):
        # --user-group, asked for rather than inherited: proxy.toml (0640
        # root:vide-oauth2) and the union authn file are chowned to a GROUP of
        # this name, which exists only because useradd creates a user-private
        # one. That is USERGROUPS_ENAB=yes in /etc/login.defs — a Debian/Ubuntu
        # default, not a guarantee — and on a box where the operator turned it
        # off the chown fails three writes later, now with a named error rather
        # than a bare KeyError but still on a box VIDE had no reason to break.
        # Omitted when something already made that group, because `useradd -U`
        # refuses then: the user is created without it and the chown still
        # resolves, which is what a re-run after a half-finished install needs.
        private = [] if system.group_exists(PROXY_USER) else ["--user-group"]
        ex.run(["useradd", "--system", *private, "-M", "-d", "/nonexistent",
                "-s", "/usr/sbin/nologin", PROXY_USER])


def ensure_caddy_membership(ex: Executor, rep: Reporter) -> None:
    if system.user_exists("caddy"):
        ex.run(["usermod", "-aG", PROXY_GROUP, "caddy"])
        rep.warn("added caddy to the 'vide-proxy' group — RESTART caddy once "
                 "(supplementary groups are read at process start): "
                 "sudo systemctl restart caddy")
    else:
        rep.warn("caddy user not found; after installing caddy run: "
                 f"sudo usermod -aG {PROXY_GROUP} caddy && sudo systemctl restart caddy")


# ---- rendered config --------------------------------------------------------
# \Z, not $: Python's $ matches before a trailing newline, and this regex is
# the newline-smuggling backstop for values interpolated into proxy.toml lines
# and Caddy redirects.
_DNS_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\Z")


#: The issuer is the fleet's root of trust and lands in a TOML line, so it gets
#: the same `\Z` anchor as _DNS_NAME: `$` would let a trailing newline open a
#: second line and reinstate a key the file swears is structurally absent.
_HTTPS_URL = re.compile(r"https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?\Z")

#: The loopback carve-out, named so it is greppable and so widening it is a
#: deliberate edit to a line that says why it exists. Every OIDC stack makes this
#: exception (RFC 8252 §7.3, OAuth 2.1): a local IdP has no CA to speak of and no
#: MITM surface, because the connection never leaves the box. oauth2-proxy itself
#: does NOT refuse a plaintext issuer — upstream's own examples use
#: `http://127.0.0.1:5556/dex` — so this control is VIDE's alone, and a rule
#: without the carve-out is a rule nothing upstream would have caught.
#: It is also the documented test seam (.env.example, VIDE_SSO_ISSUER_URL): the
#: sso-mode, host-smoke and live-fleet tiers all drive a fake IdP on
#: http://127.0.0.1. Refusing it made all three unrunnable while every unit row
#: stayed green — the tiers that would have caught it were the tiers it broke.
#: Anything non-loopback still needs https; a cleartext issuer off-box is a full
#: authentication bypass.
#:
#: LITERAL addresses only — `localhost` is deliberately NOT accepted, though the
#: RFC section above tolerates it. It is a name, so what it denotes is decided by
#: /etc/hosts and the resolver rather than by this file, and the two literals are
#: not. The seam does not need it (all three tiers spell 127.0.0.1), so admitting
#: it would buy nothing and widen what a poisoned 0644 fleet.env can point at.
#: The carve-out is still not a free pass: any local account that can bind the
#: loopback port before oauth2-proxy resolves discovery becomes the fleet's IdP.
#: What contains that is the box's own trust model — VIDE says out loud that
#: co-tenancy is shared trust (SECURITY.md) — not this regex.
_HTTP_LOOPBACK_URL = re.compile(
    r"http://(127\.0\.0\.1|\[::1\])(:\d+)?(/[A-Za-z0-9._~\-/]*)?\Z")


def check_url(url: str, what: str) -> None:
    """https-only, no whitespace, no newline — except a loopback authority (see
    _HTTP_LOOPBACK_URL). Applied on read-back from fleet.env AND on the
    operator's own value in resolve: that file is 0644 and a damaged or
    hand-edited row must not reach a rendered config unchecked, and a value the
    renderer will refuse must fail before fleet.env pins it, since there is no
    reset verb."""
    if not (_HTTPS_URL.match(url) or _HTTP_LOOPBACK_URL.match(url)):
        raise ConfigError(f"invalid {what} {url!r} — expected an https URL with no "
                          "whitespace (http is accepted only for a loopback issuer)")


def check_dns_name(name: str, what: str = "parent domain") -> None:
    """The DNS-name shape gate, shared by resolve (pre-mutation, on the fqdn and
    the derived parent) and render_proxy_toml (the backstop on the rendered
    parent). Rejecting here — not lowercasing — is deliberate: an upper-case
    fqdn that passes presence checks must fail BEFORE the host is mutated, not
    silently deep in the renderer after fleet.env is already written."""
    if not _DNS_NAME.match(name):
        raise ConfigError(f"invalid {what} {name!r} — expected a dotted DNS name "
                          "(lowercase letters, digits, hyphens)")


def render_proxy_toml(cfg: Config, parent_domain: str) -> str:
    """The entire non-secret flag surface, from one frozen literal. Secrets live
    ONLY in proxy.env. The forbidden keys are structurally absent (see the
    docstring on the module): there is no dict-of-options builder through which
    a caller could inject one, and the unit test enumerates the placeholder set.
    The parent domain is the only operator-influenced interpolation — validate it
    to a DNS-name shape so it cannot smuggle a newline that opens a new TOML line.

    The issuer and the port come from the FLEET PINS once a fleet exists, never
    live from cfg. This file is re-rendered on every converge now, and both
    values are `.env`-settable: reading them live would let one row repoint the
    fleet's root of trust at the next restart, and move the proxy away from the
    port baked into the auth block the operator pasted into their Caddyfile.
    `.env` may configure the FIRST install; after that the fleet decides.
    """
    check_dns_name(parent_domain)
    from . import sso as vide_sso
    # Both through sso's readers, which validate on read-back: fleet.env is 0644
    # and a damaged or hand-edited row must not reach the render unchecked.
    issuer = vide_sso.fleet_issuer(cfg)
    return f"""# /etc/vide/sso/proxy.toml — rendered by VIDE; do not hand-edit.
provider = "oidc"
oidc_issuer_url = "{issuer}"
redirect_url = "https://auth.{parent_domain}/oauth2/callback"
# NOT AN ADDRESS — AN INDEX. `fd:3` means "the first listening descriptor systemd
# passed", i.e. SD_LISTEN_FDS_START; oauth2-proxy computes
# `fdIndex = fd - 3` and takes that position out of activation.Files(), which
# checks LISTEN_PID against getpid() first, so a descriptor handed to some other
# process is refused rather than used. The address itself lives in
# units/oauth2-proxy.socket and is bound by PID 1 at sockets.target — which is
# the whole point: the fleet's authorization port is never free for a local
# account to take while the proxy is stopped, restarting or crash-looping.
# Consequences a future editor must not undo:
#   * exactly ONE ListenStream= in that unit, forever, or this index moves;
#   * `fd:NAME` is unimplemented upstream ("fd with name is not implemented
#     yet"), so this is always the integer form.
http_address = "fd:3"
reverse_proxy = true
# KEEP AF_INET. This line is the CVE-2026-40575 mitigation (see FLOOR above), and
# it only works because the listener is a TCP socket: a request arriving over a
# UNIX socket has RemoteAddr == "@" and is documented upstream as never trusted
# on RemoteAddr, which would silently void this. That is the reason the fleet's
# hop was reserved with a socket unit rather than moved to a unix socket — the
# move looks like a stronger fix and would have disarmed the mitigation for the
# very CVE whose floor is a code constant in this module.
trusted_proxy_ips = ["127.0.0.1/32"]
authenticated_emails_file = "{Path(cfg.sso_dir) / 'authenticated-emails'}"
cookie_domains = [".{parent_domain}"]
whitelist_domains = [".{parent_domain}"]
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"
cookie_expire = "720h"
session_cookie_minimal = true
set_xauthrequest = true
prompt = "select_account"
skip_provider_button = true
# STRUCTURALLY ABSENT, forever (rendering any of these is a contract violation):
#   email_domains (the union authenticated_emails_file is the sole authn base —
#     never a '*' domain wildcard), cookie_refresh, skip_auth_routes,
#     skip_auth_regex, api_routes, insecure_oidc_allow_unverified_email, scope,
#   trusted_ips, skip_auth_preflight, skip_jwt_bearer_tokens
# The last three joined the list late and are the ones that would be SILENT:
# trusted_ips is one word from trusted_proxy_ips, which IS rendered above — and
# it does the opposite thing, BYPASSING authentication for the listed CIDRs.
# In this topology every request reaches the proxy from Caddy at 127.0.0.1, so
# trusted_ips = ["127.0.0.1/32"] would grant the whole internet unauthenticated
# access to every SSO instance. A list that omits its most dangerous member is
# not a control.
"""


def render_proxy_env(client_id: str, client_secret: str, cookie_secret: str) -> str:
    return (f"OAUTH2_PROXY_CLIENT_ID={client_id}\n"
            f"OAUTH2_PROXY_CLIENT_SECRET={client_secret}\n"
            f"OAUTH2_PROXY_COOKIE_SECRET={cookie_secret}\n")


# ---- the --sso-secrets-stdin STRICT parser ----------------------------------
def parse_sso_secrets(text: str) -> tuple[str, str]:
    """Read the SSO secret channel: the required VIDE_SSO_CLIENT_SECRET, plus
    an OPTIONAL VIDE_SSO_CLIENT_ID (the id is public and usually arrives via the
    --sso-client-id argv flag; accepting it here too lets a single heredoc carry
    both). STRICT: a malformed line, an unknown key, or an empty value dies
    EX_USAGE naming only the KEY (never echoing a value). Deliberately not
    parse_env_text (which silently skips junk). Returns (client_id_or_empty,
    client_secret)."""
    allowed = {contract.SSO_STDIN_CLIENT_ID, contract.SSO_STDIN_CLIENT_SECRET}
    got: dict[str, str] = {}
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise UsageError(f"--sso-secrets-stdin: line {i} is not KEY=VALUE")
        key = line.partition("=")[0].strip()
        val = line.partition("=")[2].strip()
        if key not in allowed:
            raise UsageError(f"--sso-secrets-stdin: line {i}: unexpected key")
        if not val:
            raise UsageError(f"--sso-secrets-stdin: empty value for {key}")
        got[key] = val
    if contract.SSO_STDIN_CLIENT_SECRET not in got:
        raise UsageError(f"--sso-secrets-stdin: missing required key "
                         f"{contract.SSO_STDIN_CLIENT_SECRET}")
    return got.get(contract.SSO_STDIN_CLIENT_ID, ""), got[contract.SSO_STDIN_CLIENT_SECRET]


# ---- the hardened unit + provisioning composite -----------------------------
def install_proxy_unit(cfg: Config, ex: Executor, rep: Reporter) -> bool:
    """Install units/oauth2-proxy.service if it differs (byte-compare + reload),
    the sysd.install_unit idiom. The unit is static — everything variable is in
    proxy.env / proxy.toml — so it never needs a daemon-reload on a config
    change, only on a unit-body change.

    Returns True iff the unit body changed, so the caller can report the pending
    restart. daemon-reload lands the manager-side half immediately (StartLimit*,
    Restart*, ordering); everything in [Service] that configures the executed
    process governs the NEXT process, not this one.

    The compare happens BEFORE the dry-run bail so a preview shows the real
    conditional outcome — the same reasoning sysd.install_unit already carries,
    and the reason it does not simply return early like the old code did."""
    src = (cfg.repo_dir / "units" / "oauth2-proxy.service").read_text()
    dest = SYSTEMD_DIR / UNIT
    # A masked unit is a symlink to /dev/null: the operator deliberately turned
    # the fleet's gate OFF. atomic_write's os.replace replaces the dest symlink
    # ITSELF, so converging would silently unmask it — and the `enable --now`
    # below would then start what they switched off. Refuse instead, naming the
    # one command that undoes it. Cheap here, and it matters more since the
    # converge stopped being gated on a first install.
    # startswith, not ==: `systemctl mask --runtime` reports `masked-runtime`,
    # and an exact compare let that path fall through to `enable --now`, which
    # dies with a bare CommandFailed instead of the named remedy below.
    if system.unit_enable_state(UNIT).startswith("masked"):
        raise StateError(
            f"{UNIT} is masked — refusing to converge over a unit you switched "
            f"off. Undo it deliberately: sudo systemctl unmask {UNIT}")
    changed = _read(dest) != src
    if ex.narrate(f"would install {UNIT}" if changed else f"{UNIT} unchanged"):
        return changed
    if changed:
        ex.atomic_write(dest, src, mode=0o644, owner=("root", "root"))
        ex.run(["systemctl", "daemon-reload"])
    return changed


#: The one templated token in units/oauth2-proxy.socket. `ListenStream=` takes no
#: environment expansion and a drop-in cannot REPLACE a list-valued directive
#: without an empty-reset line, so substitution is the only way the fleet's pinned
#: port can reach the unit body. Every other file under units/ ships byte-identical.
SOCKET_PORT_SENTINEL = "__VIDE_PROXY_PORT__"


def _covers_port(listening: list[str], port: int) -> bool:
    """Does this socket unit hold the FLEET'S port — exactly that one?

    An EXACT token compare, never a substring, and the substring version is why
    this is a named function. `f"127.0.0.1:{port}" in line` reads fine and is
    wrong in the one direction that matters: with the fleet pinned to 4180 and
    the unit listening on 41800, `"127.0.0.1:4180"` IS a substring of
    `"127.0.0.1:41800"`, so the drift goes unreported, the reservation is
    believed to cover a port nothing is holding, and the whole section reports
    green over a live bypass. A prefix pair like that is one typo away in a file
    an operator may hand-edit.

    `systemctl show -p Listen --value` renders `<address> (Stream)`, so the
    address is the first whitespace-separated field of each line.

    IT LIVES BESIDE THE WRITER RATHER THAN IN THE DOCTOR SECTION because it
    stopped being a diagnostic helper: install_proxy_socket_unit now refuses a
    write on it, so a future edit made for a doctor reason changes what a
    converge is allowed to do. That coupling is deliberate — it is what makes
    the refusal and the converge's unbound-reservation warning provably
    complementary instead of merely intended to be."""
    want = f"127.0.0.1:{port}"
    return any(ln.split()[0] == want for ln in listening if ln.split())


def _reservation_unit_present() -> bool:
    """Is there a reservation unit AT ALL on this box — a plain file fact.

    ASKED IN ONE PLACE because it is the tie-breaker on the only question whose
    wrong answer PERMITS a write. It was spelled two ways before: `bool(_read(
    dest))` at the writer and `(SYSTEMD_DIR / SOCKET_UNIT).is_file()` at the
    permit, which disagree on a zero-byte fragment — one refusal family, two
    answers to one question.

    `exists() or is_symlink()`, and neither half is redundant. `systemctl mask`
    replaces the entry with a symlink to /dev/null, which is not a regular file,
    so `is_file()` answered "no reservation here" for the unit an operator
    deliberately switched off — and on THIS unit switching it off does not close
    the gate, it gives the address away. A dangling symlink is the same class,
    and `exists()` alone follows it to nothing. Neither is a state to permit a
    move on.

    A ZERO-BYTE OR UNREADABLE FRAGMENT READS AS PRESENT, i.e. refuse. It
    configures nothing and therefore holds nothing, so the write would have been
    harmless — but `_read` maps every OSError to `""` (:166), so "unreadable"
    and "empty" arrive here indistinguishable from "absent", which is the one
    answer that lets a converge move the fleet's authorization address. The
    escape is one documented command (`rm` the unit, `daemon-reload`) and it is
    already the consent gesture; the fail-open direction costs the fleet its
    hop."""
    p = SYSTEMD_DIR / SOCKET_UNIT
    return p.exists() or p.is_symlink()


def loaded_reservation() -> list[str] | None:
    """The addresses the reservation unit ON THIS BOX is configured for.

    `[]` means there is no reservation unit here — a first install, or a box
    where the operator deliberately removed it. `None` means the question could
    not be answered, which is NOT the same thing and may never be treated as it.

    THE MANAGER, NOT THE FILE, and this was the round's live disagreement. Both
    readers ultimately render the same bytes, so they part in only two places:
    `systemctl show -p Listen` sees a `.socket.d` drop-in and a hand edit that
    has not been reloaded yet, and the file does not. The first matters most: an
    operator who edits the unit and gets distracted leaves file=NEW, loaded=OLD,
    and OLD still held — where a file reader answers NEW, agrees with a moved
    pin, and permits the very write that drops the descriptor. It also costs no
    new parser: the shipped body carries the literal `ListenStream=4180` inside
    a comment, so a file parse needs anchoring, comment-stripping and
    exactly-once semantics, each a place to be wrong, guarding a reader that is
    wrong about the question anyway.

    NO `active` GATE, AND THAT IS THE WHOLE SHAPE OF THE REFUSAL ABOVE. It was
    measured rather than assumed: `show -p Listen` answers for a LOADED unit
    whatever its state (systemd 257 answers for a stopped podman.socket,
    ssh.socket, cni-dhcp.socket). Gating on `active` would have permitted the
    quietest failure there is — socket unit stopped, pin already moved, converge
    writes the new address and enables it, and the NEXT BOOT binds an address
    the operator's Caddyfile does not name, with nothing said in between. So
    consent to a move is not `stop`, which is ambiguous (maintenance, debugging,
    a reboot in flight); it is removing the unit, which is not. The fleet's
    reservation address is write-once.

    AN UNREADABLE MANAGER MAY NOT PERMIT, AND THE TIE IS BROKEN ON DISK RATHER
    THAN BY THE MANAGER. `unit_listen_streams` answers `[]` for BOTH "no such
    unit" and "systemctl did not answer" — system.query returns rc 124 with empty
    stdout on a timeout — so on that reader alone no rule is right.

    The first attempt broke the tie with `is-enabled`, on the reasoning that an
    absent unit answers the word `not-found` and a wedged manager answers nothing.
    **That is only true from systemd 253.** Debian 12 ships 252 and Ubuntu 22.04
    ships 249, both supported here, and on those an absent unit prints nothing to
    stdout at all — so a FIRST SSO INSTALL would have read `None`, refused to
    write the socket unit, and then died at the `systemctl enable` that follows.
    No tier could have seen it: the container is Debian 13, and the hermetic fake
    answers `"disabled"` for a unit that is not there, which no systemd produces.

    So presence is decided by a plain stat — identical on every version, needing
    no manager at all — but it BREAKS THE TIE rather than being asked first, and
    the difference between those two orderings is a live hop. The first version
    of this fix stat'ed first and returned `[]` on an absent file, which
    contradicted the paragraph above it: on a box where the operator removed the
    fragment and has not reloaded yet, the unit is STILL LOADED and STILL HOLDING
    the address, `show -p Listen` says so, and a file-first reader never asks. It
    answered `[]`, the move refusal was skipped, the new address was written and
    reloaded, systemd dropped the descriptor it was holding and bound nothing in
    its place — VIDE releasing the fleet's authorization hop by its own hand, out
    of the one function written to prevent that.

    Hence: a POSITIVE reading from the manager always decides, and the file is
    consulted only when the manager answers nothing. Then an empty `Listen` over
    a present fragment can only mean the read did not land, and refusing on it is
    correct rather than a guess; an empty `Listen` over an absent one is a first
    install or a completed consent, and permitting it is correct rather than
    generous."""
    loaded = system.unit_listen_streams(SOCKET_UNIT)
    if loaded:
        return loaded                   # a POSITIVE reading always decides
    return None if _reservation_unit_present() else []


def gate_is_on_hop(port: int) -> bool:
    """Is the fleet's authorization gate DEMONSTRABLY on 127.0.0.1:<port>?

    The permit for any write that would REPOINT the fleet — today, the
    per-instance authorization bodies in sso._render_all. It answers only in the
    affirmative direction: everything unproven is False, including an unreadable
    kernel, because the caller's refusal costs one loud command and its permit
    can cost the fleet its hop.

    TWO CASES, AND THE SECOND IS NOT A CONCESSION.

      * MIGRATED — the reservation unit is active, configured for this port, and
        the socket on it is owned by uid 0 alone. That is doctor's own `holds`
        triple, and it is the state the documented move ENDS in.
      * UN-MIGRATED BUT CONSISTENT — the gate is bound to this port by the proxy
        itself, before any reservation exists. The port IS the live hop there, so
        pointing the bodies at it is correct. It mirrors doctor's own
        `legitimate = {0} | {proxy_uid}`.

    `covers` IS NOT OPTIONAL IN CASE 1, and this is the false permit neither
    reviewer named until the mechanism was read: hop_holders' v4 match set
    includes the 0.0.0.0 WILDCARD, so `certain == {0}` is satisfied by any
    unrelated root daemon on a wildcard port. Without `covers`, a hand-edited pin
    landing on such a port would permit repointing every instance's forward_auth
    — carrying the fleet cookie — at that service. `certain == {0}` proves ROOT
    holds the address; only `covers` says the holder is OUR reservation.

    EXACTLY `== {uid}`, never `uid in certain`, for the SO_REUSEPORT reason
    doctor states: a second listener must share the effective uid, so "root plus
    somebody else" is not a state to permit a fleet-wide repoint on.

    IT IS A SECOND SPELLING OF doctor's `holds` ON PURPOSE — it is strictly
    broader (case 2), and doctor's line is the anchor of a mutation row. A unit
    row asserts the two agree wherever they overlap; that is cheaper than
    sharing a line whose exact text is load-bearing elsewhere."""
    holders = system.hop_holders(port)
    if holders is None:
        return False
    certain = set(holders.certain)
    if (system.unit_state(SOCKET_UNIT) == "active"
            and _covers_port(system.unit_listen_streams(SOCKET_UNIT), port)
            and certain == {0}):
        return True
    # CASE 2 IS GATED ON THERE BEING NO RESERVATION AT ALL, and leaving that gate
    # out was a live hole rather than an omission. The clause below trusts a
    # single uid — and it is the one uid on this box with a pre-authentication
    # surface. Ungated, on a MIGRATED box whose pin was moved (now a steady state
    # by design, because the write refusal parks it there): the new pin is free,
    # the service unit carries no SocketBindDeny=, so a compromised gate binds it,
    # `certain == {proxy_uid}` goes true, and the next `vide allow` repoints every
    # instance's forward_auth — and the fleet cookie — at the attacker. That is
    # the same inversion this section already refused for `bound`, arriving
    # through the other arm. "Before any reservation exists" is what the case
    # means; this is that sentence, executed.
    if loaded_reservation() != []:
        return False
    proxy_uid = system.user_uid(PROXY_USER)
    return proxy_uid is not None and certain == {proxy_uid}


class _Holder(enum.Enum):
    """WHO is on an address the fleet no longer pins.

    Four answers, because "nobody is there" and "we could not look" are not the
    same answer and exactly one of them is an alarm — and because "somebody is
    there" splits into a stranger and THIS BOX'S OWN RESERVATION, which is the
    ordinary steady state of a correctly-refused box and was being reported as
    the stranger."""
    UNKNOWN = "unknown"      # /proc could not be read — say so, never guess
    OURS = "ours"            # this box's own root-held reservation: nothing open
    STRANGER = "stranger"    # something is there and it is not our reservation
    NOBODY = "nobody"        # nothing is listening: the open door


def _who_holds(holders: system.HopHolders | None, loaded: list[str] | None,
               port: int) -> _Holder:
    """Classify the holder of `port` from facts sampled by the caller.

    PURE, and the two host reads stay with the caller, so all four states are
    reachable in a unit row without patching a host seam — the same discipline
    proxy_health applies to its own rows.

    THE BENIGN ARM IS KEYED ON `certain`, NEVER ON `on_hop`, and that is a
    security property rather than a preference. `on_hop` includes the `possible`
    bucket — `::` v6only rows any unprivileged account can create at will — so
    keying "this is our own reservation, nothing is open" on `on_hop` would let
    an attacker-supplied signal turn an open-door row into a this-is-fine row.
    That is the exact inversion HopHolders was split apart to prevent. `== {0}`
    and not `0 in certain`, for the SO_REUSEPORT reason stated at gate_is_on_hop:
    a second listener must share the effective uid, so "root plus somebody else"
    is not a state to reassure anybody about.

    `loaded` may be None (the manager could not be asked). An unaskable manager
    may not be read as "our reservation" — it is not a demonstration — so it
    falls through to STRANGER, which is the loud direction."""
    if holders is None:
        return _Holder.UNKNOWN
    if not holders.on_hop:
        return _Holder.NOBODY
    if (loaded is not None and _covers_port(loaded, port)
            and set(holders.certain) == {0}):
        return _Holder.OURS
    return _Holder.STRANGER


def pin_is_served(port: int) -> bool:
    """Is 127.0.0.1:<port> being SERVED by a legitimate holder right now?

    THE PASTE QUESTION, and it is deliberately NOT gate_is_on_hop. The two ask
    different things because their wrong answers cost different amounts:

      * gate_is_on_hop is a WRITE PERMIT — it decides whether VIDE may repoint
        every instance's forward_auth, so it insists the holder be the fleet's
        own reservation and refuses the un-migrated box the moment a reservation
        exists at all.
      * this one decides whether an OPERATOR may safely paste a block naming the
        address. Pasting is safe whenever something legitimate is answering
        there, and on the commonest box in the fleet the holder is the PROXY
        ITSELF: a converge installs and enables the reservation but deliberately
        restarts nothing, so between that converge and the next restart the
        socket unit is inactive while the running gate still holds the port it
        bound for itself. Judging the paste with the write permit told every
        one of those boxes DO NOT RE-PASTE over an ordinary content-only drift.

    `legitimate = {0} | {proxy_uid}`, the same pair doctor computes, and exactly
    `== {uid}` for the SO_REUSEPORT reason stated at gate_is_on_hop. An
    unreadable kernel is not a demonstration, so it is False — the conservative
    direction for advice, because the cost of a needless "do not paste" is one
    command and the cost of a wrong "paste it" is the fleet's login flow."""
    holders = system.hop_holders(port)
    if holders is None:
        return False
    certain = set(holders.certain)
    if certain == {0}:
        return True
    proxy_uid = system.user_uid(PROXY_USER)
    return proxy_uid is not None and certain == {proxy_uid}


def _pin_served(cfg: Config) -> bool:
    """pin_is_served against the fleet pin; an unreadable pin is not a
    demonstration either."""
    from . import sso as vide_sso
    try:
        return pin_is_served(vide_sso.fleet_port(cfg))
    except ConfigError:
        return False


def _gate_on_pin(cfg: Config) -> bool:
    """Did the move LAND — is the fleet's gate demonstrably on the pin?

    THE DIRECTION SELECTOR FOR EVERY REMEDY IN THIS SECTION. Several rows and
    warnings prescribe one of two opposite acts — "put VIDE_SSO_PROXY_PORT back"
    or "finish the move" — and which one is right is never decided by the files:
    it is decided by whether the address a fresh render would name is actually
    held. A file compare cannot see a move that COMPLETED, so on a box that
    finished the documented migration VIDE told the operator not to take its last
    step, forever.

    IT IS `gate_is_on_hop`, not a fourth spelling of doctor's `holds` triple. The
    row that says "run upgrade-sso" and the guard that decides whether
    upgrade-sso may write have to be the same predicate, or the product
    prescribes a command it then refuses. An unreadable pin is not a
    demonstration, so it is False."""
    from . import sso as vide_sso
    try:
        return gate_is_on_hop(vide_sso.fleet_port(cfg))
    except ConfigError:
        return False


def install_proxy_socket_unit(cfg: Config, ex: Executor, rep: Reporter,
                              port: int) -> bool:
    """Install units/oauth2-proxy.socket with the fleet's port substituted in.

    The same idiom as install_proxy_unit — byte-compare, write, reload, report
    whether the body moved — with one addition it cannot share: this unit is the
    only templated one in the tree, so the substitution itself has to be checked.

    `str.replace` and not `%`/`.format`: the body is full of prose comments that
    humans will edit, and a stray brace turning the fleet's gate renderer into a
    KeyError is not a failure mode worth inviting. The sentinel is asserted to
    appear EXACTLY ONCE before substituting, because a rotted sentinel would
    otherwise render a unit that still contains the literal `__VIDE_PROXY_PORT__`
    — which systemd refuses to parse, so the reservation would simply never
    exist while every VIDE verb reported success.

    Masked is refused for the reason the service's mask refusal already gives,
    with one twist that makes it sharper here: masking a SERVICE turns it off,
    but masking this SOCKET does not turn the gate off — it hands the fleet's
    authorization address to whoever binds it next, and stops the proxy taking it
    back. It is the one 'off switch' on this box that opens something.

    AND IT REFUSES ONE MORE THING: THE WRITE THAT WOULD MOVE THE RESERVED
    ADDRESS. That write is the only way VIDE can take the fleet's authorization
    hop away by its own hand, and refusing the WRITE rather than the VERB is not
    a softening — it is the mechanism. systemd re-claims a serialized listening
    descriptor by matching the ADDRESS, and skips any port that still has one, so
    the daemon-reload install_proxy_unit runs moments later is harmless for
    exactly as long as the body on disk still names the address systemd holds.
    Not writing is therefore what keeps that unavoidable reload safe. Raising
    instead would take `upgrade-sso` down with it — the one lever that ships an
    oauth2-proxy CVE-floor bump, and the lever three other messages point at.

    WHAT A daemon-reload CAN AND CANNOT CHANGE, which is the same fact read from
    the other side and the reason `Backlog=` is worth a sentence here. This
    function's reload changes what the manager BELIEVES about the unit; it can
    never change the descriptor the manager HOLDS. So every `[Socket]` property
    consumed at bind or listen time — `Backlog=`, `ReceiveBuffer=`, `KeepAlive*`,
    `FreeBind=`, `NoDelay=`, `IPTOS=`, `Priority=` — is written, reloaded, and
    NOT in effect: it lands only at a start from a closed state, i.e. a reboot or
    a deliberate stop/start, and never at a converge. The manager-side half
    (`StartLimit*`, `TriggerLimit*`, the ordering) does apply on reload, which is
    why the split matters at all rather than being a footnote."""
    if system.unit_enable_state(SOCKET_UNIT).startswith("masked"):
        raise StateError(
            f"{SOCKET_UNIT} is masked — refusing to converge over it. Masking "
            f"this unit does not switch the SSO gate off: it frees "
            f"127.0.0.1:{port}, the fleet's authorization port, for any local "
            f"account to bind. Undo it deliberately: "
            f"sudo systemctl unmask {SOCKET_UNIT}")
    src = (cfg.repo_dir / "units" / "oauth2-proxy.socket").read_text()
    if src.count(SOCKET_PORT_SENTINEL) != 1:
        raise StateError(
            f"units/oauth2-proxy.socket must contain {SOCKET_PORT_SENTINEL} "
            f"exactly once (found {src.count(SOCKET_PORT_SENTINEL)}) — refusing "
            "to install a socket unit whose listening address is not the "
            "fleet's pinned port")
    body = src.replace(SOCKET_PORT_SENTINEL, str(port))
    dest = SYSTEMD_DIR / SOCKET_UNIT
    # THE MOVE REFUSAL, AND IT SITS ABOVE THE COMPARE AND THE NARRATE ON PURPOSE:
    # it describes a STATE, not an action, so its text is the same dry-run or
    # not — and a preview that printed "would install (reserving 127.0.0.1:4199)"
    # for a write that will not happen is the preview lying about the one thing
    # previews exist for.
    #
    # `loaded` is a POSITIVE READING OF A DIFFERENT ADDRESS, never an empty one.
    # None means the manager could not be asked, and an input that cannot be read
    # may not decide — but here it may not PERMIT either, so None refuses. []
    # means there is genuinely no reservation on this box: a first install, or a
    # box where the operator removed the unit, which is exactly how the
    # documented move begins.
    #
    # It establishes presence ITSELF, and the argument this comment used to make
    # — that the destination read for the byte-compare below was free, so the
    # caller should supply it — was the defect. `_read` maps every OSError to
    # `""`, so an unreadable or zero-byte fragment arrived here as "no
    # reservation on this box": the single answer that PERMITS the move. One
    # question, one predicate, and the caller does not get to spell it.
    loaded = loaded_reservation()
    if loaded is None:
        # ITS OWN SENTENCE, because the move refusal's is checkably false here.
        # That message asserts a reservation exists and names the address to put
        # the pin back to — on a box where the read FAILED there may be no
        # reservation at all, and "put VIDE_SSO_PROXY_PORT back to the <could not
        # report> port" is an instruction nobody can follow. The refusal is still
        # right; only the words had to be separated.
        rep.warn(contract.MSG_PROXY_RESERVATION_UNREADABLE.format(
            socket_unit=SOCKET_UNIT, port=port))
        return False
    if loaded and not _covers_port(loaded, port):
        rep.warn(contract.MSG_PROXY_PIN_MOVE_REFUSED.format(
            socket_unit=SOCKET_UNIT, port=port,
            # The ADDRESS token only. `show -p Listen --value` renders
            # `127.0.0.1:4180 (Stream)`, and this string lands in the one
            # sentence the operator is meant to act on.
            address=", ".join(ln.split()[0] for ln in loaded if ln.split()),
            unit_path=SYSTEMD_DIR / SOCKET_UNIT,
            fleet_file=Path(cfg.sso_dir) / "fleet.env"))
        # False, and it is the honest value: nothing moved, so nothing is owed.
        # Returning True would put this unit into `wrote`, and _restart_reasons
        # would then demand a gate restart that lands nothing — a clause that is
        # still true after the restart it asked for, which is the one shape the
        # restart rules forbid outright.
        return False
    changed = _read(dest) != body
    if ex.narrate(f"would install {SOCKET_UNIT} (reserving 127.0.0.1:{port})"
                  if changed else f"{SOCKET_UNIT} unchanged"):
        return changed
    if changed:
        ex.atomic_write(dest, body, mode=0o644, owner=("root", "root"))
        ex.run(["systemctl", "daemon-reload"])
    return changed


def _ensure_state_home(cfg: Config, ex: Executor) -> None:
    """The fleet's state home. Asserted by EVERY writer rather than by whoever
    happens to run first — the split proved that ordering is not a thing to rely
    on. `install -d` semantics, so the modes are asserted, never inherited.

    root:root ONLY, and that is the load-bearing part. This is the assertion the
    credential writer makes immediately before it mkstemps here, and it has to
    hold on a box where no VIDE identity exists yet. The previous version of this
    helper also asserted the group-owned caddy/ child, which named `vide-proxy`
    before anything had created it: `install -d` resolves -o/-g during option
    parsing and exits 1 with `invalid group` before it creates anything, so the
    fix for the first-install crash reintroduced the first-install crash one line
    later. Naming an identity is a precondition; this helper now names none.

    The state ROOT is asserted too: on a named target nothing else creates
    /etc/vide before this point, so it would otherwise be born as an `install -d`
    ANCESTOR, taking its mode from whatever umask root happened to carry."""
    ex.ensure_dir(Path(cfg.state_dir), mode=0o755, owner=("root", "root"))
    ex.ensure_dir(Path(cfg.sso_dir), mode=0o755, owner=("root", "root"))


def _ensure_caddy_dir(cfg: Config, ex: Executor, rep: Reporter) -> None:
    """The group-readable body directory — caddy reads the rendered authz files
    out of it, which is why it is owned by the group caddy is a member of.

    It ESTABLISHES the identity it names rather than assuming some earlier caller
    did. That is the other half of the fix: a helper carrying an invisible
    "somebody ran ensure_identities first" precondition broke twice in two rounds
    on the same journey, and a split alone would have left the next caller free
    to break it a third time. ensure_identities is read-guarded, so on every run
    after the first this costs two lookups and no mutation."""
    ensure_identities(ex, rep)
    ex.ensure_dir(Path(cfg.sso_dir) / "caddy", mode=0o750, owner=("root", PROXY_GROUP))


def record_credentials(cfg: Config, ex: Executor, rep: Reporter, *,
                       client_id: str, client_secret: str) -> bool:
    """Write proxy.env. The ONLY part of provisioning that needs a secret, and
    therefore the only part still gated behind credentials_needed.

    PRESERVES any recorded cookie secret — regenerating it silently signs out
    the whole fleet, which no converge may do. A genuine first install has none,
    so one is minted here.

    Returns True iff the file changed, because oauth2-proxy reads proxy.env
    ONCE at startup: a corrected client secret that is written but not followed
    by a restart has fixed nothing, which is the whole failure the re-affirm
    lever exists to undo."""
    from . import secrets as vide_secrets
    # Its own directory, because it is now the FIRST writer. Splitting
    # ensure_proxy left the ensure_dir calls in converge_proxy and moved this
    # write ahead of them, so a first SSO install died in mkstemp on a missing
    # /etc/vide/sso. The unit tier could not see it: the fake executor's
    # atomic_write mkdirs parents and the real one does not — a fake more
    # forgiving than the product hides exactly this class. Idempotent, so
    # converge_proxy asserting the same directories again costs nothing.
    # The state HOME only — never the group-owned caddy/ child. This runs before
    # anything has created vide-proxy, and `install -d -g` on an unknown group
    # exits 1 before creating anything.
    _ensure_state_home(cfg, ex)
    recorded = parse_env_text(_read(env_path(cfg)))
    cookie_secret = (recorded.get("OAUTH2_PROXY_COOKIE_SECRET")
                     or vide_secrets.gen_cookie_secret())
    body = render_proxy_env(client_id, client_secret, cookie_secret)
    changed = _read(env_path(cfg)) != body
    ex.atomic_write(env_path(cfg), body, mode=0o600, owner=("root", "root"))
    return changed


def _repair_toml_posture(cfg: Config, ex: Executor, rep: Reporter) -> None:
    """Put proxy.toml's mode and owner back if they drifted — WITHOUT rewriting
    the file.

    The separation is the whole design. proxy.toml's mtime is an input to
    `upgrade-sso`'s restart decision (see _gate_inputs), so re-writing it to fix
    a permission bit would restamp it newer than the running gate and bounce the
    fleet's sole authorization gate for a run in which no byte changed — the
    exact defect the conditional write above exists to remove. chmod(2) and
    chown(2) move ctime and leave mtime alone, so this repair is invisible to
    that decision.

    CONDITIONAL, so a clean box pays nothing and a drifted one says what it
    fixed. Silence on a healthy box is what keeps the warning readable on an
    unhealthy one.

    WHAT IT DEFENDS. A widening — 0660, or an owner change to the proxy's own
    account — is silent everywhere else in this tree: nothing reads this file's
    mode, and the byte compare above still matches, so nothing repairs it and
    nothing reports it. What it would buy is WRITE access for the one account on
    the box with a pre-authentication surface facing the internet, over a file
    whose `trusted_proxy_ips` line is the CVE-2026-40575 mitigation and whose
    security depends on which keys are ABSENT.

    Only root can create the drift (chmod needs ownership or CAP_FOWNER), so
    this is operator error, a restore-from-backup or third-party config
    management — not an attacker's opening move. It is repaired because the
    repair is free, not because the likelihood is high."""
    path = toml_path(cfg)
    facts = system.path_facts(path)
    if facts is None:
        return                      # not provisioned; nothing to assert
    if facts.is_symlink:
        # REFUSE, LOUDLY, AND CHANGE NOTHING. path_facts is an lstat — it
        # answers about the LINK — while chmod and chown DEREFERENCE, so a
        # repair here would read one file's posture and rewrite another's. The
        # link's own mode is 0777 by construction, so the comparison below can
        # never be satisfied: this would warn and mutate on every converge,
        # forever, while the target drifted freely. And the state itself is the
        # attack lstat exists to catch — root's own config replaced by a pointer
        # into somewhere writable — so it is a finding, not a thing to heal.
        rep.warn(f"{path} is a SYMLINK, not a regular file. VIDE will not chmod "
                 f"or chown through it: that would change a file it did not "
                 f"inspect. The shared proxy loads this path as root — replace "
                 f"the link with the real file, or say why it is there.")
        return
    entry = system.group_entry(PROXY_USER)
    want_gid = entry[0] if entry is not None else None
    if facts.mode != TOML_MODE:
        rep.warn(f"{path} was {facts.mode:04o}, not {TOML_MODE:04o} — restoring. "
                 f"A wider mode on this file grants write access to the shared "
                 f"proxy's own account over the trusted-proxy CIDR that fronts "
                 f"every SSO instance on this box.")
        ex.run(["chmod", f"{TOML_MODE:04o}", str(path)])
    if facts.uid != 0 or (want_gid is not None and facts.gid != want_gid):
        rep.warn(f"{path} was owned by {facts.uid}:{facts.gid}, not "
                 f"root:{PROXY_USER} — restoring.")
        ex.run(["chown", f"root:{PROXY_USER}", str(path)])


def converge_proxy(cfg: Config, ex: Executor, rep: Reporter, *,
                   parent_domain: str, was_active: bool) -> str:
    """Everything about the shared proxy that needs NO secret — and therefore
    runs on EVERY SSO apply, not only the first.

    `was_active` is a REQUIRED keyword, deliberately without a default. It is
    "was something already serving before this run touched anything", and it must
    be sampled by the caller before ITS first write — this function is already
    past that point. A default would let a future caller take the observation
    late, which is precisely the bug: sampling after `enable --now` says only
    "we just started it". It was an inline `systemctl is-active` here, which also
    made one unit row and its mutation proof properties of whether the box
    running the tier happened to host a live proxy rather than of this tree.

    This is the fix for the fleet's root of trust having been provision-once:
    the unit's whole hardening surface and every line of proxy.toml (including
    trusted_proxy_ips, the mitigation the CVE floor names) used to describe the
    repository rather than any running system, and nothing detected the drift.
    sysd.install_unit has re-asserted the code-server template on every converge
    since slice 1; the correct idiom was simply never applied here.

    It does NOT restart. A converge is usually run FOR SOMEONE ELSE — installing
    user B must never be able to take the fleet's auth gate down for A, C and D,
    and a failed restart does exactly that. `daemon-reload` alone lands the half
    that protects an installed fleet from a post-reboot lockout (StartLimit*,
    Restart*, the ordering: manager-side, consulted at the next restart
    decision); the exec-context hardening and proxy.toml are restart-gated and
    land at the next explicit lever. The pending state is REPORTED, not
    recorded — see proxy_health.

    Returns the shared auth-subdomain Caddy block for the CALLER to print;
    stdout is install_flow's channel and this module must not write to it."""
    ensure_identities(ex, rep)
    _ensure_state_home(cfg, ex)
    _ensure_caddy_dir(cfg, ex, rep)
    # was_active arrives from the caller, sampled before ITS first write. "The
    # running process predates its config" is only a statement about a process
    # that was already running: on a first install every file is trivially
    # "changed", and reporting a pending restart for a proxy that is about to
    # start fresh is noise the operator learns to ignore.

    # The binary only when actually missing: a torn proxy.toml must not trigger
    # a needless re-download.
    if not current_link(cfg).exists():
        ver = resolve_version(cfg)
        rep.info(f"installing oauth2-proxy {ver}")
        sha = install_version(cfg, ex, rep, ver)
        flip_current(cfg, ex, ver)
        record_version(cfg, ex, ver, sha)
        prune(cfg, ex)

    # The union seed goes through sso.py (its file, its lock): a blind
    # write-empty-if-missing here raced a concurrent `vide allow` between the
    # exists() check and the write, truncating a just-populated union —
    # fail-closed fleet-wide 401s until the next re-render.
    # Backfill the fleet pins on a box provisioned before they existed: it has
    # been running on these values all along, so recording them changes nothing
    # today and stops a .env row changing them tomorrow. Without this, every
    # pre-existing fleet keeps reading the issuer and port live — which is the
    # hole, just on the boxes that already exist.
    from . import sso as vide_sso
    pins = vide_sso.fleet_pins(cfg)
    if pins and not (pins.get("VIDE_SSO_ISSUER_URL") and pins.get("VIDE_SSO_PROXY_PORT")):
        rep.info("recording the fleet's issuer and proxy port in fleet.env "
                 "(previously read live from config on every converge)")
        vide_sso.persist_fleet(cfg, ex, parent_domain,
                               issuer=cfg.sso_issuer_url.rstrip("/"),
                               proxy_port=cfg.sso_proxy_port)

    # THE RESERVATION GOES IN FIRST — BEFORE proxy.toml SAYS `fd:3`.
    # The order is the whole content of this block. proxy.toml naming an
    # inherited descriptor while no socket unit exists is a box that keeps
    # serving normally and then, unattended, fails to start its authorization
    # gate at the next reboot: the proxy would exec, find no LISTEN_FDS, and
    # crash-loop. The old order wrote the toml first and installed units after,
    # with a raising mask-refusal in between — so that state was not theoretical,
    # it was one masked unit away.
    port = vide_sso.fleet_port(cfg)
    socket_changed = install_proxy_socket_unit(cfg, ex, rep, port)
    # BOTH UNIT FILES ON DISK BEFORE EITHER IS STARTED, which is the same
    # principle the paragraph above states, applied one hop further. A socket
    # unit that is listening while the service it TRIGGERS does not yet exist
    # answers a connection by trying to activate nothing: systemd fails the
    # socket with SOCKET_FAILURE_RESOURCES and a failed socket unit closes its
    # descriptors — i.e. hands the fleet's authorization port straight back to
    # the box, in the middle of an install. The later `enable --now` does pull
    # the failed socket back through `Requires=`, so the window is recoverable
    # rather than fatal; it is also free to close, and this is where it closes.
    unit_changed = install_proxy_unit(cfg, ex, rep)
    # `enable` ALWAYS, `--now` never. Enabling is what puts the reservation into
    # the boot transaction at sockets.target, which is the window this whole unit
    # exists for and the one no restart can substitute for. Starting is a
    # different question, below. It also repairs the dangling
    # sockets.target.wants symlink the documented `rm` leaves behind, which is
    # why it is not conditional on the write having happened.
    #
    # GATED ON THE FRAGMENT EXISTING, and only because the refusal above can now
    # decline with no file on disk (the operator removed the unit and has not
    # reloaded, so the manager still holds the address and loaded_reservation
    # refuses on the manager's word). `systemctl enable` on an absent fragment is
    # a hard error on every supported systemd, so leaving this unconditional
    # would kill the run two lines after a refusal whose whole contract is
    # "nothing was written; the rest of this run continues".
    #
    # `ex.dry_run` FIRST, because a preview writes nothing: on a dry first
    # install the fragment is legitimately absent at this instant and the real
    # run WILL enable it, so testing the file alone would drop the step from
    # every preview of the commonest path — a preview lying about what the run
    # does, which is the one thing previews exist not to do.
    if ex.dry_run or _reservation_unit_present():
        ex.run(["systemctl", "enable", SOCKET_UNIT])
    if not was_active:
        # Nothing was serving when this run began, so the port is free and the
        # socket can take it now — a first install gets the reservation
        # immediately rather than at some later restart.
        #
        # Tolerated failing, deliberately. A converge runs FOR SOMEONE ELSE, and
        # a port held by something at this instant must not abort user B's
        # install. Warn and let doctor carry the red: the BYPASS ladder is a
        # better place for that diagnosis than a traceback out of an install.
        try:
            ex.run(["systemctl", "start", SOCKET_UNIT])
        except CommandFailed:
            rep.warn(contract.MSG_PROXY_PORT_UNRESERVED.format(
                socket_unit=SOCKET_UNIT, state="unable to bind", port=port))
    elif not ex.dry_run and system.unit_state(SOCKET_UNIT) != "active":
        # was_active AND the reservation is not up: the RUNNING proxy is still
        # bound to the port itself, so the socket unit cannot bind it and
        # starting it here would fail for a reason that is not a fault. The
        # reservation lands at the next gate restart. Say so — an operator who
        # upgrades and reads "Install complete" would otherwise believe the fix
        # is in effect on this box when it is not, and that is exactly the
        # silence-that-reads-as-health this tree keeps paying for.
        #
        # THE SECOND CONDITION IS NOT A REFINEMENT, IT IS THE DIFFERENCE BETWEEN
        # AN ALARM AND NOISE. `was_active` alone is True on a MIGRATED box too —
        # the service is running, on the inherited descriptor — so every
        # `sudo ./install.sh` on a converged fleet printed this, forever, about
        # a box where systemd has held the address since sockets.target. And it
        # is the same string doctor uses as its migration-day red row, which
        # doctor reaches only after ruling out `holds`, NOT BOUND and DRIFT: on
        # one box, in one minute, install.sh said NOT YET RESERVED while
        # `vide doctor` said reserved and exited green. A migration alarm that
        # keeps firing after the migration is a token that stops meaning
        # anything.
        #
        # In the NEGATIVE only, which is the discipline _restart_reasons states
        # for this same reader: `active` is a weak positive (a bare
        # daemon-reload can leave a socket unit active holding nothing), so it
        # is used here to SUPPRESS a warning that doctor will still raise as
        # NOT BOUND, never to assert that the reservation is in effect.
        #
        # AND THE MESSAGE'S FIRST CLAUSE IS CHECKED BEFORE IT IS MADE. It says
        # "the running proxy still holds 127.0.0.1:{port} itself" and then
        # prescribes a restart on the strength of it. On a box whose pin was
        # hand-edited that claim is false — the gate is serving the OLD address —
        # and both remedies it names (upgrade-sso, a reboot) would then MOVE the
        # fleet's authorization hop rather than land a reservation on it. The
        # kernel is asked rather than assumed, which is this file's own rule.
        #
        # `on_hop`, NOT `certain`: to claim the pin is NOT where the gate is, any
        # listener at all on that address must suppress the claim. And `None`
        # suppresses it too — an unreadable kernel keeps the status quo message
        # rather than escalating on a measurement that never happened.
        holders = system.hop_holders(port)
        rep.warn((contract.MSG_PROXY_RESERVATION_OFF_PIN
                  if holders is not None and not holders.on_hop
                  else contract.MSG_PROXY_RESERVATION_PENDING).format(
                      socket_unit=SOCKET_UNIT, port=port))
    # A SEPARATE STATEMENT, NOT A THIRD ARM, and the reason is mechanical rather
    # than stylistic. `systemctl start` on an already-active unit returns
    # -EALREADY and the caller reports success, so the start in the `not
    # was_active` branch above is a NO-OP on a reload-orphaned socket unit: it
    # neither rebinds nor fails. The orphan is therefore reachable from BOTH
    # branches, and an `elif` would see half of them.
    #
    # SAMPLED AFTER THIS RUN'S OWN enable/start, which is why the unit state is
    # read again here instead of being hoisted: on the `not was_active` path a
    # start happened in between, and one sample cannot honestly serve both sides
    # of it.
    #
    # THE UNIT SAYING `active` IS A WEAK POSITIVE — a socket unit whose address
    # changed under a reload stays active holding nothing — so it is paired with
    # the kernel here exactly as doctor pairs them. `covers` is a required
    # conjunct: active-and-NOT-covering is DRIFT, whose remedy is not a restart,
    # and on that box the refusal in install_proxy_socket_unit has already spoken
    # once in this same run.
    #
    # `certain`, not `on_hop`: this unit binds ONE literal v4 address, so its own
    # descriptor can only ever appear in `certain`. A `::` row — which any local
    # account can create — may not be allowed to silence the absence of the
    # reservation. And `holders is None` may not decide at all.
    if not ex.dry_run and system.unit_state(SOCKET_UNIT) == "active":
        held = system.hop_holders(port)
        if (_covers_port(system.unit_listen_streams(SOCKET_UNIT), port)
                and held is not None and 0 not in held.certain):
            rep.warn(contract.MSG_PROXY_PORT_NOT_BOUND.format(
                socket_unit=SOCKET_UNIT, unit=UNIT, port=port))

    body = render_proxy_toml(cfg, parent_domain)
    toml_changed = _read(toml_path(cfg)) != body
    # CONDITIONAL, AND THE CONDITION IS THE WHOLE POINT — THIS FILE'S MTIME IS AN
    # INPUT to _restart_reasons, through _gate_inputs. Written unconditionally, every
    # `sudo ./install.sh` on an SSO box moved that mtime whether or not a byte
    # had changed, so `stale` was True on the next `sudo vide upgrade-sso` and
    # that verb restarted the fleet's sole authorization gate for a run in which
    # nothing had changed. Two mutation rows guard it — one on the mtime, one on
    # what the moved mtime costs the NEXT verb — arriving
    # through the WRITER instead of the predicate, and on a converge that had
    # itself correctly decided to stay quiet, since MSG_PROXY_RESTART_PENDING
    # below is gated on these same byte-compares. The other two files in that
    # comparison, both units, have always been conditional; this is the third.
    #
    # WHAT THE CONDITION COSTS, AND WHY THE COST IS PAID BACK ONE LINE LOWER
    # RATHER THAN ACCEPTED. An unconditional write also re-asserted 0640
    # root:vide-oauth2 on every converge, and making the write conditional
    # retired that repair. The argument for accepting the loss was that the
    # drift is fail-LOUD — a proxy.toml its own user cannot read means the unit
    # does not start, which is doctor's first line — and that argument holds in
    # ONE DIRECTION ONLY. A NARROWING is loud. A WIDENING is silent, and it is
    # the direction that matters: 0660, or an owner change to vide-oauth2, hands
    # WRITE access to the one account on this box with a pre-authentication
    # surface facing the internet. This file carries trusted_proxy_ips — the
    # CVE-2026-40575 mitigation the version floor exists for — and the
    # forbidden-key list, and BOTH are properties of the RENDERER rather than of
    # the bytes on disk the moment something else can write them.
    #
    # So the repair comes back, as a posture repair and not as a write. chmod
    # and chown move ctime and NOT mtime, so it costs nothing against the rule
    # below. What may never come back is an unconditional atomic_write.
    #
    # The rule this establishes: A FILE WHOSE MTIME IS READ AS A DECISION INPUT
    # IS WRITTEN ONLY WHEN ITS CONTENT CHANGES. All three inputs to
    # _gate_inputs now obey it, and no other file in the tree is
    # in that set. `upgrade_sso` carries the same discipline on the same file —
    # tidy one and go looking for the other.
    if toml_changed:
        ex.atomic_write(toml_path(cfg), body, mode=TOML_MODE,
                        owner=("root", PROXY_USER))
    _repair_toml_posture(cfg, ex, rep)
    vide_sso.seed_union(cfg, ex)

    # `enable --now` starts a STOPPED unit and is a no-op on a running one —
    # which is exactly right here: it heals the enable that never happened
    # without touching a healthy fleet.
    #
    # TOLERATED ON EXACTLY ONE BOX, and a tier row found this rather than a
    # reading. The service carries `Requires=<socket unit>`, so when the operator
    # has removed the socket FRAGMENT without a daemon-reload — the state the
    # move refusal above declines to write over, because the unit is still
    # loaded and still holding the address — systemd resolves that Requires=
    # against a unit file that is gone and exits 5, "unit not found". The
    # refusal's whole contract is "nothing was written; the rest of this run
    # continues", and dying three statements later broke it just as surely as an
    # unguarded `enable` on the socket unit would have.
    #
    # NARROW, and deliberately not a bare try/except: the failure is swallowed
    # only when the fragment really is absent, so an `enable --now` that fails
    # for any other reason still takes the run down as before.
    try:
        ex.run(["systemctl", "enable", "--now", UNIT])
    except CommandFailed:
        if _reservation_unit_present():
            raise
        rep.warn(contract.MSG_PROXY_RESERVATION_FRAGMENT_GONE.format(
            socket_unit=SOCKET_UNIT, unit=UNIT,
            unit_path=SYSTEMD_DIR / SOCKET_UNIT))
    ensure_caddy_membership(ex, rep)

    if (toml_changed or unit_changed or socket_changed) and was_active and not ex.dry_run:
        rep.warn(contract.MSG_PROXY_RESTART_PENDING)

    return render_auth_host(cfg, ex, rep, parent_domain)


def render_auth_host(cfg: Config, ex: Executor, rep: Reporter,
                     parent_domain: str) -> str:
    """Write the auth host's body and its static pages, reload Caddy if either
    moved, and return the three-line block the operator pastes.

    CALLED FROM TWO PLACES AND THAT IS THE POINT. converge_proxy runs it while
    provisioning; upgrade_sso runs it on the branch where the proxy is ALREADY at
    the pinned version and no converge happens — the branch where a box has gone
    longest without this file being touched. A warning used to stand there
    instead, because the artifact was one VIDE could not re-land. It can now, so
    it does; a warning whose remedy the tool owns is a chore handed to a human.

    THE POLICY THAT INVERTED HERE. This file used to be written only when absent:
    it was the copy the operator had pasted FROM, and refreshing it would have
    made _auth_block_drift compare equal forever — a working security control
    disabled while its code stayed in place. The operator no longer pastes it.
    They paste a site header and an `import` of this path, so the file IS the live
    config and VIDE owns it exactly as it owns the per-instance bodies. Writing it
    every run is therefore not the hazard it was; refusing to would be, because it
    would leave the fleet's login flow frozen at whatever the box was first
    installed with.

    A WRITE ALONE CHANGES NOTHING and that is the trap the reload exists for.
    Caddy holds its config in memory; a re-rendered file it never re-reads is a
    silent no-op, and the caller would report success over a login host still
    running the old body. When the paste was verbatim the operator's own reload
    closed that gap. Nothing else does now — so the same lever `allow`/`revoke`
    already pull is pulled here, and only when something actually changed."""
    from . import caddy
    from . import sso as _sso_for_port
    pin = _sso_for_port.fleet_port(cfg)
    block = caddy.emit_auth_block(parent_domain, sso_dir=str(cfg.sso_dir))
    body = caddy.emit_auth_body(parent_domain, pin, sso_dir=str(cfg.sso_dir))
    persisted = Path(cfg.sso_dir) / "caddy" / "auth.caddy"
    pages_dir = Path(cfg.sso_dir) / "caddy" / caddy.AUTH_PAGES_DIRNAME
    # `.strip()` ON BOTH SIDES, kept from the version this replaced: a copy
    # differing by one trailing newline would otherwise reload Caddy on EVERY
    # converge, which is the same permanently-on nuisance in a new costume.
    # AND THE SAME LOCK THE PER-INSTANCE BODIES CARRY, because this file just
    # joined their class. Rewriting it is now a write that can REPOINT the
    # fleet's authorization sub-request, and on a moved-pin box that is the exact
    # harm this release's refusals exist to prevent: install_proxy_socket_unit
    # declines to move the reservation, so the gate stays on the OLD address —
    # and a converge that cheerfully re-rendered this body at the NEW pin would
    # aim the login host at a port nobody serves. VIDE would take the fleet's
    # login down by its own hand, out of the run written to stop exactly that.
    #
    # THE PERMIT IS gate_is_on_hop, NOT pin_is_served: this is a write permit,
    # and it may only answer in the affirmative direction. Unproven is refusal.
    #
    # A CONTENT-ONLY CHANGE IS NOT A REPOINT and must not be gated, or every
    # ordinary upgrade — a new directive, a corrected timeout — would refuse on
    # any box whose gate happens to be down. So the comparison is on the HOP,
    # read with the one parser allowed to read this format. An absent file is a
    # first install: nothing to break, nothing to protect.
    on_disk = _read(persisted)
    from . import caddy as _caddy_hops
    old_hops = _caddy_hops.hops(on_disk)
    repoint = bool(on_disk) and old_hops and old_hops != _caddy_hops.hops(body)
    if repoint and not gate_is_on_hop(pin):
        if not ex.dry_run:
            rep.warn(contract.MSG_AUTH_BODY_REPOINT_REFUSED.format(
                path=persisted, port=pin,
                held=", ".join(str(h) for h in sorted(old_hops))))
        return block
    changed = on_disk.strip() != body.strip()
    ex.atomic_write(persisted, body, mode=0o644, owner=("root", "root"))
    # 0750/0640 root:vide-proxy, matching the per-instance bodies beside them:
    # the DIRECTORY is the access gate here, and caddy reaches these only through
    # its membership of that group. atomic_write mkstemps into dest.parent, so
    # the directory has to exist before the first page is written.
    ex.ensure_dir(pages_dir, mode=0o750, owner=("root", PROXY_GROUP))
    for name, html in caddy.auth_pages(parent_domain).items():
        page = pages_dir / name
        changed = changed or _read(page).strip() != html.strip()
        ex.atomic_write(page, html, mode=0o640, owner=("root", PROXY_GROUP))
    if changed and not ex.dry_run:
        # fail_soft: a Caddy that will not reload is the operator's own config
        # to fix, and failing the converge over it would strand the box halfway
        # through a provisioning run for a reason VIDE did not cause.
        _sso_for_port.reload_caddy(ex, rep, fail_soft=True)
    return block


def rotate_sso(cfg: Config, ex: Executor, rep: Reporter) -> None:
    """Regenerate the cookie secret, rewrite proxy.env, restart. Keeps a .prev
    and auto-restores on a failed post-restart health check — a rejected secret
    must not become a fleet-wide outage."""
    from . import secrets as vide_secrets
    if not provisioned(cfg):
        raise StateError("no SSO proxy provisioned — nothing to rotate")
    cur = parse_env_text(_read(env_path(cfg)))
    client_id = cur.get("OAUTH2_PROXY_CLIENT_ID", "")
    client_secret = cur.get("OAUTH2_PROXY_CLIENT_SECRET", "")
    prev = env_path(cfg).with_suffix(".env.prev")
    if not ex.dry_run:
        ex.atomic_write(prev, _read(env_path(cfg)), mode=0o600, owner=("root", "root"))
    new_secret = vide_secrets.gen_cookie_secret()
    ex.atomic_write(env_path(cfg),
                    render_proxy_env(client_id, client_secret, new_secret),
                    mode=0o600, owner=("root", "root"))
    ex.run(["systemctl", "restart", UNIT])
    if not ex.dry_run and not _proxy_pings(cfg):
        rep.warn("proxy did not come back after rotation — restoring the previous "
                 "cookie secret")
        ex.atomic_write(env_path(cfg), _read(prev), mode=0o600, owner=("root", "root"))
        # Restored — the copy has served its purpose, and it holds the live
        # client secret. Remove it BEFORE the restart: a raising restart (a
        # start-rate-limited unit after the bad secret crash-looped it) must
        # not leave the secret material behind.
        ex.run(["rm", "-f", str(prev)])
        ex.run(["systemctl", "restart", UNIT])
        raise StateError("rotate-sso failed: the proxy rejected the new secret "
                         "(restored the previous one)")
    # The .prev holds the OLD cookie secret + the live client secret — delete it
    # once the new secret is proven good, so it does not linger on disk.
    ex.run(["rm", "-f", str(prev)])
    rep.info("rotated the shared SSO cookie secret; all sessions are signed out")
    # The rotation is the stolen-cookie kill switch, so it is used under stress —
    # and its own recovery path shows a "potential attack" 403 once. Warn BEFORE
    # the operator meets it, and name the lever that clears it.
    from . import sso as vide_sso
    domain = vide_sso.parent_domain(cfg) or "<DOMAIN>"
    rep.warn(contract.MSG_ROTATE_RETRY.format(
        url=contract.SIGNOUT_URL.format(domain=domain)))


def upgrade_sso(cfg: Config, ex: Executor, rep: Reporter) -> None:
    if not provisioned(cfg):
        raise StateError("no SSO proxy provisioned — nothing to upgrade")
    # The socket unit is asserted on BOTH paths through this verb, before either
    # branches. This is the lever that lands the port reservation on an existing
    # fleet — a converge installs and enables it but never restarts the gate, so
    # until something restarts the service the running proxy still holds the port
    # itself and the reservation is inert. Asserting it here, ahead of the
    # version test, means "the binary happens to be current" cannot be a reason
    # the box never gets it. The restart that follows on either path is what
    # actually hands the address to systemd.
    from . import sso as vide_sso
    socket_changed = install_proxy_socket_unit(
        cfg, ex, rep, vide_sso.fleet_port(cfg))
    # Gated for the reason given at the converge's own `enable`: a refusal can
    # now leave the box with no fragment, and enabling an absent one is fatal.
    if ex.dry_run or _reservation_unit_present():
        ex.run(["systemctl", "enable", SOCKET_UNIT])
    # THE TOML AND THE SERVICE UNIT ARE ASSERTED ON BOTH PATHS TOO, above the
    # version test, and leaving them inside the "already current" branch was a
    # latent fleet-wide outage rather than an untidiness. On a version BUMP the
    # box would end up with the socket unit enabled while proxy.toml still told
    # the proxy to bind for itself and the service unit still had no
    # `Requires=`. At the next boot the socket takes the address at
    # sockets.target, the proxy gets EADDRINUSE, and — with no start limiter to
    # stop it — crash-loops forever: the gate down, unattended, on a box whose
    # upgrade reported success. `docs/sso.md` names this verb as the lever after
    # a `git pull`, so the version-bump path is the ordinary one, not the corner.
    parent = vide_sso.parent_domain(cfg)
    toml_changed = False
    if parent:
        body = render_proxy_toml(cfg, parent)
        toml_changed = _read(toml_path(cfg)) != body
        if toml_changed:
            ex.atomic_write(toml_path(cfg), body, mode=TOML_MODE,
                            owner=("root", PROXY_USER))
    unit_changed = install_proxy_unit(cfg, ex, rep)
    ver = resolve_version(cfg)
    if ver == installed_version(cfg):
        # …but the unit OR proxy.toml may still be behind. A converge re-asserts
        # both and deliberately does not restart (installing user B must not drop
        # the gate for A, C and D), so this verb is where a changed exec-context
        # or a changed config actually lands. Widened for that: it is the
        # operator's explicit "apply it now", and refusing because the binary
        # happens to be current would leave the hardening permanently unapplied
        # on a box that never sees a new release.
        #
        # BOTH, not just the unit: MSG_PROXY_RESTART_PENDING sends the operator
        # here, and a run that re-installed the unit while ignoring proxy.toml
        # would report success and change nothing for a config-only drift.
        # ONE QUESTION, ASKED ONCE: is the process serving the fleet's gate right
        # now the one this box's current state describes — started from the files
        # on disk, and holding the port through the reservation rather than on its
        # own? Every clause in _restart_reasons is annotated with which of TWO
        # failure directions it prevents, because this decision has now been wrong
        # in both.
        #
        # DIRECTION 1 — THE NO-OP. Three byte-compares were once the whole test
        # (`install_proxy_unit(...) or toml_changed or socket_changed`). The
        # documented order is "install this version, then run upgrade-sso", so the
        # converge has ALREADY written all three by the time an operator gets
        # here: every compare said "unchanged", this verb printed "unit and config
        # current", nothing restarted, and the reservation could never land on any
        # box in the fleet — while doctor went on naming this very command.
        #
        # DIRECTION 2 — THE BOUNCE. The fix for that compared proxy.toml's mtime
        # against the running process, while converge_proxy rewrote proxy.toml
        # UNCONDITIONALLY. The mtime moved on every converge, so this verb bounced
        # the fleet's sole authorization gate after every unrelated install. A
        # lever three messages point at cannot be one that costs an outage to pull.
        #
        # THE RULE OUT OF BOTH: every clause must be FALSE immediately after the
        # restart it demanded. A clause that is not self-clearing is not a reason
        # to restart, it is a loop — which is why _gate_inputs carries an entry
        # requirement about its writers, and why converge_proxy's write is
        # conditional.
        #
        # AND: AN INPUT THAT CANNOT BE READ MAY NOT DECIDE. `unknown` is not "no".
        # An unreadable input voting restart bounces the gate forever on a box
        # with a wedged systemctl (direction 2); voting "current" silently is
        # direction 1 wearing the words of health. So it is REPORTED, and the
        # no-op is safe only because it is loud — and because `wrote` needs no
        # host read at all.
        gate_state = system.unit_state(UNIT)
        pid = system.unit_main_pid(UNIT)
        started = system.proc_start_realtime(pid) if pid is not None else None
        # Sampled AFTER this run's own writes above, deliberately: the two clauses
        # then agree on a readable box, and `wrote` is what remains when they
        # cannot be read.
        written = {str(p): system.path_mtime(p) for p in _gate_inputs(cfg)}
        socket_state = system.unit_state(SOCKET_UNIT)
        # FULL PATHS, the same identifiers `written` uses. They used to be unit
        # NAMES here and paths there, so a run that tripped both clauses named
        # the same file two different ways in one warning.
        #
        # EMPTY UNDER --dry-run, and that is not tidiness: install_proxy_unit
        # returns `changed` before its dry-run bail, on purpose, so without this
        # guard a preview announced "this run rewrote …" about writes that did
        # not happen — in the past tense. converge_proxy guards both of its
        # equivalent warnings the same way.
        wrote = [] if ex.dry_run else [
            str(p) for p, moved in ((SYSTEMD_DIR / UNIT, unit_changed),
                                    (SYSTEMD_DIR / SOCKET_UNIT, socket_changed),
                                    (toml_path(cfg), toml_changed)) if moved]
        reasons, unreadable = _restart_reasons(
            wrote=wrote, gate_state=gate_state, pid=pid, started=started,
            written=written, socket_state=socket_state)
        if reasons:
            # SAY WHY. The bounce-every-run defect was invisible for a round
            # because this warning never named the clause that fired; an operator
            # who saw "proxy.toml was written after the running proxy started" on
            # a box where nothing had changed would have reported it on day one.
            rep.warn("restarting the shared proxy to apply it (" +
                     "; ".join(reasons) + ") — this is what hands the fleet's "
                     "authorization port to systemd, so from here on nothing else "
                     "can bind it. " + _inflight_sentence(socket_state))
            ex.run(["systemctl", "restart", UNIT])
            _verify_proxy_came_back(cfg, ex, rep)
        elif unreadable:
            # A NO-OP THAT SPEAKS. Nothing observable said restart, but at least
            # one input did not settle the question — and the operator, not this
            # verb, is the one who knows whether they changed anything.
            #
            # "DID NOT SETTLE IT", NOT "COULD NOT BE READ", and the distinction
            # is this verb's own rule applied to its own output. Some entries
            # here really are failed reads (a wedged systemctl, an unreadable
            # /proc); others are perfectly successful reads of a state this
            # decision declines to act on — `activating`, `deactivating`,
            # `reloading`. Calling the second kind unreadable points the
            # operator at the wrong organ, and on THIS tree that is not a corner
            # case: the service disables its start limiter on purpose, so
            # `activating (auto-restart)` is where a permanently broken gate
            # RESTS. The one person most likely to read this sentence is the one
            # whose gate is crash-looping.
            rep.warn("not restarting the shared proxy: nothing observable says it "
                     "is behind, and these inputs did not settle it (" +
                     "; ".join(unreadable) + "). If you changed the unit or "
                     f"proxy.toml, apply it yourself: sudo systemctl restart {UNIT}")
        else:
            # SAY WHAT WAS OBSERVED AND NOT ONE WORD MORE. Two earlier drafts
            # over-claimed here: "the port reservation is in effect", then
            # "{SOCKET_UNIT} holds the port". Both assert that the ADDRESS is
            # held; all this verb established is the manager's word that the
            # unit is active — which _restart_reasons calls a weak positive nine
            # lines from here, because a bare daemon-reload can leave a socket
            # unit active holding nothing. Doctor answers the holder question,
            # with a kernel-verified uid, and this verb does not read it.
            rep.info(f"oauth2-proxy already at {ver}; the running gate started "
                     f"after its unit and config, and {SOCKET_UNIT} is active "
                     f"(whether the address is really held is `vide doctor`'s row)")
        # UNCONDITIONAL, and outside the branch on purpose: the per-instance
        # authz bodies can be stale even when the unit and proxy.toml are
        # current, because nothing re-renders them on a converge (see
        # sso.rerender_bodies). "Already at the pinned version" is exactly the
        # box where that has been true longest.
        vide_sso.rerender_bodies(cfg, ex, rep)
        # RE-LAND the auth host rather than warn that it is behind. This is the
        # branch where the proxy is already at the pinned version, so no converge
        # runs and nothing else in this verb touches that file — which is exactly
        # why a warning used to sit here. The warning was correct only while the
        # file was the operator's; now it is VIDE's, and the fix is one call.
        _parent = vide_sso.parent_domain(cfg)
        if _parent:
            render_auth_host(cfg, ex, rep, _parent)
        return
    rep.info(f"upgrading oauth2-proxy {installed_version(cfg)} -> {ver}")
    rep.warn("this RESTARTS the shared proxy — in-flight requests briefly fail; "
             "existing sessions survive (the cookie secret is unchanged)")
    sha = install_version(cfg, ex, rep, ver)
    flip_current(cfg, ex, ver)
    record_version(cfg, ex, ver, sha)
    ex.run(["systemctl", "restart", UNIT])
    # Before prune, never after: prune keeps exactly one rollback version, and
    # running it on the way out of a failed upgrade would delete the one thing the
    # operator needs. _verify_proxy_came_back raises, so this ordering is the
    # guarantee and not a convention.
    _verify_proxy_came_back(cfg, ex, rep)
    prune(cfg, ex)
    vide_sso.rerender_bodies(cfg, ex, rep)
    _parent = vide_sso.parent_domain(cfg)
    if _parent:
        render_auth_host(cfg, ex, rep, _parent)


def _gate_inputs(cfg: Config) -> list[Path]:
    """What the shared proxy reads ONCE, at exec — and therefore the complete set
    of files whose movement obliges a gate restart.

    THE ENTRY REQUIREMENT, because getting it wrong is how this verb learned to
    bounce the fleet: a path may join this list only if its writers move its
    mtime when, AND ONLY WHEN, its content moves. A file rewritten
    unconditionally has an mtime that lies about when its content changed, and a
    restart decision built on that mtime is a restart on every run.

    Two exclusions, both deliberate and both invisible from here otherwise:
      * the union authenticated-emails file is HOT-RELOADED by the proxy —
        listing it would make every `vide allow` owe the fleet a gate restart;
      * proxy.env IS read once at exec, but its writers restart the gate
        themselves (install_flow, rotate_sso) and record_credentials rewrites it
        unconditionally — so listing it would re-import the exact defect the
        entry requirement above exists to keep out."""
    return [SYSTEMD_DIR / UNIT,
            SYSTEMD_DIR / SOCKET_UNIT,
            toml_path(cfg)]


def _inflight_sentence(socket_state: str) -> str:
    """What a restart of the gate costs, said accurately for THIS box. On a
    migrated box systemd holds the listening socket, so connections are accepted
    and queued across the restart; on an un-migrated one the process owns the
    address and they fail. The two restart warnings used to disagree about the
    same operation, and this is the sentence an operator reads before pressing
    enter on the fleet's only auth gate."""
    if socket_state == "active":
        return ("In-flight requests queue rather than fail; nobody is signed out, "
                "the cookie secret is unchanged.")
    if socket_state == "unknown":
        # THREE-WAY, because this reader can fail and a warning may not assert a
        # state the same run refused to decide from. The unreadable arm hedges
        # rather than claiming: erring toward "it may hurt" is the right
        # direction for a warning, but the rule this file adopted is about
        # CLAIMING, not about direction.
        return ("If the reservation is not yet in effect, in-flight requests "
                "briefly FAIL while the address is released; if it is, they "
                "queue. Either way nobody is signed out and the cookie secret "
                "is unchanged.")
    return ("In-flight requests briefly FAIL — the reservation is not in effect "
            "yet, so the address is released while the process restarts. Nobody "
            "is signed out; the cookie secret is unchanged.")


#: The resolution of the start-time reader, and it is not a fudge factor.
#:
#: TWO FLOORS, not one, and the arithmetic is written out because this constant
#: is defended by an argument rather than by a measurement — so the argument has
#: to be complete or the next person to lean on it leans on a rounding error.
#: /proc/stat's `btime` is printed in WHOLE SECONDS (floored), and field 22 is
#: floored to CLOCK TICKS by nsec_to_clock_t. Worst-case earliness is therefore
#: 1 + 1/USER_HZ ≈ 1.01 s, not 1.00 s.
#:
#: 1.0 still ships, deliberately. The residual 10 ms needs a gate input whose
#: mtime lands within one tick of the proxy's exec, and every writer in
#: _gate_inputs is separated from that exec by at least a `systemctl` round trip
#: and a Go runtime start; the filesystem's own current_time() also floors in
#: the safe direction. Widening to 1.01 would buy nothing measurable and start
#: eating real operator edits.
#:
#: The error is ONE-DIRECTIONAL and its direction is "the running process looks
#: older than it is" — i.e. toward calling a freshly installed box stale and
#: bouncing the fleet's sole authorization gate. This cancels exactly that. It
#: cannot hide a real staleness: a file that is legitimately newer than the
#: running process is newer by the gap between two operator commands — seconds
#: at the very least, usually days — never by milliseconds.
#:
#: If the reader ever moves to the manager's microsecond ExecMainStartTimestamp,
#: delete this deliberately and say so — do not let it rot into a silent widening.
_START_TIME_SLACK = 1.0


def _restart_reasons(*, wrote: Sequence[str], gate_state: str, pid: int | None,
                     started: float | None, written: Mapping[str, float | None],
                     socket_state: str) -> tuple[list[str], list[str]]:
    """Must `upgrade-sso` restart the shared proxy? Returns (reasons, unreadable).

    ONE QUESTION: is the process serving the fleet's gate right now the one this
    box's current state describes — started from the files on disk, and holding
    the port through the reservation rather than on its own? A non-empty
    `reasons` means no. `unreadable` is every input that could not be
    established, and the caller MUST print it when it does not restart.

    Pure on purpose. Every input is sampled by the caller through system.py, so
    this decision can be exercised as a decision instead of mocked away — the
    previous version could only be tested by mocking itself, and shipped
    restarting on every run with the suite green.

    THE RULE THIS SHAPE ENFORCES: every clause must be FALSE immediately after
    the restart it demanded. A clause that is not self-clearing is not a reason
    to restart, it is a loop — which is why _gate_inputs carries an entry
    requirement about its writers, and why converge_proxy's write is conditional.

    AND: AN INPUT THAT CANNOT BE READ MAY NOT DECIDE. `unknown` is not "no". An
    unreadable input voting restart bounces the gate forever on a box with a
    wedged systemctl; voting "current" silently is the other failure wearing the
    words of health. So it is REPORTED, and the no-op is safe only because it is
    loud — and because `wrote` needs no host read at all.

    THE CLOCK-STEP CAVEAT, and it is about the FILES rather than about the
    process. `started` is anchored to /proc/stat's btime, which the kernel
    recomputes on every read as (realtime offset - suspend offset) — so a
    settimeofday step MOVES it, and the computed start is always expressed in
    the CURRENT realtime frame, the same frame a file's st_mtime was stamped in.
    Both terms therefore stay mutually comparable across a step, which is the
    property that licenses the comparison at all.

    WHAT A BACKWARD STEP DOES BREAK, and this is the one place Rule A above does
    not hold: an mtime stamped BEFORE the step is a pre-step number, and a
    process started after it is a post-step one. If the step is large enough, the
    file keeps reading newer than the process — and it keeps reading newer after
    the restart, because the restart cannot move the FILE back. So the clause
    does not self-clear; it clears when someone next writes one of those files,
    or when the clock is stepped forward again. The verb is not silent about it
    (it names the file it restarted for), the direction is the safe one (a
    needless restart, never a missed one), and the trigger is an administrator
    stepping the box's clock backwards past the age of its own config. Recorded
    as an exception rather than swept in, because Rule A is the reason the rest
    of this function is shaped the way it is. system._btime's docstring points
    here for this paragraph; do not delete it without moving it."""
    reasons: list[str] = []
    unreadable: list[str] = []
    # THIS RUN's own writes. Certain, and the only clause that touches no host
    # read: if /proc or systemd cannot be attributed, it is still a fact that we
    # rewrote these files seconds ago. It exists so an unreadable box cannot
    # become a silent no-op (DIRECTION 1). Deliberately redundant with the mtime
    # compare below on a readable box — the redundancy is the fallback.
    if wrote:
        reasons.append("this run rewrote " + ", ".join(sorted(wrote)))
    # IS THE GATE SERVING AT ALL. `inactive`/`failed` is not "nothing to do":
    # printing "unit and config current" over a dead gate is the
    # silence-that-reads-as-health this tree keeps paying for (DIRECTION 1).
    # `activating`/`deactivating`/`reloading` are NOT in that set — restarting a
    # proxy in the middle of a slow OIDC discovery turns a healthy start into
    # MSG_PROXY_DID_NOT_RETURN and sends the operator to roll back a binary that
    # is fine (DIRECTION 2). And "unknown" is this reader failing, not a state
    # word: counting it would bounce the gate on every run of a box whose
    # systemctl is wedged (DIRECTION 2).
    if gate_state in ("inactive", "failed"):
        reasons.append(f"{UNIT} is {gate_state} — the gate is not running")
    elif gate_state != "active":
        unreadable.append(f"{UNIT} is {gate_state}; not deciding from that")
    elif pid is None or started is None:
        # VINTAGE, unattributable. Do not guess in either direction: `wrote`
        # above still covers this run, and the socket clause below still covers
        # the un-migrated box, so what is lost is bounded and it is SAID.
        unreadable.append(f"could not read when the running {UNIT} started")
    else:
        # VINTAGE. The one question a byte-compare structurally cannot answer:
        # the files are current BECAUSE a converge wrote them, and the running
        # process is the only thing that is not (DIRECTION 1 — the closed loop
        # that made the migration impossible on every box). Observed, never
        # recorded: a "restart owed" flag would be recorded intent gating control
        # flow, which is how this tree latched a half-finished box before (see
        # credentials_needed).
        for name, m in sorted(written.items()):
            if m is None:
                unreadable.append(f"could not read {name}")
            elif m > started + _START_TIME_SLACK:
                reasons.append(f"{name} was written after the running {UNIT} started")
    # PROVENANCE, and the one state disk cannot show. Everything above compares
    # against files; a socket unit stopped, masked or never started AFTER the gate
    # came up leaves no file trace at all — the live process keeps serving on the
    # descriptor it already holds, and the address goes back to the box the moment
    # it exits. Used in the NEGATIVE only: `active` is a weak positive (a bare
    # daemon-reload can leave a socket unit active holding nothing), so not-active
    # is evidence the reservation is not in effect while active is not evidence
    # that it is (DIRECTION 1). "unknown" is again the reader failing, and it used
    # to mean restart: a timed-out `systemctl is-active` bounced the fleet's gate
    # on every run (DIRECTION 2).
    if socket_state == "unknown":
        unreadable.append(f"could not read the state of {SOCKET_UNIT}")
    elif socket_state != "active":
        reasons.append(f"{SOCKET_UNIT} is {socket_state} — the port reservation "
                       f"is not in effect")
    return reasons, unreadable


# _warn_auth_block_stale and _auth_block_advice lived here and are gone. Both
# existed for one reason: the auth block was a copy the operator pasted and VIDE
# could not rewrite, so the only thing the tool could do about a stale one was
# talk about it — at the migration lever, in a doctor row, and in `vide info`,
# each having to decide whether "re-paste it" was advice or a way to publish the
# fleet's login flow at an address nothing held. `render_auth_host` writes the
# file now, so the question is not answered more carefully; it is not asked.
# contract.MSG_AUTH_BLOCK_MOVED lost its only caller with them.


def gate_port(cfg: Config) -> int:
    """The address the fleet's gate is actually SERVING on — which is the pin on
    every healthy box and is not the pin on exactly one kind of unhealthy one.

    THE PIN IS WHAT THE FLEET DECIDED; THIS IS WHERE THE GATE IS. They part when
    the pin is hand-edited: install_proxy_socket_unit then refuses to move the
    reservation, so systemd keeps holding the old address and the proxy keeps
    inheriting it. Probing the pin there answers about a port nobody is listening
    on, and every caller reads that silence as its own kind of catastrophe —
    `_verify_proxy_came_back` calls a healthy gate dead and hands the operator a
    binary-rollback procedure that undoes a CVE fix, and rotate_sso reads it as
    "the proxy rejected the new cookie secret", RESTORES the previous secret and
    reports failure. The stolen-cookie kill switch then un-burns the very secret
    it was invoked to burn, silently.

    IT NEVER GUESSES: the reservation's address when there is one and it is not
    the pin, otherwise the pin — which is the un-migrated box, where the proxy
    binds the pin for itself. Both branches name an address something is meant to
    be on, and neither is a default."""
    from . import sso as vide_sso
    pin = vide_sso.fleet_port(cfg)
    loaded = loaded_reservation()
    if loaded and not _covers_port(loaded, pin):
        for ln in loaded:
            head = ln.split()[0] if ln.split() else ""
            if head.startswith("127.0.0.1:"):
                try:
                    return int(head.rsplit(":", 1)[1])
                except ValueError:
                    break
    return pin


def proxy_answers(cfg: Config, *, timeout: float = 3.0,
                  port: int | None = None) -> bool:
    """One probe, one reader of the port, for every caller that asks "is the
    shared proxy serving". It was the same two lines in three places, and two of
    them were byte-identical — which is not only duplication: `prove-teeth`'s
    mutations are line-oriented `sed`, so an identical line cannot be mutated in
    one caller without silently mutating the other, and neither could carry a
    proof at all.

    `gate_port`, never config and no longer the bare pin. rotate_sso reads a
    failed probe as "the proxy rejected the new cookie secret" and RESTORES the
    secret it was invoked to burn — so a port divergence here does not fail
    loudly, it silently disarms the stolen-cookie kill switch. The pin protected
    that against a `.env` row; it did not protect it against the pin itself
    moving, which is the half gate_port closes.

    `port` IS AN OPTIMISATION AND NOTHING ELSE — it exists so a poll loop can
    resolve the address ONCE instead of shelling out to systemctl twice per
    iteration, up to the whole restart budget. It is never a second policy: the
    only caller that passes it got the value from gate_port one frame up.

    `timeout` is a parameter and not a constant because the two kinds of caller
    now want different ones. Under socket activation a probe against a down proxy
    no longer refuses instantly — it completes the handshake into systemd's
    accept queue and blocks — so a poll loop pays the full timeout on EVERY
    iteration. Loops pass PROXY_PING_TIMEOUT_S; the single-shot diagnostic keeps
    the module default, because it only probes in states where it cannot queue."""
    return system.healthz(gate_port(cfg) if port is None else port,
                          path="/ping", timeout=timeout)


def _proxy_pings(cfg: Config) -> bool:
    """Wait for the shared proxy to answer after a restart WE performed.

    The budget is UNIT_RESTART_BUDGET_S and not a number of its own, and that is
    the whole point: this used to wait 20s while the unit's retry runway was
    120s. So on precisely the slow-OIDC-discovery boot the runway exists for, the
    proxy was still legitimately coming up when this gave up. rotate_sso reads a
    False here as "the proxy rejected the new cookie secret" and RESTORES the old
    one, which means the stolen-cookie kill switch un-burned the secret it was
    invoked to burn, on a transient, and told the operator it had failed. A
    waiter that is shorter than the thing it waits for is not a timeout, it is a
    false negative with a recovery path attached.

    A MONOTONIC DEADLINE, not an iteration count — and that stopped being a
    matter of taste when the port became reserved. `for _ in range(BUDGET)` with
    `sleep(1)` measures seconds only while a probe is free, and against a
    socket-activated port a failed probe is NOT free: connect(2) succeeds into
    systemd's accept queue instead of being refused, so every miss costs its full
    timeout. At the module default that turned a 120s budget into ~480s of wall
    clock; even at PROXY_PING_TIMEOUT_S it would overshoot by a third. Count
    time, never iterations.

    BOUNDED BY BOTH, and the second bound is not belt-and-braces. The pacing here
    is an injectable `sleep`, so a deadline read off the real clock and advanced
    by a call the caller can neutralise is not a bound at all: patch `sleep` to a
    no-op and the loop spins on wall clock for the whole budget. That is not
    hypothetical — it is what a monotonic-only rewrite did to this tier, turning
    a 10-second suite into a 4-minute one, twice, in two different loops. So:
    the deadline governs in production, where each probe genuinely costs time;
    the attempt count keeps the loop finite when it does not. They are the same
    budget expressed two ways, and whichever is reached first is correct."""
    import time
    # RESOLVED ONCE, OUTSIDE THE LOOP. gate_port shells out to systemctl twice,
    # and this loop runs up to the whole restart budget — paying that per
    # iteration would turn a probe budget into a subprocess storm on the one path
    # where the fleet's gate is already down. The address cannot move underneath
    # us either: only install_proxy_socket_unit writes it, and it is not running.
    port = gate_port(cfg)
    deadline = time.monotonic() + UNIT_RESTART_BUDGET_S
    for _ in range(UNIT_RESTART_BUDGET_S):
        if proxy_answers(cfg, timeout=PROXY_PING_TIMEOUT_S, port=port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)
    return False


def _verify_proxy_came_back(cfg: Config, ex: Executor, rep: Reporter) -> None:
    """Refuse to report success on a restart of the fleet's SOLE auth gate that
    did not come back.

    Both restarts in upgrade_sso were unverified, so a proxy that failed to start
    on the new binary left every `auth: none` IDE on the box unreachable and the
    verb exited 0. The N-1 directory `prune` deliberately keeps exists for exactly
    this and was named in no message, no doc and no verb — so the lever was there
    and the operator had no way to know. Raising rather than warning is also what
    keeps it: prune() runs after this, and pruning on the way out of a failed
    upgrade would delete the version being rolled back to."""
    if ex.dry_run or _proxy_pings(cfg):
        return
    raise StateError(contract.MSG_PROXY_DID_NOT_RETURN.format(
        unit=UNIT, dir=cfg.oauth2_proxy_dir))


def state_path(cfg: Config) -> Path:
    return Path(cfg.sso_dir) / "proxy.state"


def bootstrap_observed(cfg: Config) -> bool:
    """Has the shared proxy EVER been seen answering /ping on this box?

    Purely diagnostic — nothing branches on it, which is the point. Recorded
    intent that gates control flow is how the old bootstrap_needed latched a
    half-finished box; a record that gates nothing cannot. It answers the one
    question live state genuinely cannot: `proxy unit: DOWN` means something
    quite different on a box where provisioning never completed than on one that
    worked yesterday, and only doctor's advice differs between them."""
    return state_path(cfg).is_file()


def proxy_ready(cfg: Config, ex: Executor, rep: Reporter) -> bool:
    """Wait for the proxy to actually answer, then record that it did.

    `systemctl enable --now` returning 0 proves nothing here: the unit is
    Type=exec, so the manager considers it started as soon as execve succeeds,
    and oauth2-proxy exits 1 LATER, during OIDC discovery, when the issuer is
    unreachable. So a slow resolver on a fresh box yields a successful install
    command and a crash-looping proxy — the install prints "Install complete"
    and every request 502s.

    The budget is a stated willingness to wait rather than a derivation from the
    unit — see UNIT_RESTART_BUDGET_S, which lost its derivation when the start
    limiter had to be switched off. What it has to cover did not change: a slow
    resolver completing OIDC discovery on a cold box. Paced through ex.idle so
    the curses wizard keeps repainting — a bare sleep here freezes the pane, and
    unlike _proxy_pings this runs inside the install path.

    A MONOTONIC DEADLINE, because `waited += 2.0` counted only the sleeps. Under
    socket activation each failed probe also costs its own timeout (connect(2)
    succeeds into the accept queue instead of being refused), so the loop
    overshot its own documented budget by more than half again.

    Bounded by BOTH the deadline and an attempt count, for the reason spelled out
    on _proxy_pings: the pacing is `ex.idle`, an executor seam, and a fake
    executor returns from it instantly — so a deadline alone stops bounding
    anything and the loop burns the entire budget in real seconds. It did, in
    this tier, in the one test that deliberately runs the positive control
    unmocked."""
    import time
    from . import sso as vide_sso
    deadline = time.monotonic() + UNIT_RESTART_BUDGET_S
    attempts = int(UNIT_RESTART_BUDGET_S / 2.0)
    for _ in range(attempts):
        if time.monotonic() >= deadline:
            break
        if proxy_answers(cfg, timeout=PROXY_PING_TIMEOUT_S):
            ex.atomic_write(state_path(cfg),
                            "# written the first time this box's shared proxy\n"
                            "# answered /ping. Diagnostic only: nothing reads it\n"
                            "# to decide what to do.\n",
                            mode=0o644, owner=("root", "root"))
            return True
        # KEPT, BUT IT ALMOST NEVER FIRES NOW, AND THAT IS THE POINT.
        # This used to be the fast exit: a unit that had burned its restart
        # budget rested in `failed`, so waiting out the rest told the operator
        # nothing. The budget is gone — a limiter that fires makes systemd close
        # the listening descriptor and hand the fleet's authorization port back
        # to the box — so the crash-looping proxy now rests in
        # `activating (auto-restart)` forever and this branch is unreachable for
        # that cause. It is kept for the causes that remain (a failed dependency,
        # an explicit stop racing the wait), and it is NOT replaced by a restart
        # counter: with RestartSec pacing the loop, "we watched it fail N times"
        # and "we waited N x RestartSec" are the same bound written twice. What
        # the operator needs instead is to tell a crash loop from a service that
        # never started at all, and the message below names both units for that.
        if system.unit_is_failed(UNIT):
            break
        ex.idle(2.0)
    # The issuer the proxy is actually configured with, not the one .env names:
    # a message that sends the operator to check the wrong URL is worse than no
    # message, and this one fires exactly when they are already lost.
    rep.warn(contract.MSG_PROXY_NOT_READY.format(
        issuer=vide_sso.fleet_issuer(cfg), seconds=int(UNIT_RESTART_BUDGET_S),
        socket_unit=SOCKET_UNIT, unit=UNIT))
    return False


# ---- doctor -----------------------------------------------------------------
def _reservation_rows(lines: list[str], socket_state: str, socket_enabled: str,
                      listening: list[str], bound: bool, usurped: bool,
                      holds: bool, active: bool, port: int, *,
                      covers: bool, holders) -> bool:
    """Is the fleet's authorization port actually reserved? Appends rows, returns ok.

    Separate from liveness because the two questions came apart the day systemd
    started holding the address. A proxy that is DOWN on a reserved port is an
    outage — bad, bounded, self-healing. A proxy that is UP on an unreserved port
    is an open door, and it reads as perfect health everywhere else in this
    section. That asymmetry is the whole reason these rows exist."""
    # TWO DIFFERENT QUESTIONS, TWO DIFFERENT SEAMS, and getting that wrong made
    # both of these rows dead code in the first draft. `unit_state` is
    # `systemctl is-active`, whose vocabulary is active / activating /
    # deactivating / inactive / failed / reloading — it NEVER says "masked", and
    # on current systemd an absent unit reads `inactive` rather than "unknown".
    # So keying either row on that word meant the two states an operator most
    # needs named — the unit was never installed, and the unit was deliberately
    # switched off — both fell through to the generic line. `masked` and the
    # empty string are `systemctl is-enabled` answers, which is why the caller
    # samples both.
    if holders is None:
        # NEITHER /proc/net/tcp NOR /proc/net/tcp6 COULD BE READ. Effectively
        # unreachable on Linux, and it is a row rather than an assumption for
        # the reason the whole section exists: every verdict below rests on this
        # read, and a reader that fails to "nobody is listening" would print the
        # NOT BOUND row's "the fleet's authorization port is open right now"
        # from a measurement that never happened — with a remedy that restarts
        # the fleet's gate. Unknown is said, never guessed in either direction.
        lines.append(
            f"  proxy port: UNREADABLE — could not read /proc/net/tcp, so who "
            f"holds 127.0.0.1:{port} is unknown. Nothing below this line was "
            f"established. Check that /proc is mounted: findmnt /proc")
        return False
    if not socket_enabled:
        lines.append(
            f"  proxy port: NO RESERVATION UNIT — {SOCKET_UNIT} is not installed, "
            f"so nothing holds 127.0.0.1:{port} and any local account can bind it "
            f"whenever the proxy is not on it. Install it: sudo ./install.sh")
        return False
    if socket_enabled.startswith("masked"):
        # `masked` and `masked-runtime` both mean the operator switched it off —
        # and on THIS unit that does not switch the gate off, it gives the
        # address away.
        lines.append(contract.MSG_PROXY_PORT_UNRESERVED.format(
            socket_unit=SOCKET_UNIT, state=socket_enabled, port=port))
        return False
    if socket_enabled != "enabled":
        # `disabled` — the lapse with NO live symptom, which is why it needed a
        # row of its own rather than falling through to the good news. The unit
        # can be up, covering the pin and held by root right now, and still be
        # absent from the next boot transaction: `systemctl disable` removes the
        # sockets.target symlink and touches nothing that is running. The window
        # this whole unit exists to close is the one between sockets.target and
        # the proxy's own start, and a disabled unit reopens exactly that window
        # while every other signal in this section stays green.
        lines.append(
            f"  proxy port: NOT ENABLED AT BOOT — {SOCKET_UNIT} is "
            f"{socket_enabled or 'not enabled'}. It may be holding "
            f"127.0.0.1:{port} right now, but it is not in the boot transaction: "
            f"after the next reboot the address is free from sockets.target "
            f"until the proxy itself starts, and any local account can take it "
            f"in that window. Restore it: sudo systemctl enable {SOCKET_UNIT}")
        return False
    if usurped:
        # KERNEL-VERIFIED, and it outranks every row BELOW it — the four above
        # return first, and they should: an unreadable kernel, a missing unit
        # and a masked or unenabled one are all states in which this question
        # has not been asked properly yet. Something that is neither systemd nor
        # the proxy is listening on the fleet's authorization port. This fires
        # even when the socket unit reports
        # `active` and is configured for this very port — the reload-orphaned
        # state, where systemd let the descriptor go without leaving the unit,
        # and every manager-side signal still says health.
        #
        # ITS OWN MESSAGE, not MSG_PROXY_PORT_UNRESERVED with a `state=` string
        # spliced in. That message's fixed body says "Nothing has taken it yet
        # — that is the only thing separating this line from the one above it",
        # which is the exact opposite of this state, and its remedy (`enable
        # --now` the socket unit) dies EADDRINUSE here. A row that contradicts
        # itself in two sentences and then prescribes a command that cannot work
        # is worse than no row.
        lines.append(contract.MSG_PROXY_PORT_TAKEN.format(
            port=port, proxy_user=PROXY_USER,
            uids=", ".join(str(u) for u in sorted(holders.on_hop))
                 or "an unknown user"))
        return False
    if socket_state == "active" and covers and not bound:
        # THE RELOAD STATE, and the model that used to be here was inverted.
        # `systemctl show -p Listen` reports what the unit FILE configures, not
        # what is bound: after editing ListenStream= and running only a
        # daemon-reload, systemd frees the old address, binds nothing, and this
        # query happily answers with the NEW one. So a check that compared the
        # pin against `show -p Listen` agreed with itself and printed "reserved"
        # over a port nothing was holding — a false closure produced by the very
        # row written to catch one.
        # The ground truth is whether anything is listening, which is why `bound`
        # comes from the kernel's own socket table and not from the manager.
        # The body is a constant now because a converge prints the same row from
        # the same three facts. Both readers see "active, configured for the pin,
        # nothing listening" and both prescribe the one command that fixes it, so
        # one text is right — unlike NOT YET RESERVED, whose two readers stand in
        # different states and must NOT share a sentence.
        lines.append(contract.MSG_PROXY_PORT_NOT_BOUND.format(
            socket_unit=SOCKET_UNIT, unit=UNIT, port=port))
        return False
    if socket_state == "active" and not covers:
        # KEYED ON `covers`, NOT ON `not holds`, and that distinction was a real
        # defect for one round. `holds` gained a third conjunct (the listening
        # socket is owned by root) and this row was not re-derived, so a box
        # whose unit IS configured for the pin — but whose holder could not be
        # confirmed — printed "listening on 127.0.0.1:4180 but the fleet is
        # pinned to 127.0.0.1:4180". A row that contradicts itself inside one
        # sentence teaches the operator to stop reading the section.
        #
        # DRIFT, and nothing else can see it: the unit is up and configured for
        # an address that is NOT the fleet pin, while the pin, the per-instance
        # Caddy bodies and the pasted auth block all name the other one. So the
        # box reserves an address nobody dials and leaves the address everybody
        # dials FREE — a false closure in which every other row would otherwise
        # be green.
        #
        # The CAUSE is the pin moving without this unit being re-rendered; it is
        # NOT the reload state, which the row eight lines above owns and which
        # ends with the unit holding neither address. Those two were described
        # in each other's words for two rounds — the reload case is "systemd
        # frees the old address and binds nothing", this one is "the unit was
        # never told about the new address at all".
        #
        # This is checked BEFORE the good news, and `holds` is computed from it
        # rather than from unit state alone. An earlier draft had `holds` mean
        # only "a socket unit is active", so on a drifted box the BYPASS arm was
        # suppressed as if the port were covered: the real hop was squattable,
        # something answering it produced this advisory row and NO containment
        # ladder at all.
        # THE REMEDY IS NOT A RESTART, and saying it was is a defect this row
        # carried from its first draft. `show -p Listen` reports the LOADED
        # configuration, so in this state the unit is configured for an address
        # that is not the pin — and restarting it rebinds THAT address. The
        # restart is safe (it releases nothing anyone dials, and creates no
        # exposure) but it is ineffective and NON-CLEARING: the row is still here
        # afterwards. An operator who restarts the fleet's gate twice on a row
        # that does not clear stops trusting the section, and this section is
        # where the containment ladder lives.
        #
        # The two numbers have to be reconciled, and which way is the operator's
        # call because only they can see the Caddyfile they pasted into.
        lines.append(
            f"  proxy port: DRIFT — {SOCKET_UNIT} is configured for "
            f"{', '.join(listening) or '(nothing)'} but the fleet is pinned to "
            f"127.0.0.1:{port}, "
            + ("which SOMETHING ELSE is already answering on"
               if bound else "which nothing is holding")
            + " — so that port is not VIDE's. Restarting the unit will NOT fix "
            "this: it would rebind the address the unit is configured for, which "
            "is the wrong one. Reconcile the two — put VIDE_SSO_PROXY_PORT back "
            "to the address above in <sso_dir>/fleet.env if the pin was changed "
            "by hand, or complete the move: see docs/sso.md.")
        return False
    if holds:
        # SAY WHAT WAS VERIFIED — and this round it is finally the whole claim.
        # Three independent things had to agree to get here: the manager says
        # the unit is up, the unit is configured for THE FLEET'S port, and the
        # socket actually listening on that address is owned by uid 0. The last
        # one is the one that used to be missing: earlier drafts either asserted
        # "held by pid=1" from `ss -Htlnp` (a process-chosen string, so a
        # squatter could earn the affirmative line) or admitted "VIDE cannot
        # prove it" and sent the operator to run the same forgeable command by
        # hand — a control whose automated and manual forms fail to the same
        # input is one control, not two. /proc/net/tcp's uid column is written
        # by the kernel and readable without root, so the check is now VIDE's
        # and it is the same check on every box.
        #
        # WHAT IS STILL NOT CLAIMED: that the uid-0 holder is systemd rather
        # than some other root process. Root already owns the box, so that
        # distinction buys nothing an attacker at uid 0 could not simply take.
        lines.append(
            f"  proxy port: reserved — {SOCKET_UNIT} is active for "
            f"127.0.0.1:{port} and the socket listening there is owned by uid 0")
        return True
    if active:
        # W0 — installed, enabled, and INERT. The running proxy is still bound to
        # the port itself, so the socket unit cannot take it until the gate
        # restarts. This is the state EVERY pre-existing box lands in the moment
        # this version converges, and the one an operator is most likely to read
        # as done because every other row is green.
        #
        # RED, not a warning, and the counter-argument is worth stating: this
        # turns `doctor --quiet` — the documented cron hook — red fleet-wide on
        # upgrade day, which is a mistake this tree has made before (keying
        # failure on a marker's absence reddened healthy boxes). The difference is
        # that those boxes were healthy and these are not: the hole this row
        # describes is open, it is the one the release exists to close, and it has
        # a one-command fix. A migration checklist that pages is the point.
        #
        # …ON A BOX WHERE THE FIRST CLAUSE IS TRUE, AND THAT IS CHECKED HERE FOR
        # FREE. The message says the running proxy still holds the pin itself. On
        # a re-pinned box it does not — it is on the old address — and the two
        # remedies this row names would then MOVE the fleet's authorization hop
        # instead of landing a reservation on it. `bound` is already in hand from
        # the same /proc read the rows above used, so choosing costs no new host
        # read at all: `usurped` was ruled out several rows up, so by the time
        # execution reaches here `bound` means precisely "a legitimate identity
        # is listening on the pin" — which is exactly the message's precondition.
        lines.append((contract.MSG_PROXY_RESERVATION_PENDING if bound
                      else contract.MSG_PROXY_RESERVATION_OFF_PIN).format(
                          socket_unit=SOCKET_UNIT, port=port))
        return False
    lines.append(contract.MSG_PROXY_PORT_UNRESERVED.format(
        socket_unit=SOCKET_UNIT, state=socket_state, port=port))
    return False


def proxy_health(cfg: Config, *, check_staleness: bool = True) -> tuple[bool, list[str]]:
    """Doctor's shared-proxy section body. Returns (ok, lines). `check_staleness`
    is gated off for `doctor --quiet` so a cron/monitoring probe never depends on
    github.com latency.

    A DIAGNOSTIC REPORTS; it does not die. The fleet readers validate on every
    read, which is right for a renderer — a damaged 0644 fleet.env must not reach
    a config — but wrong here: a doctor that aborts on the very state it exists to
    describe leaves the operator with a traceback and an exit code from the wrong
    family (`doctor --quiet` promises 69/UNAVAILABLE, and an escaping ConfigError
    is 78). So the read is caught, reported as the red line it is, and the rest of
    the section still runs."""
    from . import sso as vide_sso
    lines: list[str] = []
    ok = True
    # SAMPLE EVERY PIECE OF MANAGER STATE UP FRONT, BEFORE ANY PROBE.
    # Not tidiness — correctness. Against a socket-activated port the /ping probe
    # below is itself an ACTIVATION TRIGGER: connecting can start the service.
    # The old shape read `active` before the probe and `unit_is_failed` /
    # `unit_main_pid` after it, so the squat arm compared post-probe manager state
    # against a pre-probe answer — doctor's own probe erasing the evidence of the
    # condition doctor was checking for, and the losing side of that race prints
    # the word BYPASS and tells the operator to stop caddy. A fail-loud arm may
    # not rest on a timing assumption.
    socket_state = system.unit_state(SOCKET_UNIT)
    # `is-enabled`, a DIFFERENT vocabulary from `is-active` and the only one that
    # says `masked` or answers empty for a unit that is not installed. Sampled
    # here so both live-state questions are asked before any probe.
    socket_enabled = system.unit_enable_state(SOCKET_UNIT)
    listening = (system.unit_listen_streams(SOCKET_UNIT)
                 if socket_state == "active" else [])
    active = system.unit_is_active(UNIT)
    failed = system.unit_is_failed(UNIT)
    main_pid = system.unit_main_pid(UNIT)
    lines.append(f"  proxy unit: {'active' if active else 'DOWN'}")
    ok = ok and active
    try:
        port = vide_sso.fleet_port(cfg)
    except ConfigError as e:
        lines.append(f"  proxy port: UNREADABLE — {e}")
        return False, lines
    # ---- the reservation, which is a different question from liveness ----
    # These rows exist because "the proxy is down" and "the port is free" stopped
    # being the same sentence. systemd holds the address; the proxy only inherits
    # it. A down proxy on a reserved port is an outage. A down proxy on a free
    # port is an open door — and so is a HEALTHY proxy whose reservation never
    # took effect, which is the state every pre-existing box is in until its gate
    # restarts, and the one an operator is most likely to read as done.
    # `holds` is "the reservation covers THE FLEET'S port", not "a socket unit is
    # up". It needs the pin, so it is computed here rather than with the other
    # manager samples — and everything downstream that asks "is the address
    # covered" must use this and not socket_state, or a drifted box reads as
    # protected while its real hop is free.
    # THREE signals, not one. The unit must be up, configured for the fleet's
    # port, AND the socket actually listening there must be owned by root.
    #
    # WHAT THIS CAN NOW TELL YOU, and the paragraph that used to sit here said
    # the opposite: attribution no longer "needs `ss -Htlnp` and root". It is a
    # uid the kernel wrote, in /proc/net/tcp, which is world-readable — so
    # `holds` is a verified claim rather than a hopeful one, and it is the same
    # claim whether or not doctor runs as root. The old text also told the
    # reader that "only a `pid=1` entry proves the address is reserved", which
    # is now the one thing contract.py and docs/threat-model.md forbid in
    # capitals: that entry carries a process-chosen name.
    # WHO holds it, ANSWERED IN NUMBERS THE KERNEL WROTE.
    #
    # This replaced a `ss -Htlnp` parse, and the replacement is the whole point
    # rather than a tidy-up. That column renders `users:(("<comm>",pid=N,fd=M))`
    # and <comm> is set by the process itself through prctl(PR_SET_NAME) — no
    # privilege needed — so a squatter naming itself the five characters `pid=1`
    # put a 1 into any regex over the line. The old code answered that by
    # weakening the SENTENCE ("nothing affirmative is built on it") while
    # `holds` still carried `not usurped` as a conjunct: clearing the suspicion
    # ADDED health, restored the affirmative row over a live squat and removed
    # the containment ladder. The absence of a negative was load-bearing in the
    # green direction, which is the inversion this file keeps paying for.
    # /proc/net/tcp's uid column cannot be dressed up, and it needs no root — so
    # `holds` can rest on a POSITIVE and a non-root doctor gets the real answer.
    holders = system.hop_holders(port)
    # The one legitimate non-root holder: on a converged-but-not-yet-restarted
    # box the proxy is still bound to the address itself. That is NOT YET
    # RESERVED — a migration checklist item — and firing the containment ladder
    # at it would tell every operator on upgrade day to stop caddy. Recognised
    # by UID rather than by MainPID, and that matters: MainPID is readable by
    # any local account, so the pid-shaped version of this exclusion widened the
    # forgeable surface instead of narrowing it. Becoming `vide-oauth2` requires
    # root.
    proxy_uid = system.user_uid(PROXY_USER)
    legitimate = {0} | ({proxy_uid} if proxy_uid is not None else set())
    on_hop = holders.on_hop if holders is not None else set()
    # THE POSITIVE: the socket on the fleet's hop is owned by root, which is
    # what systemd holding it looks like from the outside.
    #
    # `certain` ONLY — a `::` row can never make a box read reserved, because
    # procfs exposes no IPV6_V6ONLY flag and a v6only wildcard serves no v4
    # traffic at all. And EXACTLY {0}, not `0 in certain`: SO_REUSEPORT lets a
    # second listener share the address, and the kernel requires the two to have
    # equal effective uids — so against a root socket that second listener is
    # also root, and "root plus somebody else" is not a state to call reserved
    # on a box where root is the only identity that may hold this hop.
    root_held = holders is not None and set(holders.certain) == {0}
    # …and its complement, which no longer depends on the attacker's choices:
    # something is on the fleet's hop and it is neither of the two identities
    # that may be. `on_hop` rather than `certain`, deliberately — a `::` row MAY
    # be dual-stack and really serving the hop, so it must be able to raise an
    # alarm even though it may never grant health.
    usurped = holders is not None and bool(on_hop) and not (on_hop <= legitimate)
    # ONE READER ANSWERS EVERY QUESTION, and that is not tidiness either. This
    # used to be a second `ss -Htln` (system.listening_ports), so two subprocess
    # invocations sampled nearly the same fact at two instants and could
    # disagree — and that reader returns an EMPTY SET when `ss` fails, so a
    # wedged or killed `ss` printed "the fleet's authorization port is open
    # right now" from a measurement that never happened, with a remedy that
    # bounces the gate. /proc/net/tcp answers "is anything listening there",
    # "who owns it" and "who is being SERVED on it" from the same read, and
    # distinguishes an unreadable kernel (None) from an empty one — which is the
    # row above this one.
    bound = bool(on_hop)
    # WHO IS ANSWERING RIGHT NOW, which is a different question from who holds
    # the address and is the one MSG_PROXY_PORT_SQUATTED's step 2 calls not
    # optional. An attacker that hands the LISTENING socket back while staying
    # alive keeps serving every connection Caddy already had open: the holder
    # check goes green behind it, doctor prints `reserved`, and step 5 now
    # presents that as a check rather than as prose. The accepted sockets keep
    # the uid of whoever created the listener they came from, so the same
    # legitimacy test applies to them.
    harvesting = (holders is not None
                  and bool(set(holders.served) - legitimate))
    # `bound` IS NOT A POSITIVE CONJUNCT, and that inversion was a real hole
    # rather than a tidiness: it is ambient state an unprivileged account can
    # create. With it in the AND, the reload-orphaned box — socket unit
    # `active`, systemd holding nothing after a bare daemon-reload — was turned
    # GREEN by the attack itself: one `bind(2)` on the pin satisfied `bound`,
    # flipped this to True so doctor printed "reserved", and cancelled the /ping
    # probe on the way past. A signal an attacker controls may add a warning; it
    # may never remove one. It survives below only in the NOT BOUND row, where
    # its absence is the evidence.
    covers = _covers_port(listening, port)
    holds = socket_state == "active" and covers and root_held
    ok = _reservation_rows(lines, socket_state, socket_enabled, listening,
                           bound, usurped, holds, active, port,
                           covers=covers, holders=holders) and ok
    # PROBE ONLY WHERE A PROBE CANNOT TRIGGER AN ACTIVATION.
    #   * active           -> the probe reaches a running process; no trigger.
    #   * not holds        -> nothing is socket-activated on that address, so a
    #                         connect starts nothing AND still fails fast with
    #                         ECONNREFUSED. This is the un-migrated box, and it is
    #                         the squat detector's home — which is why the
    #                         condition is written this way and not on `active`.
    #   * otherwise        -> the socket is listening and the service is not up.
    #                         The answer is already known from unit state, the
    #                         probe would cost its whole timeout, and it would
    #                         start a service the operator may have stopped on
    #                         purpose. `doctor --quiet` is the documented cron
    #                         hook: probing here makes it a scheduled
    #                         `systemctl start`, on every tick, forever.
    #
    # An answer on /ping proves that SOMETHING answers, never that it is the
    # proxy — that half was true before this change and stays true after it.
    answers = system.healthz(port, path="/ping") if (active or not holds) else None
    if active and not answers:
        lines.append(f"  proxy /ping: NO ANSWER on 127.0.0.1:{port}")
        ok = False
    # TWO ARMS, AND ONLY ONE OF THEM NEEDS THE ATTACKER TO COOPERATE.
    #
    # `usurped` raises containment BY ITSELF. It used to be a disjunct inside
    # the `answers and …` conjunction, which meant the one signal in this
    # section that does not depend on the attacker's choices was gated on a
    # signal that does: a squatter answering Caddy's real forward_auth request
    # while 404-ing /ping left `answers` False, so the operator got an advisory
    # row and no ladder — during the harvest the ladder exists to stop. The uid
    # read is a kernel fact about who is on the fleet's hop; nothing about it
    # needs corroboration from the process being reported.
    #
    # `harvesting` raises it by itself too, and it is the ONE state a
    # listener-only check structurally cannot see: an attacker that hands the
    # listening socket back while staying alive goes on serving every connection
    # Caddy already had open. The address reads reserved, the holder check goes
    # green, and the harvest continues behind it. That is why the ladder's step 1
    # is `stop caddy` and not `reload` — a reload leaves whatever is in flight on
    # the far end it already chose — and why step 2 asks for `ss -Htnp` WITHOUT
    # `-l`. Until now nothing in doctor looked at the state that step describes.
    #
    # The third arm is unchanged and is a different question: on a box where the
    # reservation is not in effect, something is answering the hop and the
    # service is dead or unattributable. That one genuinely needs the answer,
    # because without a uid mismatch the answer is the only evidence.
    if usurped or harvesting or (answers and not holds and (failed or main_pid is None)):
        # `not holds` is the ONLY thing this change adds to the predicate, and
        # everything else about it is deliberately untouched.
        #
        # The new clause narrows: on a box where systemd is holding the address,
        # whatever answers reached it through the reservation, so the arm cannot
        # fire at all. On a box where it is not held — never migrated, or lapsed —
        # the old question is exactly as live as it was.
        #
        # `failed`-or-no-MainPID stays, and it is NOT redundant with `not holds`.
        # An early draft of this dropped it, reasoning that on a migrated box the
        # service's liveness is no longer evidence about who owns the address.
        # That is true of the ADDRESS and false of the ANSWER: the state
        # "reservation not in effect yet, proxy up and serving on the port it
        # bound itself" is where every pre-existing box lands the moment this
        # version converges, and without the guard doctor greets all of them by
        # printing BYPASS and telling the operator to stop caddy. It is
        # _reservation_rows that describes that state, correctly, as pending.
        #
        # And it is still not `not active`: unit_is_active is False for
        # `activating` and `deactivating` too, so the naive form accuses the
        # operator of an attack in the middle of their own restart — the fastest
        # way to teach someone to stop reading doctor.
        lines.append(contract.MSG_PROXY_PORT_SQUATTED.format(
            port=port, unit=UNIT, socket_unit=SOCKET_UNIT))
        ok = False
    # /reverse_proxy/upstreams, never /config/: the latter returns the operator's
    # ENTIRE running config — ACME references, DNS-provider tokens, basic_auth
    # hashes — into VIDE's process, which is a worse thing to do than the problem
    # being detected. This endpoint answers with upstream health and nothing
    # secret, and an answer at all is the whole signal.
    if system.healthz(CADDY_ADMIN_PORT, path="/reverse_proxy/upstreams"):
        lines.append(contract.MSG_CADDY_ADMIN_OPEN.format(port=CADDY_ADMIN_PORT))
        ok = False
    # ONLY when the proxy is also not answering. The marker is written the first
    # time /ping succeeds, so EVERY box provisioned before it existed lacks one —
    # keying a failure on its absence alone turned `doctor --quiet`, the
    # documented monitoring hook, red fleet-wide on upgrade, on boxes that were
    # perfectly healthy. Absence is only evidence when it agrees with live state.
    if not bootstrap_observed(cfg) and not active:
        # Distinguishes "provisioning never finished here" from "it worked and
        # is down now". They look identical in live state and want opposite
        # advice, and the first used to be unreachable: the old predicate
        # latched, so a re-run silently skipped the steps that had failed.
        lines.append(contract.MSG_PROXY_NEVER_BOOTSTRAPPED)
        ok = False
    elif active:
        # The running process may legitimately predate its own unit: a converge
        # re-asserts the file but never restarts. Observed from /proc, not from
        # a recorded intent, so it clears itself the moment anyone restarts.
        # main_pid is the value sampled at the top, deliberately — a second read
        # here would be a second observation of a thing the probe above can move.
        if main_pid is not None:
            nnp = system.proc_no_new_privs(main_pid)
            if nnp is False:
                lines.append("  proxy sandbox: the RUNNING process has no "
                             "NoNewPrivs — it predates the shipped unit; apply "
                             "with: sudo vide upgrade-sso")
    # NRestarts REPLACES A SIGNAL THIS CHANGE HAD TO GIVE UP.
    # The service's start limiter is off, because a limiter that fires makes
    # systemd close the listening descriptor and hand the fleet's authorization
    # port back to the box (units/oauth2-proxy.service spells out the four-link
    # chain). The cost is that a permanently broken proxy no longer rests in
    # `failed`, where a status line would show it — it rests in
    # `activating (auto-restart)`, forever, which looks far more alive than it is.
    # So the loudness moves here.
    #
    # Advisory, never part of `ok`, and only when the proxy is NOT answering: a
    # box that restarted the gate twice during maintenance is not broken, and a
    # counter that reddens doctor for remembering history would be noise the
    # operator learns to skip. When it fires alongside a red row it is the thing
    # that says "this is not a slow start, it is a loop".
    restarts = system.unit_n_restarts(UNIT)
    if restarts is not None and restarts > 0 and not answers:
        lines.append(f"  proxy restarts: {restarts} — the unit retries "
                     f"indefinitely by design (a start limit that fired would "
                     f"free the fleet's port), so it will not land in `failed`; "
                     f"read the cause: journalctl -u {UNIT} -n 50")
    inst = installed_version(cfg)
    if inst:
        floor = ".".join(map(str, FLOOR))
        # _parse_version RAISES ConfigError on anything it cannot read, and both
        # of its arguments here are host state rather than validated input: `inst`
        # is a directory name under oauth2_proxy_dir, and `latest` is whatever
        # github answered. The fleet-port read three sections up is already caught
        # for exactly this reason and these two were not — so a hand-made
        # directory, or a release tag that stops looking like a version, took
        # doctor down with a traceback and an exit code from the wrong family,
        # on the one verb whose job is to describe a box in that state.
        try:
            below = _parse_version(inst) < FLOOR
        except ConfigError as e:
            lines.append(f"  proxy version: UNREADABLE — {e}")
            ok = False
            below = None
        if below is None:
            pass
        elif below:
            lines.append(f"  proxy version: {inst} is BELOW the {floor} security floor")
            ok = False
        elif check_staleness:
            latest = net.resolve_latest_version(cfg, url=cfg.oauth2_proxy_releases_latest_url)
            try:
                newer = bool(latest) and _parse_version(latest) > _parse_version(inst)
            except ConfigError:
                # An unreadable UPSTREAM tag is not a fault of this box, and the
                # floor check above has already passed. Report the version we have
                # and say the comparison did not happen, rather than reddening a
                # healthy fleet over github's release naming.
                lines.append(f"  proxy version: {inst} (could not compare with the "
                             f"latest release tag {latest!r})")
                newer = None
            if newer is None:
                pass
            elif newer:
                lines.append(f"  proxy version: {inst} (latest {latest} — consider vide upgrade-sso)")
            else:
                lines.append(f"  proxy version: {inst}")
        else:
            lines.append(f"  proxy version: {inst}")
    # caddy group propagation — two failure modes: caddy never joined the group
    # at all, or it joined but the LIVE process predates the membership. Both
    # produce the identical "every SSO request 502s" outage; name each.
    entry = system.group_entry(PROXY_GROUP)
    if entry is not None:
        gid, members = entry
        if "caddy" not in members:
            lines.append("  caddy: NOT a member of vide-proxy — every SSO instance "
                         "502s; run: sudo usermod -aG vide-proxy caddy && "
                         "sudo systemctl restart caddy")
            ok = False
        else:
            pid = system.unit_main_pid("caddy.service")
            if pid is not None and gid not in system.proc_groups(pid):
                lines.append(contract.MSG_CADDY_GROUP_STALE)
                ok = False
    # The auth body IS VIDE's to re-land — render_auth_host rewrites it every
    # converge and reloads Caddy — but only when the write permit allows it, and
    # a refused converge leaves the file behind what this build emits with
    # nothing to say so. That drift is silent by construction, and it has
    # happened: the on-disk copy sat two days behind the live config. Compare the
    # copy against what this build would emit; it is the only half we can see
    # from here, and it is the half that moves first.
    # TWO FACTS, SAMPLED ONCE EACH AND THREADED DOWN, never re-derived per row.
    # They are not interchangeable, and pin_is_served says why at length:
    # `served` decides what an operator is told to PASTE, `on_pin` decides
    # whether a row may name a write the product would then refuse.
    #
    # Once each, because the two rows below choose between OPPOSITE acts on
    # `served`, and the whole value of one named fact is lost if they read the
    # host a few milliseconds apart and disagree — this section has already paid
    # once for two readers of one fact at two instants. (The bodies row is not
    # one of those two: it prescribes a single act and is deliberately silent in
    # the other direction rather than reversing.)
    served = _pin_served(cfg)
    on_pin = _gate_on_pin(cfg)
    lines.extend(_auth_block_drift(cfg, on_pin=served))
    # PART OF `ok`, unlike the drift line above it, and the asymmetry is the
    # point. A stale paste is a to-do: whatever the operator pasted is still
    # serving. A MOVED PIN is the opposite — what they pasted is still serving an
    # address this box no longer reserves, and every other row in this section is
    # computed against the pin, so without this one doctor exits 0 over a
    # fleet-wide outage with an open authorization hop.
    hop_lines, hop_ok = _abandoned_hop(cfg, on_pin=served)
    lines.extend(hop_lines)
    ok = ok and hop_ok
    # PART OF `ok`, and it is the row that closes the one state in which this
    # verb ASSERTED cleanliness over a live authorization bypass. auth.caddy
    # above is one file and a converge can be refused the write on it; these are
    # per-instance and LIVE the moment caddy reloads, and nothing in the product
    # read one until now.
    body_lines, body_ok = _stale_authz_bodies(cfg, on_pin=on_pin)
    lines.extend(body_lines)
    ok = ok and body_ok
    return ok, lines


def _auth_block_drift(cfg: Config, *, on_pin: bool) -> list[str]:
    """Advisory only — deliberately NOT part of `ok`. Whatever the operator
    pasted is still serving, and failing doctor over a file VIDE cannot write
    would train them to ignore it. Silent when the copy is current, so it costs
    a clean run nothing.

    "A stale paste is a to-do, not cosmetics" — the older wording called it
    cosmetics, and that stopped being true when the auth block gained the
    transport timeout. A box on the old paste has a LOGIN HOST THAT HANGS while
    the gate is down, where it used to fail fast. Still advisory, for the reason
    above, but `upgrade_sso` now warns about it at the moment the operator is
    already doing maintenance rather than leaving it to this line alone."""
    # Local, like every other caddy/sso reference here: both import back into
    # this module, and a top-level import would be a cycle.
    from . import caddy
    from . import sso as vide_sso
    path = Path(cfg.sso_dir) / "caddy" / "auth.caddy"
    try:
        on_disk = path.read_text(encoding="utf-8")
    except OSError:
        # No copy at all means SSO was never provisioned here; the proxy
        # sections above already say so far more usefully than this would.
        return []
    parent = vide_sso.parent_domain(cfg)
    if not parent:
        return []
    # The pin, so the detector compares against what the WRITER wrote. When
    # these were computed from different sources the drift check reported
    # permanent drift against a file the converge considered current.
    try:
        # Read ONCE, inside the guard that was already here. The second read
        # this replaced sat below the guard and unprotected, so a ConfigError
        # from it escaped an advisory row into proxy_health — one line under a
        # comment promising the exact opposite.
        pin = vide_sso.fleet_port(cfg)
        want = caddy.emit_auth_body(parent, pin, sso_dir=str(cfg.sso_dir))
    except ConfigError:
        # Same rule as proxy_health: an advisory check may not take doctor down.
        # The port section above already reports an unreadable pin, in words that
        # name the file — repeating it here would only add noise.
        return []
    if on_disk.strip() == want.strip():
        return []
    # WHICH SENTENCE, and the question this splits on changed shape entirely when
    # the body stopped being a paste. It used to be "is re-pasting safe" — one
    # diagnostic could not tell the operator to re-paste two rows above a THE PIN
    # MOVED row telling them not to, and the re-paste was the step that published
    # the fleet's login flow to an unheld address.
    #
    # Nobody re-pastes anything now. Drift means only that VIDE has not re-rendered
    # this file since the build changed, and the remedy is a verb VIDE owns. So the
    # split is no longer about danger; it is about whether that verb will WORK.
    # `render_auth_host` refuses to advance the body when doing so would repoint
    # the fleet at an address the gate is not serving, so on that box "run
    # upgrade-sso" is an instruction that will decline. Say the real state instead
    # — the same words the converge would print — and leave the pin rows above to
    # name the repair.
    #
    # `on_pin` is the SAMPLED value the caller already took (see proxy_health), so
    # every sentence in one run agrees; re-reading it here is how a diagnostic ends
    # up contradicting itself between two of its own lines.
    # `old and old != new`, NOT `old != new` — caddy.hops' own rule, which this
    # row is the second place to need: EMPTY MEANS NOTHING TO COMPARE, never "it
    # disagrees". A body carrying no hop at all (a hand-written stub, a file this
    # build did not write) would otherwise be reported as a refused repoint, in a
    # sentence naming the address it supposedly dials — with nothing to name.
    old = caddy.hops(on_disk)
    if not on_pin and old and old != caddy.hops(want):
        return [contract.MSG_AUTH_BODY_REPOINT_REFUSED.format(
            path=path, port=pin,
            held=", ".join(str(h) for h in sorted(old)))]
    return [contract.MSG_AUTH_BLOCK_MOVED.format(path=path)]


def _abandoned_hop(cfg: Config, *, on_pin: bool) -> tuple[list[str], bool]:
    """Did the fleet's pin MOVE away from the address the pasted auth block
    names? Returns (lines, ok).

    THE ONLY THING IN THE PRODUCT THAT CAN SEE THE TERMINAL STATE, and that is
    why it is part of `ok` rather than an advisory. Every other row in this
    section is computed against the PIN: after a hand edit of fleet.env, a
    converge and a reboot, systemd holds the NEW address, `covers` is true for
    it, `hop_holders(new).certain == {0}`, `usurped` and `harvesting` are false,
    and the real proxy answers /ping on it. Doctor prints `proxy port: reserved`
    and exits 0 — while the fleet's actual authorization hop, the one the
    operator's own Caddyfile still dials, is unheld, squattable, and every IDE
    behind it returns 502. A diagnostic that is green on a fleet-wide outage is
    the failure this whole section exists to stop.

    THAT SEQUENCE NO LONGER RUNS THROUGH A VIDE VERB, and the row stays anyway.
    install_proxy_socket_unit refuses to re-render the unit onto an address the
    loaded reservation does not name, so "edit, converge, reboot" now ends with
    systemd still holding the OLD address and the disagreement reported by DRIFT
    on every run. What is left reaching this row is root's own hand — a
    hand-edited unit, a drop-in, a restore from a backup taken mid-move — which
    is exactly the population a row rather than a refusal is right for. Being
    unreachable through the product is not the same as being unreachable.

    WHAT IT MAY CLAIM, AND WHAT IT MAY NOT. `auth.caddy` is what VIDE last
    WROTE, not truth about what Caddy is serving: a converge that was refused the
    write permit leaves it stale, and Caddy holds its config in memory, so even a
    fresh file proves nothing until a reload lands. The row therefore names the
    file and never says "your Caddy dials …" — and it is silent when the file is
    missing, which is the same silence _auth_block_drift keeps for the same
    reason.

    PAIRED WITH THE KERNEL, because the pasted port alone says only that two
    numbers differ. `hop_holders` on the ABANDONED address is the ground truth
    that decides whether this is a migration to finish or an open door, and it
    is the half that earns the row its place in `ok`."""
    from . import caddy, sso as vide_sso
    path = Path(cfg.sso_dir) / "caddy" / "auth.caddy"
    try:
        on_disk = path.read_text(encoding="utf-8")
    except OSError:
        return [], True
    try:
        pin = vide_sso.fleet_port(cfg)
    except ConfigError:
        return [], True          # already reported, in words that name the file
    # caddy.hops, not a second regex here. The block this file reads back is the
    # one caddy.py emitted, and the round that added a guard over the SAME format
    # in sso.py made the duplication a correctness question rather than a tidiness
    # one: two parsers of one format is how a guard passes while doctor alarms
    # about the same file.
    pasted = caddy.hops(on_disk)
    stale = sorted(p for p in pasted if p != pin)
    if not stale:
        return [], True
    # MORE THAN ONE STALE HOP MEANS THIS IS NOT A COPY THIS BUILD EMITTED.
    # emit_auth_block renders exactly one address (twice), so two of them is a
    # hand-edited or merged file with no single subject to classify and no single
    # number to put back — and the remedy below names ONE port. A remedy that is
    # still true after the operator follows it is the one shape this section
    # forbids outright, so that arm says what it sees and asks for a hand.
    if len(stale) > 1:
        return ([f"  proxy port: THE PIN MOVED — {path} names more than one "
                 f"authorization hop ("
                 + ", ".join(f"127.0.0.1:{p}" for p in stale)
                 + f") while the fleet is pinned to 127.0.0.1:{pin}. VIDE emits "
                 f"exactly one, so this file was hand-edited or merged and VIDE "
                 f"cannot say which address your Caddyfile dials. Reconcile it "
                 f"by hand against the block `vide info` prints."], False)
    old = stale[0]
    holders = system.hop_holders(old)
    # THE THIRD INPUT, AND IT IS AN ATTRIBUTION RATHER THAN A DETECTION. Before
    # it this row computed only "is anything there" and then asserted "and it is
    # not this reservation" — a claim it had never established, false in the
    # single most common state it will ever be read in. On an ordinarily-refused
    # box the write refusal is what parked the operator here, so the abandoned
    # address is held by THIS BOX'S OWN PID-1 reservation; the sentence sent them
    # to the containment ladder, and the containment actions for a squatter
    # (`systemctl stop`/`mask` the socket unit, hunt and kill) either take the
    # fleet down or free the address their Caddyfile still dials.
    who = _who_holds(holders, loaded_reservation(), old)
    tail = {
        _Holder.UNKNOWN:
            ", and VIDE could not read /proc/net/tcp, so who holds that address "
            "is unknown — it may be open. Check that /proc is mounted: "
            "`findmnt /proc`.",
        _Holder.OURS:
            ", which THIS BOX'S OWN reservation is still holding: nothing is "
            "open there and every instance behind it is still being served. "
            "What moved is the PIN, not the gate.",
        _Holder.STRANGER:
            ", which something is currently holding — and it is NOT this box's "
            "reservation. The containment ladder on the `proxy /ping` line is "
            "computed for the PIN, not for this address; read it, then apply it "
            "here.",
        _Holder.NOBODY:
            ", which NOTHING is holding: any local account can bind it and "
            "answer for every instance here.",
    }[who]
    # THE REMEDY'S DIRECTION IS A LIVE FACT, NOT A CONSTANT. "Put the pin back"
    # is the cheap, no-outage direction only while the gate is still on the OLD
    # address. On a box where the move actually LANDED, walking the pin back
    # marches the reservation off an address it is now holding — this row would
    # be prescribing the outage it exists to prevent.
    if on_pin:
        # NOTHING TO PASTE AND NOTHING TO DELETE, and the second half is why this
        # sentence is written out rather than shortened. It used to end "remove
        # {path} and re-converge" — auth.caddy, the file the operator's own
        # Caddyfile imports. Following that takes their WHOLE Caddy config down,
        # every site on the box, which is the exact outcome sso.tombstone_instance
        # refuses to create. The gate is on the pin here, so the write permit is
        # granted and one verb does all of it.
        remedy = (f" The reservation is already on 127.0.0.1:{pin}, so the move "
                  f"landed: finish it with sudo vide upgrade-sso — that "
                  f"re-renders {path} and every instance's authorization body at "
                  f"the new pin and reloads caddy. Your Caddyfile needs no edit "
                  f"and {path} must NOT be deleted: your config imports it.")
    else:
        remedy = (f" Fix it in ONE of two directions — put VIDE_SSO_PROXY_PORT "
                  f"back to {old} in {Path(cfg.sso_dir) / 'fleet.env'} (no "
                  f"re-paste, no outage), or complete the move: see docs/sso.md.")
    lines = [
        f"  proxy port: THE PIN MOVED — {path} names 127.0.0.1:{old}, the fleet "
        f"is pinned to 127.0.0.1:{pin}, and every row above is about the PIN. "
        f"While that file stands, an SSO instance served from it sends its "
        f"authorization sub-request to 127.0.0.1:{old}"
        + tail
        + " VIDE reads that file, not your running Caddy, so it cannot tell you "
          "whether the config Caddy is holding in memory agrees with it."
        + remedy]
    return lines, False


def _stale_authz_bodies(cfg: Config, *, on_pin: bool) -> tuple[list[str], bool]:
    """Does any per-instance authorization body still dial an address the fleet
    no longer pins? Returns (lines, ok).

    THE ONE STATE IN WHICH THIS VERB ASSERTED CLEANLINESS OVER A LIVE BYPASS, and
    it is manufactured by the product itself. Follow the documented move and skip
    or fail only the `sudo vide upgrade-sso` step — rerender_bodies WARNS AND
    RETURNS, deliberately and correctly — then converge again once the gate IS on
    the pin. auth.caddy is rewritten at the new pin by that converge, so
    _auth_block_drift and _abandoned_hop both go silent; the reservation covers
    the new pin and is root-held, so every reservation row is green. Doctor exits
    0 while every instance body still sends its forward_auth to the old, now-free
    address, which any local account may bind and answer 202 on — for every
    instance, collecting the fleet cookie on every request.

    THE ANSWER TO A FAIL-SOFT CONTROL IS A SENSOR, NOT A RAISE. rerender_bodies'
    warn-and-return is right: refuse the write, never the verb. This row is the
    compensating control that makes the soft failure observable after the
    operator's terminal is gone.

    IN proxy_health AND NOT IN cmd_doctor'S PER-INSTANCE LOOP. `doctor --quiet` —
    the documented cron hook, and the channel that mails on output — prints only
    proxy_health's lines, of which this row is one. A row placed in the instance
    loop would move the exit code and print nothing at all to the one reader that
    is awake at 4am."""
    from . import sso as vide_sso
    try:
        pin = vide_sso.fleet_port(cfg)
    except ConfigError:
        return [], True          # already reported, in words that name the file
    bodies, unreadable = vide_sso.authz_body_hops(cfg)
    lines: list[str] = []
    if unreadable:
        # ADVISORY, NOT PART OF `ok` — the MSG_SOCKET_UNOBSERVABLE rule: a
        # property that could not be observed is not a fault. It must still be
        # SAID, because silence here reads as agreement and this row's whole job
        # is to not be fail-open.
        lines.append(
            f"  instance bodies: not observable — {len(unreadable)} of them "
            f"under {Path(cfg.sso_dir) / 'caddy'} could not be read (that "
            f"directory is 0750 root:vide-proxy and the bodies are 0640); "
            f"re-run with sudo for this row.")
    # …and it does NOT return here. Whatever WAS readable is still evidence, and
    # discarding it because a sibling was not would let one unreadable file hide
    # every other body on the box.
    off = sorted(u for u, hops in bodies.items() if hops - {pin})
    if not off:
        return lines, True
    # SILENT WHEN THE GATE IS NOT ON THE PIN, and this is a deliberate hole
    # rather than an oversight. On that box the bodies agree with the address the
    # gate is actually on, DRIFT and THE PIN MOVED already carry the red, and the
    # only remedy this row could name — upgrade-sso, which re-renders them — is
    # the very write _refuse_a_hop_move refuses there. A row whose remedy the
    # product refuses is a row that teaches operators to stop reading rows.
    if not on_pin:
        return lines, True
    stale = sorted({p for hops in bodies.values() for p in hops} - {pin})
    # The manager is asked ONCE, not once per stale port: loaded_reservation()
    # runs a `systemctl show` and the answer is the same for every address.
    loaded = loaded_reservation()
    # ANY, not "not all": one open address among several is the open one, and
    # UNKNOWN must not fall through into the reassuring half — a kernel we could
    # not read is not evidence that somebody is there.
    open_here = any(_who_holds(system.hop_holders(p), loaded, p) is _Holder.NOBODY
                    for p in stale)
    lines.append("  instance bodies: STALE HOP — the authorization bodies VIDE "
             "wrote for " + ", ".join(off) + " send their forward_auth to "
             + ", ".join(f"127.0.0.1:{p}" for p in stale)
             + f", but the fleet is pinned to 127.0.0.1:{pin} and the gate is "
             f"holding the pin. If your Caddyfile still imports them — VIDE "
             f"printed those import lines and cannot read that file — every "
             f"request to the hosts they serve is authorized by whatever holds "
             "the old address"
             + ("; NOTHING is holding it, so any local account can bind it and "
                "answer for them." if open_here else ".")
             + " This is a half-applied move: run `sudo vide upgrade-sso` to "
             "re-render the bodies and reload caddy.")
    return lines, False
