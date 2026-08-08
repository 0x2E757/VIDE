"""Fleet SSO AUTHZ state: the per-instance email whitelists, the union
authenticated-emails file, the VIDE-owned per-instance Caddy body, the
persisted parent domain, and the socket-mode instance record. One flock
serializes every write. This module NEVER touches proxy.env/proxy.toml
(oauth2proxy.py owns those) — one writer module per file under <sso_dir>.

Authorization model (spike Q1): authentication is fleet-shared (one Google
login, one .<domain> cookie); authorization is PER INSTANCE. The union file is
the fail-closed authn base (hot-reloaded, an email on no instance is 401'd and
its session evicted); the per-instance `allowed_emails` query in the imported
Caddy body is the authz check (403 for a valid session not on THIS list).
"""
from __future__ import annotations

import fcntl
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import caddy, contract, system
from .config import Config, parse_env_file
from .errors import ConfigError, StateError, UsageError
from .executor import Executor
from .reporter import Reporter

_GMAIL_DOMAINS = ("gmail.com", "googlemail.com")


# ---- paths (all under <sso_dir>; NEVER a *.env at the top of /etc/vide, which
# ---- registry.list_instances would read back as a phantom instance) ---------
def allowlists_dir(cfg: Config) -> Path:
    return Path(cfg.sso_dir) / "allowlists"


def allowlist_file(cfg: Config, user: str) -> Path:
    return allowlists_dir(cfg) / user


def union_file(cfg: Config) -> Path:
    return Path(cfg.sso_dir) / "authenticated-emails"


def caddy_body(cfg: Config, user: str) -> Path:
    return Path(cfg.sso_dir) / "caddy" / f"{user}.caddy"


def fleet_file(cfg: Config) -> Path:
    return Path(cfg.sso_dir) / "fleet.env"


# ---- email hygiene ----------------------------------------------------------
def normalize_email(raw: str) -> str:
    """lowercase + strip, then refuse the shapes that silently misauthorize.
    The proxy's file check lowercases both sides, but the per-request query
    check is case-sensitive exact — so normalization here is what makes them
    agree. A comma is the query separator; embedded whitespace makes an entry
    unmatchable."""
    e = raw.strip().lower()
    if not e:
        raise UsageError("empty email")
    if "," in e:
        raise UsageError(f"email may not contain a comma (the query separator): {raw!r}")
    if any(c.isspace() for c in e):
        raise UsageError(f"email may not contain whitespace: {raw!r}")
    # Markup metacharacters. No real address carries them (RFC's quoted-string
    # form allows some, Google asserts none, and this gate is already stricter
    # than RFC), and an allow-listed email is REFLECTED back into HTML by the
    # per-instance /vide page. Refusing them at the only door that writes the
    # allow-list is what makes that reflection safe, rather than an escaping
    # routine sitting downstream of a validator that let the payload through.
    bad = set(e) & set("<>\"'`&{}\\")
    if bad:
        raise UsageError(f"email may not contain {''.join(sorted(bad))}: {raw!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in e):
        raise UsageError(f"email may not contain control characters: {raw!r}")
    if e.count("@") != 1 or e.startswith("@") or e.endswith("@"):
        raise UsageError(f"not a valid email address: {raw!r}")
    local, _, domain = e.partition("@")
    if not local or "." not in domain:
        raise UsageError(f"not a valid email address: {raw!r}")
    return e


def gmail_variant_warning(email: str) -> str | None:
    """Gmail ignores dots and +tags in the local part, so `j.doe@gmail.com` and
    `jdoe@gmail.com` are one account — an entry with a variant may authorize
    nobody. Warn, never gate."""
    local, _, domain = email.partition("@")
    if domain in _GMAIL_DOMAINS and ("." in local or "+" in local):
        return (f"'{email}' — gmail ignores dots and +tags in the local part; "
                "Google will assert the canonical address, which may not match")
    return None


# ---- the lock ---------------------------------------------------------------
@contextmanager
def _sso_lock(cfg: Config, timeout: float) -> Iterator[None]:
    """NON-REENTRANT: a nested acquire in the same process times out after
    `timeout` and raises StateError (bounded fail-loud, never a deadlock) —
    do not call a locked helper from under the lock. The lock file is 0600:
    flock(2) grants LOCK_EX on a read-only fd, so a laxer mode would let any
    local user wedge every verb for the timeout."""
    Path(cfg.sso_dir).mkdir(parents=True, exist_ok=True)
    fd = os.open(Path(cfg.sso_dir) / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:  # same flock(2) family + LOCK_NB poll as ports.py
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StateError(
                        f"could not acquire {cfg.sso_dir}/.lock within {timeout:.0f}s") from None
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)


# ---- parent domain ----------------------------------------------------------
def parent_domain(cfg: Config) -> str | None:
    return parse_env_file(fleet_file(cfg)).get("VIDE_SSO_PARENT_DOMAIN") or None


def fleet_pins(cfg: Config) -> dict[str, str]:
    """Every fleet-scoped value persisted at first SSO install.

    The parent domain was always here. The issuer URL and the proxy port joined
    it when proxy.toml started converging on EVERY apply: before that they were
    frozen by the fact that the file was written once, and afterwards a single
    `.env` row would have repointed the whole fleet's IdP — and desynchronised
    proxy.toml, auth.caddy and every forward_auth body from the block the
    operator pasted by hand. What is rendered on every converge must come from
    what the fleet decided, not from whatever `.env` says today."""
    return parse_env_file(fleet_file(cfg))


def _pin_port(raw: str, source: str) -> int:
    """ONE policy for a damaged port, everywhere and from either source: refuse.
    It used to be two — the renderer raised ConfigError and the other reader
    silently fell back to config, so the two consumers of one broken value
    disagreed about what the port is, which is the exact divergence the pin
    exists to prevent.

    The CONFIG value goes through here too, not only the pin. Without that, a
    `.env` row of 0 or 99999 renders into proxy.toml and into the block the
    operator pastes by hand, and is then recorded as the fleet's pin — becoming
    a value every reader afterwards refuses, with no reset verb to clear it. The
    one moment it can still be a correctable typo is before it is written down.

    `isascii()` as well as `isdigit()`: '²'.isdigit() is True and int('²')
    raises, so a hand-edited 0644 fleet.env could produce an unmapped ValueError
    traceback instead of a contract error."""
    if not (str(raw).isascii() and str(raw).isdigit() and 1 <= int(raw) <= 65535):
        raise ConfigError(f"VIDE_SSO_PROXY_PORT in {source} is not a TCP port: "
                          f"{raw!r}")
    return int(raw)


def fleet_port(cfg: Config) -> int:
    """THE reader of the shared proxy's port. Everything that renders or probes
    one comes through here — proxy.toml, the auth block the operator pastes, every
    per-instance forward_auth body, `vide info`, the drift check and all three
    /ping probes.

    One reader because the moment two of them disagree, the authz hop points at a
    port the proxy is not listening on, and any local account can bind it and
    answer 202 for every instance on the box. That was reachable: the pin landed
    in proxy.toml alone while _render_all — which runs on every allow and revoke,
    and then reloads Caddy — still read `.env` live, so one row rewrote every
    instance's body to a port nothing served and pushed it live.

    Falling back to cfg covers a box with no recorded port — a first install,
    and ALSO a fleet provisioned before this row existed, which is the honest
    caveat: on such a box `.env` still decides until the next converge records
    the pin, so the window this closes is not yet closed everywhere.
    TestI10OneReaderForTheFleetPins pins this function and fleet_issuer as the
    only places in src/vide that may read those two rows."""
    raw = fleet_pins(cfg).get("VIDE_SSO_PROXY_PORT", "")
    return (_pin_port(raw, str(fleet_file(cfg))) if raw
            else _pin_port(cfg.sso_proxy_port, "VIDE_SSO_PROXY_PORT"))


def fleet_issuer(cfg: Config) -> str:
    """THE reader of the fleet's OIDC issuer. Same rule and a sharper reason: it
    is the root of trust, and re-reading it live let one `.env` row repoint the
    whole fleet's IdP at the next restart. Re-validated on the way out because
    fleet.env is host state, not validated input — restore-from-backup and a hand
    edit both reach a render otherwise, and the file is 0644."""
    from .oauth2proxy import check_url
    issuer = (fleet_pins(cfg).get("VIDE_SSO_ISSUER_URL")
              or cfg.sso_issuer_url).rstrip("/")
    check_url(issuer, "VIDE_SSO_ISSUER_URL")
    return issuer


def persist_fleet(cfg: Config, ex: Executor, domain: str, *,
                  issuer: str, proxy_port: int) -> None:
    ex.ensure_dir(Path(cfg.sso_dir), mode=0o755, owner=("root", "root"))
    ex.atomic_write(fleet_file(cfg),
                    f"VIDE_SSO_PARENT_DOMAIN={domain}\n"
                    f"VIDE_SSO_ISSUER_URL={issuer}\n"
                    f"VIDE_SSO_PROXY_PORT={proxy_port}\n",
                    mode=0o644, owner=("root", "root"))


def persist_parent_domain(cfg: Config, ex: Executor, domain: str) -> None:
    """Back-compat entry point: the fleet file gains its two new pins from the
    CURRENT config on a box that predates them, which is right — that box has
    been running on those values all along."""
    persist_fleet(cfg, ex, domain, issuer=cfg.sso_issuer_url.rstrip("/"),
                  proxy_port=cfg.sso_proxy_port)


# ---- allow-list I/O ---------------------------------------------------------
def read_allowlist(cfg: Config, user: str) -> list[str]:
    f = allowlist_file(cfg, user)
    try:
        text = f.read_text()
    except OSError:
        return []
    return sorted({ln.strip() for ln in text.splitlines() if ln.strip()})


def _all_emails(cfg: Config) -> set[str]:
    out: set[str] = set()
    d = allowlists_dir(cfg)
    if d.is_dir():
        for f in d.iterdir():
            if f.is_file():
                out |= set(read_allowlist(cfg, f.name))
    return out


def _authz_hops(cfg: Config, users: list[str]) -> set[int]:
    """Every 127.0.0.1 port the authorization artifacts ALREADY on this box send
    their forward_auth to.

    FILES ONLY, and that is what makes the guard below free on every healthy box:
    these are two records VIDE itself wrote, so answering "would this render move
    the fleet's hop" needs no host read at all. An unreadable or absent file
    contributes nothing — a tombstoned body carries no upstream, and a first
    install has no bodies — so absence can never be mistaken for disagreement and
    a destroyed instance can never refuse a grant on a live one.

    auth.caddy IS INCLUDED, AND IT IS NOT REDUNDANT. Where instances exist their
    bodies already answer, but on a box whose instances were all destroyed the
    bodies are gone while auth.caddy still remembers what the operator pasted
    from — and that is exactly the box where a pre-pin fleet can be re-pointed by
    one `VIDE_SSO_PROXY_PORT=<n> sudo -E vide allow`, with no file written and
    nothing left behind. It is a REFUSAL input only: stale means an extra
    refusal, absent means silence, and both fail in the safe direction.

    NOT MERGED WITH authz_body_hops BELOW, which walks the same directory for
    doctor. The `users` filter here is load-bearing in a way it is not there: a
    body left behind by a destroyed instance may not refuse a grant on a live
    one, while for a sensor that same orphan is exactly what must be reported."""
    out: set[int] = set()
    for user in users:
        try:
            out |= caddy.hops(caddy_body(cfg, user).read_text(encoding="utf-8"))
        except OSError:
            pass
    try:
        out |= caddy.hops(
            (Path(cfg.sso_dir) / "caddy" / "auth.caddy").read_text(encoding="utf-8"))
    except OSError:
        pass
    return out


def authz_body_hops(cfg: Config) -> tuple[dict[str, set[int]], list[str]]:
    """Every per-instance authorization body ON DISK, by user, with the hops it
    dials — plus the ones that could not be READ, which is a different answer and
    may not be folded into the first.

    A WALK, NOT A NAME LIST, and that is the whole difference from _authz_hops
    above. That one is keyed by the users a render is about, which is right for a
    refusal input and wrong for a sensor: a body left behind by an instance whose
    allow-list is gone still dials whatever it dials, and the operator's Caddyfile
    still imports it by name. The danger here is per-FILE, so the files are what
    is enumerated.

    THE UNREADABLE LIST IS SEPARATE BECAUSE THE CALLER MUST NOT GO GREEN ON IT.
    These bodies are 0640 root:vide-proxy, so a doctor run as anyone else reads
    none of them — and "no hops found" would then be indistinguishable from
    "every hop agrees", which is fail-open in the one row that exists to be
    fail-closed.

    auth.caddy IS EXCLUDED, and the reason survived the change that made it a
    VIDE-owned import rather than a pasted copy — one clause of it did not, and is
    corrected here rather than left to read as still true. "VIDE cannot re-render
    it" is now FALSE: converge_proxy writes it every run. What is still true is
    that _abandoned_hop owns it, that these bodies answer a different question
    (which instances dial the wrong hop) with a different repair, and that
    allow/revoke — the writes this enumeration serves — do not touch the auth host
    at all, since it authorizes nobody. Mixing them would put one remedy on two
    artifacts whose repair paths never coincided.

    The pages/ subdirectory that arrived with the same change is skipped for free
    by the suffix test below, and deliberately so: it holds static HTML, dials
    nothing, and could contribute no hop even if it were read."""
    out: dict[str, set[int]] = {}
    unreadable: list[str] = []
    d = Path(cfg.sso_dir) / "caddy"
    # THE DIRECTORY IS TESTED BEFORE THE FILES, and this is the whole
    # fail-closed property rather than a nicety. `Path.glob` SWALLOWS the
    # PermissionError from scandir and yields nothing — so on the shipped
    # posture (this directory is 0750 root:vide-proxy) a non-root `vide doctor`
    # got an empty walk, an empty `unreadable`, and read it as "every body
    # agrees with the pin". The per-file arm below cannot catch that: anyone who
    # can list a 0750 directory can read the 0640 files inside it, so the
    # two-arms-per-file shape covered a state the product cannot produce while
    # missing the one it produces on every non-root invocation. `doctor` and
    # `info` are both needs_root=False.
    try:
        entries = sorted(d.iterdir())
    except OSError:
        # One sentinel, not a per-file list: nothing here was observed at all.
        return {}, ["<the authorization directory could not be listed>"]
    for f in entries:
        if f.suffix != ".caddy" or f.name == "auth.caddy":
            continue
        try:
            # A tombstoned body carries no upstream, so a destroyed instance
            # contributes an empty set and falls out of every comparison on its
            # own — the same "empty means nothing to compare, never it
            # disagrees" rule caddy.hops states.
            out[f.stem] = caddy.hops(f.read_text(encoding="utf-8"))
        except OSError:
            unreadable.append(f.stem)
    return out, unreadable


# A FILE-ONLY "are our records stale" reader was written here for `vide info`
# and then removed rather than kept, and the reason is worth recording so it is
# not reinvented. It asked whether this box's own artifacts still name a hop the
# fleet does not pin — no host read, an answer on a wedged box, which is the
# right shape for a read-only verb. But it could not AGREE with doctor: on a
# landed move whose auth.caddy is still behind, doctor says "re-paste" while the
# records still name the old hop, so `vide info` said DO NOT about the very
# block doctor had just asked for. Whether pasting is safe is not a property of
# any file VIDE holds — it is whether the address the fresh block NAMES is being
# served — so the verb asks oauth2proxy.pin_is_served, the same fact doctor uses.
# Two channels, one answer, by construction rather than by review.


def _refuse_a_hop_move(cfg: Config, port: int, users: list[str]) -> None:
    """Refuse to repoint the whole fleet's authorization hop as a side effect of
    a grant.

    THE MOST REACHABLE ROUTE INTO THE ABUSE CASE, and until now it was guarded by
    nothing. _render_all reads the pin live and rewrites EVERY instance's
    forward_auth upstream, and its callers then reload Caddy — so one edited row
    plus one `vide allow` pointed the authorization sub-request of every
    `auth: none` IDE on the box at an address nothing was holding, and pushed it
    live. Any local account can then bind that address and answer 202 for every
    instance, receiving the fleet cookie on every request.

    DETECTION IS FILES, THE PERMIT IS THE KERNEL, and the asymmetry is the point.
    Evidence to REFUSE comes from records VIDE wrote, which are always readable;
    evidence to PERMIT must come from the live box, so an unreadable one refuses.
    That ordering is also what keeps the guard free: on every healthy box, and on
    every first install, nothing moves and no host read is performed at all.

    WHERE IT SITS IS A SECURITY PROPERTY, NOT STYLE. It runs after _write_union,
    so a revoke still evicts the address fleet-wide before this can refuse —
    above that write, a moved pin would turn a revocation into a no-op during the
    one incident it exists for."""
    named = sorted(_authz_hops(cfg, users) - {port})
    if not named:
        return
    from .oauth2proxy import SOCKET_UNIT, SYSTEMD_DIR, gate_is_on_hop
    if gate_is_on_hop(port):
        # The documented move completed: the gate is demonstrably on the pin, so
        # the bodies are the half still lagging and rendering them is the repair.
        return
    raise StateError(contract.MSG_PROXY_HOP_MOVE_REFUSED.format(
        port=port, named=", ".join(f"127.0.0.1:{p}" for p in named),
        unit_path=SYSTEMD_DIR / SOCKET_UNIT,
        fleet_file=fleet_file(cfg)))


def _render_all(cfg: Config, ex: Executor) -> None:
    """Re-render the union authn file and every per-instance Caddy body from the
    canonical allow-lists. Called under the lock after any mutation. The union
    is written FIRST — it is the fail-closed authn base and must reflect a
    revocation even when the body render below refuses (tombstone catches that
    refusal and keeps tearing down)."""
    ex.ensure_dir(Path(cfg.sso_dir), mode=0o755, owner=("root", "root"))
    ex.ensure_dir(Path(cfg.sso_dir) / "caddy", mode=0o750, owner=("root", "vide-proxy"))
    _write_union(cfg, ex)
    parent = parent_domain(cfg) or ""
    d = allowlists_dir(cfg)
    files = [f for f in sorted(d.iterdir()) if f.is_file()] if d.is_dir() else []
    if files:
        _require_parent(cfg, parent)
        # Read once, and on THIS side of _write_union: a revoke must still evict
        # the email fleet-wide when the pin is damaged and the body render below
        # refuses. The pin rather than config, because this loop runs on every
        # allow and revoke and its callers then reload Caddy — so a live read
        # let one `.env` row rewrite every instance's authz hop to a port the
        # proxy is not listening on, and push it live. Any local account can
        # bind a free loopback port and answer 202 for every instance on the box.
        port = fleet_port(cfg)
        # …and reading ONE pin is only half of it. The pin says where the fleet
        # decided to be; it does not say that moving there is safe. Beside
        # _require_parent and after the union write, for the same reason that one
        # is here: both refuse the BODY render and neither may cost a revocation.
        _refuse_a_hop_move(cfg, port, [f.name for f in files])
    for f in files:
        user = f.name
        sock = str(system.socket_path(user))
        body = caddy.render_forward_auth_body(
            user, read_allowlist(cfg, user), parent, sock, port)
        ex.atomic_write(caddy_body(cfg, user), body,
                        mode=0o640, owner=("root", "vide-proxy"))


def _require_parent(cfg: Config, parent: str) -> None:
    """Refuse to render authz bodies without a valid recorded parent domain.
    A lost/blank fleet.env (the restored-from-backup box) would otherwise write
    `redir * https://auth.//oauth2/start...` into every body and reload caddy —
    a silently broken login for the whole fleet, surfacing only as a browser
    dead-end VIDE never sees. Shape-checked too: fleet.env is host state, not
    validated input, and the parent is interpolated into the redirect."""
    if not parent:
        raise StateError(
            f"VIDE_SSO_PARENT_DOMAIN is missing from {fleet_file(cfg)} — SSO "
            "instances exist but the shared parent domain is unrecorded; the "
            "login redirect is built from it. Restore the line "
            "(VIDE_SSO_PARENT_DOMAIN=<domain>) or re-run: sudo ./install.sh --auth sso")
    from .oauth2proxy import check_dns_name
    check_dns_name(parent, f"parent domain (from {fleet_file(cfg)})")


def _write_union(cfg: Config, ex: Executor) -> None:
    """The ONE writer of the union authn file. The mode/owner tuple is
    load-bearing platform contract: the proxy unit runs User=vide-oauth2 with
    no Group=, so readability rests entirely on this group + the group-read
    bit — edit it here or nowhere."""
    union = "".join(f"{e}\n" for e in sorted(_all_emails(cfg)))
    ex.atomic_write(union_file(cfg), union, mode=0o640, owner=("root", "vide-oauth2"))


def seed_union(cfg: Config, ex: Executor) -> None:
    """Bootstrap-time union seeding (called by oauth2proxy.converge_proxy — the
    union is THIS module's file, so the write happens here, under the same lock
    allow/revoke hold; never call it while already holding _sso_lock). Renders
    FROM the canonical allow-lists: a blind `write "" if missing` raced a
    concurrent `vide allow` between its exists() check and its write,
    truncating a just-populated union — a fail-closed fleet-wide 401 until the
    next re-render. Deriving is also converge-shaped: it heals a torn union
    instead of assuming empty. A preview narrates and returns before the lock —
    it must not create <sso_dir>/.lock (the allow() precedent)."""
    if ex.narrate("would seed the authenticated-emails union from the allow-lists"):
        return
    with _sso_lock(cfg, cfg.lock_timeout):
        _write_union(cfg, ex)


def rerender_bodies(cfg: Config, ex: Executor, rep: Reporter) -> None:
    """Re-render every per-instance authz body from the canonical allow-lists,
    then reload caddy. Called by `vide upgrade-sso`.

    THE GAP THIS CLOSES. The per-instance bodies are VIDE-owned files, but
    nothing re-renders them on a converge: `_render_all` runs from allow, revoke
    and destroy only. So a change to what render_forward_auth_body EMITS — a new
    directive, a corrected matcher, a timeout — reached a provisioned box at its
    next `vide allow` and not before, which on a stable fleet is never. The
    bodies silently described an older build for as long as nobody added a user.

    Deliberately NOT called from converge_proxy, for the same reason converge
    does not restart the proxy: a converge runs FOR SOMEONE ELSE, and rewriting
    every instance's authorization hop plus reloading the operator's Caddy during
    user B's install puts A, C and D at risk of B's run. `upgrade-sso` is the
    operator's explicit "apply it now", and it is already the lever that lands
    the unit and the port reservation — so one lever lands all three, and a box
    is either migrated or it is not.

    fail_soft on the reload, like destroy's: the bodies on disk are already
    correct at this point, and a Caddy that refuses to reload for an unrelated
    reason in the operator's own config must not turn an upgrade into a
    traceback. The next allow/revoke reloads again.

    AND THE HOP-MOVE REFUSAL IS CAUGHT HERE FOR THE SAME REASON THE RELOAD IS.
    This runs at the TAIL of `upgrade-sso` — after the binary has been swapped,
    the gate restarted and the old version pruned — so a raise would report
    failure for a run that already succeeded at its primary purpose, and would
    skip the auth-block warning that follows it. Nothing is weakened by warning
    instead: the control fired, the bodies were not moved, and only the exit code
    is at stake. It is the same "refuse the write, not the verb" this release
    applies to the reservation unit, one module over. `allow` and `revoke` let it
    raise — the operator is present, the union write has already landed, and the
    failure is fail-closed."""
    if ex.narrate("would re-render every instance's Caddy authz body"):
        return
    try:
        with _sso_lock(cfg, cfg.lock_timeout):
            _render_all(cfg, ex)
    except (StateError, ConfigError) as e:
        rep.warn(f"{e} — the instance authorization bodies were not re-rendered.")
        return
    reload_caddy(ex, rep, fail_soft=True)


def reload_caddy(ex: Executor, rep: Reporter, *, fail_soft: bool = False) -> None:
    """The graceful reload the allow/revoke verbs run themselves (ratified): a
    reload is NOT the prohibited restart, and a revoke that silently waits for a
    human is fail-open — so by default a failure is loud AND re-raised, with the
    manual remediation printed (the union file still gives immediate fleet-exit
    revocation regardless).

    fail_soft is for the DESTROY/tombstone path only: on exactly the box a failed
    SSO install produces (Caddy absent or unconfigured) the reload cannot succeed,
    and it must not abort the teardown before stop/disable/rm. The allow-list is
    already dropped on disk, so the authz state is correct the moment any Caddy
    reads it; only the live reload is deferred."""
    try:
        ex.run(["systemctl", "reload", "caddy"])
    except Exception as e:  # noqa: BLE001 — surface, with a manual fallback
        rep.warn(f"could not reload caddy ({e}); run: sudo systemctl reload caddy")
        if not fail_soft:
            raise


def _write_allowlist(cfg: Config, ex: Executor, user: str, emails: list[str]) -> None:
    ex.ensure_dir(allowlists_dir(cfg), mode=0o700, owner=("root", "root"))
    ex.atomic_write(allowlist_file(cfg, user), "".join(f"{e}\n" for e in sorted(emails)),
                    mode=0o600, owner=("root", "root"))


def allow(cfg: Config, ex: Executor, rep: Reporter, user: str, email: str,
          *, force_restart: bool = False) -> None:
    """Idempotent, converge-shaped. Adds the email, re-renders, reloads caddy."""
    email = normalize_email(email)
    warn = gmail_variant_warning(email)
    if warn:
        rep.warn(warn)
    # A preview mutates nothing and must not create <sso_dir>/.lock or touch the
    # allow-lists — narrate and return, the ports.claim_port precedent.
    if ex.narrate(f"would allow '{email}' on '{user}' and reload caddy"):
        return
    with _sso_lock(cfg, cfg.lock_timeout):
        cur = read_allowlist(cfg, user)
        if email in cur:
            rep.info(f"'{email}' already allowed on '{user}'")
        else:
            _write_allowlist(cfg, ex, user, [*cur, email])
            rep.info(f"allowed '{email}' on '{user}'")
        _render_all(cfg, ex)
        reload_caddy(ex, rep)
        if force_restart:
            ex.run(["systemctl", "restart", "vide-oauth2-proxy.service"])


def revoke(cfg: Config, ex: Executor, rep: Reporter, user: str, email: str,
           *, force_restart: bool = False) -> None:
    """Idempotent, converge-shaped. The last-email case is caller-gated
    destructive (the instance becomes deny-all)."""
    email = normalize_email(email)
    if ex.narrate(f"would revoke '{email}' from '{user}' and reload caddy"):
        return
    with _sso_lock(cfg, cfg.lock_timeout):
        cur = read_allowlist(cfg, user)
        if email not in cur:
            rep.info(f"'{email}' was not on '{user}'")
        else:
            _write_allowlist(cfg, ex, user, [e for e in cur if e != email])
            rep.info(f"revoked '{email}' from '{user}'")
        _render_all(cfg, ex)
        reload_caddy(ex, rep)
        if force_restart:
            ex.run(["systemctl", "restart", "vide-oauth2-proxy.service"])


def would_empty(cfg: Config, user: str, email: str) -> bool:
    """True iff revoking `email` leaves `user` with no allowed addresses — the
    deny-all state the CLI gates behind a destructive confirm."""
    try:
        email = normalize_email(email)
    except UsageError:
        return False
    cur = read_allowlist(cfg, user)
    return email in cur and len(cur) == 1


# ---- the socket-mode instance record ----------------------------------------
def claim_binding(cfg: Config, ex: Executor, rep: Reporter, user: str, fqdn: str = ""):
    """The sso twin of ports.claim_port: derive the deterministic socket path
    (no allocator, no lock — the path is a pure function of the username) and
    persist the SOCKET_RECORD (mode + socket + fqdn). Returns a Binding."""
    from .registry import Binding
    sock = system.socket_path(user)
    if ex.narrate(f"would record sso socket binding for {user}: {sock}"):
        return Binding.unix(sock)
    ex.ensure_dir(Path(cfg.state_dir), mode=0o755, owner=("root", "root"))
    ex.atomic_write(Path(cfg.state_dir) / f"{user}.env",
                    contract.SOCKET_RECORD.format(socket=sock, fqdn=fqdn),
                    mode=0o644, owner=("root", "root"))
    return Binding.unix(sock)


def recorded_fqdn(cfg: Config, user: str) -> str:
    """The FQDN persisted in an sso instance's record (empty if none)."""
    return parse_env_file(Path(cfg.state_dir) / f"{user}.env").get("VIDE_FQDN", "")


def tombstone_instance(cfg: Config, ex: Executor, rep: Reporter, user: str) -> None:
    """Called by `vide destroy` of an SSO instance. Rewrites the imported Caddy
    body to a 410 tombstone (NEVER deletes it — a dangling import fails the
    operator's whole Caddy config load), drops the allow-list, re-renders the
    union, reloads caddy."""
    if ex.narrate(f"would tombstone the caddy body for '{user}' and reload caddy"):
        return
    with _sso_lock(cfg, cfg.lock_timeout):
        ex.ensure_dir(Path(cfg.sso_dir) / "caddy", mode=0o750, owner=("root", "vide-proxy"))
        ex.atomic_write(caddy_body(cfg, user), caddy.render_tombstone(user),
                        mode=0o640, owner=("root", "vide-proxy"))
        af = allowlist_file(cfg, user)
        if af.exists() or ex.dry_run:
            ex.run(["rm", "-f", str(af)])
        # D6 applies to the render too: destroy runs on damaged boxes by design.
        # _render_all writes the union BEFORE the parent guard can fire, so the
        # revocation is applied even when fleet.env is lost; only the OTHER
        # instances' bodies stay as-is. Warn and keep tearing down.
        try:
            _render_all(cfg, ex)
        except (StateError, ConfigError) as e:
            rep.warn(f"could not re-render the caddy bodies ({e}) — "
                     "continuing the teardown")
        # D6: fail-soft — a destroy runs on exactly the box a failed install left
        # (Caddy absent/unconfigured), and must complete stop/disable/rm even when
        # the reload cannot. The allow-list is already gone from disk above.
        reload_caddy(ex, rep, fail_soft=True)
    rep.info(f"tombstoned {user}: remove the pasted block from your Caddyfile, "
             f"then delete {caddy_body(cfg, user)}")
