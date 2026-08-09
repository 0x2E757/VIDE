"""Gates before any mutation. In dry-run, failures WARN instead of aborting
(so a preview runs on any box) — skipping an assertion, never a mutation.

The gate is SPLIT because the two halves must straddle ensure_prereqs:

    preflight_platform   facts apt CANNOT fix (distro, CPU arch, systemd)
    ensure_prereqs       apt-get install argon2 curl git ca-certificates
    preflight_tools      the command floor — checked AFTER apt installed curl

Merging them forces a false choice: gate `curl` before ensure_prereqs and a
bare Debian box is refused for a tool apt was about to install; gate the
distro after it and a Fedora box dies on `apt-get: command not found` before
the polished refusal ever speaks. The boundary is exactly "unfixable facts"
vs "just-installed tools". The install sequencer pins this ordering with a
trace test.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping

from .config import Config
from .errors import ConfigError, UnavailableError, VideError
from .executor import Executor
from .reporter import Reporter
from . import system

# apt-get is deliberately NOT listed: the distro gate is the stronger,
# semantic assertion of the same fact. openssl stays on the floor for slice 1
# even though Python now generates entropy via the stdlib `secrets` module —
# trimming the documented floor is a contract change to ratify separately.
REQUIRED_TOOLS: tuple[str, ...] = ("curl", "openssl", "ss", "systemctl")

# Only these have upstream STANDALONE binaries for BOTH toolchains VIDE
# downloads: Node via nvm (Tier-1 x64/arm64 only at these majors) AND
# code-server --method standalone (amd64/arm64 only). Anything else
# half-installs, then 404s at the toolchain fetch.
SUPPORTED_MACHINES: frozenset[str] = frozenset({"x86_64", "amd64", "aarch64", "arm64"})


def _pf_fail(dry_run: bool, rep: Reporter, err: VideError) -> None:
    if dry_run:
        rep.warn(f"preflight (dry-run): {err}")
        return
    raise err


def arch_supported(machine: str) -> bool:
    return machine in SUPPORTED_MACHINES


def platform_gate(cfg: Config, ex: Executor, rep: Reporter) -> None:
    osr = system.os_release(cfg.os_release_file)
    if osr is None:
        _pf_fail(ex.dry_run, rep,
                 ConfigError("/etc/os-release missing; cannot confirm Debian/Ubuntu"))
    else:
        # Debian ships NO ID_LIKE — match against both fields, word-split.
        words = set(osr.id.split()) | set(osr.id_like.split())
        if words & {"debian", "ubuntu"}:
            rep.debug(f"distro ok: {osr.pretty_name or osr.id or '?'}")
        else:
            detected = osr.id or "unknown"
            pretty = f" ({osr.pretty_name})" if osr.pretty_name else ""
            _pf_fail(ex.dry_run, rep, ConfigError(
                f"unsupported distro '{detected}'{pretty}: VIDE targets Debian/Ubuntu"))

    machine = system.uname_m(cfg.uname_m)
    if not arch_supported(machine):
        _pf_fail(ex.dry_run, rep, ConfigError(
            f"unsupported CPU architecture '{machine}': VIDE needs x86_64/amd64 or "
            "aarch64/arm64 — upstream Node.js and code-server ship no standalone "
            "binary for it (32-bit Pi/armv7l, i686, riscv64 would half-install, "
            "then 404 at the toolchain fetch)"))

    if not system.systemd_present():
        _pf_fail(ex.dry_run, rep,
                 UnavailableError("systemd not detected (no /run/systemd/system)"))


#: What must be trustworthy inside the checkout. `.env` leads because it is the
#: only one an operator edits, and the only one that is optional.
#: The named top-level entries. `src` and `units` appear here for their OWN modes
#: and are then WALKED (below), never enumerated.
_GATED_ENTRIES: tuple[str, ...] = (".env", "install.sh", "vide", "src", "units")
#: …and everything beneath these, recursively. An enumeration had three holes at
#: once — `src/vide` was missing from this half, `src/vide/tui` from BOTH halves
#: (it is imported as root on every wizard install), and `__pycache__` from
#: either — because a list has to be extended whenever a subpackage is added and
#: nobody adding one is thinking about this file. The predicate is unchanged;
#: only the path set grows, so the stock `git clone` this gate is careful not to
#: refuse is still not refused.
_GATED_TREES: tuple[str, ...] = ("src", "units")


def checkout_gate(repo_dir: Path, *, dry_run: bool, rep: Reporter,
                  trusted_uids: frozenset[int],
                  walk_root: Path | None = None,
                  group_writers: Callable[[int], frozenset[int] | None]
                  = system.group_writer_uids) -> None:
    """Refuse to run code out of a checkout a third party can rewrite.

    `sudo ./install.sh` executes this repository AS ROOT, and `.env` is
    root-equivalent in full. Named rows are the loud half — `VIDE_NVM_INSTALLER_URL`
    and `VIDE_PNPM_INSTALLER_URL` are fetched and executed as root,
    `VIDE_PNPM_GLOBAL_SUBDIR` lands in /etc/profile.d and is sourced by every
    login shell — but the general case is broader: config.load_config
    `setdefault`s EVERY key into os.environ, which _spawn hands to every root
    child, so an unnamed row (LD_PRELOAD, BASH_ENV) reaches them too. Do not
    reduce this to an enumeration; a list here reads as exhaustive and is not.
    So whoever can write the checkout already has root at the operator's next
    converge — silently, and with no other gate anywhere in the tree.

    The predicate is NOT "root-owned", which would break the README's own first
    command for everybody. It is **writable only by principals already entitled
    to root**: owned by a trusted uid, and not group- or other-writable. Alice
    running `sudo ./install.sh` on her own clone is not an escalation — she can
    already reach root. Bob running it on Alice's clone is.

    Trusting SUDO_UID is exactly as trustworthy as the rest of root's
    environment, and the tree already makes that call for SUDO_USER
    (install_flow.resolve_plan). Stated here rather than assumed.

    Ancestors count: a 0755 tree inside a 0777 directory is rewritable by
    renaming the tree out from under it, so `/tmp/vide` is refused — no sticky
    exception, since that is the classic hostile location rather than an edge
    case. `.env` is lstat-ed: a root-owned `.env` SYMLINKED from a world-
    writable directory is the whole attack, and `stat` would follow it and
    report the innocent target.

    `walk_root` bounds the ancestor walk and `group_writers` resolves a gid to
    the uids behind it; both exist because the gate is otherwise untestable —
    every temp dir lives under /tmp, /tmp is 0o1777, and the box's real groups
    are not a fixture. Production passes neither. Same seam as
    system.os_release(path) and system.socket_path(run_dir=...).

    Never prints the file's contents — only its path and the remedy."""
    def refuse(what: str, why: str) -> None:
        # The remedy leads with RE-CLONE, and the ordering is the point. This gate
        # asks "can a third party write this NOW", never "has one ever" — so if the
        # answer was ever yes, the tree's CONTENTS are suspect and no permission
        # change restores them. The old remedy offered only chown/chmod, which
        # sanitizes every mode and no byte, and left the reader believing the
        # checkout was safe again.
        _pf_fail(dry_run, rep, ConfigError(
            f"refusing to run from an untrusted checkout: {what} {why}. VIDE "
            f"executes this tree as root, so it must be writable only by root or "
            f"by the operator invoking sudo.\n"
            f"  Fix it properly: re-clone into a location only root can write "
            f"(e.g. /opt/vide-src). Permissions can be repaired; contents cannot "
            f"be un-read, and this check cannot tell you whether anything was "
            f"already changed.\n"
            f"  If you are certain nothing was written: chown -R root: {repo_dir} "
            f"&& chmod -R go-w {repo_dir} && rm -rf {repo_dir}/src/vide/__pycache__ "
            f"{repo_dir}/src/vide/tui/__pycache__ — the __pycache__ removal is not "
            f"optional and not cosmetic: a .pyc there is loaded in preference to "
            f"the .py you just reviewed, it is gitignored so it shows in no diff, "
            f"and it survives the chown perfectly well. (Do not reach for "
            f"`git clean -xdf` here — it deletes your .env too.)\n"
            f"  Read-only commands that do NOT come through this gate and still "
            f"work: systemctl status code-server@<user>, journalctl -u "
            f"code-server@<user>."))

    def unsafe(f) -> str:
        """Why a third party could write this path, or "" if none could.

        Deliberately NOT `mode & 0o022`: Debian and Ubuntu default to umask 002
        AND to user-private groups, so a plain `git clone` yields a 0775 tree
        owned by `alice:alice` — group-writable by a group containing only
        alice. Refusing that would refuse the documented quick-start clone on a
        stock box. The real question is whether any uid OUTSIDE the trusted set can
        write, so the group is resolved rather than assumed."""
        if f.mode & 0o002:
            return f"is world-writable (mode {f.mode:04o})"
        if f.mode & 0o020:
            writers = group_writers(f.gid)
            if writers is None:
                return (f"is group-writable (mode {f.mode:04o}) by gid {f.gid}, "
                        f"which does not resolve")
            outside = writers - trusted_uids
            if outside:
                return (f"is group-writable (mode {f.mode:04o}) by gid {f.gid}, "
                        f"whose members include uid(s) "
                        f"{', '.join(str(u) for u in sorted(outside))}")
        return ""

    resolved = Path(repo_dir).resolve()
    chain: list[Path] = [*reversed(resolved.parents), resolved]
    if walk_root is not None:
        stop = Path(walk_root).resolve()
        chain = [p for p in chain if p == stop or stop in p.parents]
    # Ancestors first: an unsafe parent makes every check below it moot.
    for anc in chain:
        f = system.path_facts(anc)
        if f is None:
            continue  # a path that vanished mid-walk is not this gate's business
        if f.uid not in trusted_uids:
            return refuse(str(anc), f"is owned by uid {f.uid}, which is not root "
                                    f"and not the sudo caller")
        if (why := unsafe(f)):
            return refuse(str(anc), why)

    def gated_paths():
        for name in _GATED_ENTRIES:
            yield name, resolved / name
        # Sorted, so a refusal names the same path on every box and a bug report
        # from one machine is reproducible on another. rglob follows no symlinks,
        # which is what this wants: a link inside the tree is judged as the link.
        for tree in _GATED_TREES:
            for p in sorted((resolved / tree).rglob("*")):
                yield p.name, p

    for name, p in gated_paths():
        f = system.path_facts(p)
        if f is None:
            continue  # .env is optional; the rest are absent only in a broken tree
        if name == ".env" and f.is_symlink:
            return refuse(str(p), "is a symlink (its target's ownership says "
                                  "nothing about who can repoint it)")
        if f.uid not in trusted_uids:
            return refuse(str(p), f"is owned by uid {f.uid}, which is not root "
                                  f"and not the sudo caller")
        if (why := unsafe(f)):
            return refuse(str(p), why)


def trusted_uids_from_env(environ: Mapping[str, str]) -> frozenset[int]:
    """root, plus the uid behind sudo when there is one. Read from the process
    environment ONLY — a VIDE_* setting that could widen this set would be a
    waiver by another name, and would be settable from the very `.env` the gate
    exists to judge."""
    uids = {0}
    raw = environ.get("SUDO_UID", "").strip()
    if raw.isdigit():
        uids.add(int(raw))
    return frozenset(uids)


def tools_gate(ex: Executor, rep: Reporter) -> None:
    missing = [c for c in REQUIRED_TOOLS if not system.have_cmd(c)]
    if missing:
        _pf_fail(ex.dry_run, rep,
                 UnavailableError(f"missing required command(s): {' '.join(missing)}"))
