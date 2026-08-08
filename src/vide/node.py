"""Install Node.js (via nvm) + pnpm ONCE, system-wide, into world-traversable
/opt, exposed to all users / systemd / non-interactive shells via the shared
bin dir. Designed for multi-year durability:

  * install-once is separated from converge-every-run;
  * the CONVERGE path is NETWORK-FREE and self-healing (re-resolves the
    node/pnpm binaries from the on-disk layout and re-points the links/wrapper,
    re-applies world-traversable perms, re-asserts the per-user PNPM_HOME
    profile) — so nothing rots after day one and the ONLY step that can 404 is
    a missing install.

Every hard-won external-world fact in the bash survives here; each carries its
provenance comment. This module is where all three historical shipped bugs
lived — treat every "simplification" as a suspect.
"""
from __future__ import annotations

import re
from pathlib import Path

from .config import Config
from .errors import ConfigError, Ex
from .executor import Executor
from .reporter import Reporter
from . import contract, system

# ---- pure helpers -----------------------------------------------------------


def node_major(version: str) -> int | None:
    """Leading major integer (strips a 'v'), or None if unparseable."""
    v = version.lstrip("v").split(".", 1)[0]
    return int(v) if re.fullmatch(r"[0-9]+", v) else None


def _parse_version(v: str) -> tuple[int, ...] | None:
    parts = v.lstrip("v").split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def nvm_resolve_bindir(nvm_dir: Path, node_major_floor: int) -> Path | None:
    """Highest installed Node >= major, resolved purely from the on-disk nvm
    layout (versions/node/vX.Y.Z/bin), NOT `nvm which`. Stable across nvm
    versions; network-free; heals a dangling symlink; adopts a newer patch.
    Versions compare as INTEGER TUPLES (bash used sort -V; a naive string
    compare regresses 9.10 < 9.9)."""
    best: tuple[tuple[int, ...], Path] | None = None
    for bindir in nvm_dir.glob("versions/node/v*/bin"):
        node = bindir / "node"
        if not (node.is_file() and node.stat().st_mode & 0o111):
            continue
        parsed = _parse_version(bindir.parent.name)
        if parsed is None or parsed[0] < node_major_floor:
            continue
        if best is None or parsed > best[0]:
            best = (parsed, bindir)
    return best[1] if best else None


def pnpm_resolve_bin(pnpm_home: Path) -> Path | None:
    """Absolute path to the pnpm executable the installer dropped, resolved
    from the on-disk layout rather than a fixed filename: `pnpm setup`'s target
    dir has moved across pnpm majors (<=v10 flat $PNPM_HOME/pnpm; v11+
    $PNPM_HOME/bin/pnpm). Canonical (bin/) wins over legacy (flat); a glob
    backstop catches a future relocation. Network-free."""
    candidates = [pnpm_home / "bin/pnpm", pnpm_home / "pnpm"]
    candidates += sorted(pnpm_home.glob("*/pnpm"))
    for c in candidates:
        if c.is_file() and c.stat().st_mode & 0o111:
            return c
    return None


def emit_pnpm_launcher(abs_pnpm: Path) -> str:
    """Content for <bin_dir>/pnpm. pnpm's cmd-shim finds its payload RELATIVE
    to $0's directory and does NOT canonicalise symlinks, so a plain symlink
    sends it hunting under <bin_dir>/../global (wrong). A tiny exec wrapper
    calling the shim by ABSOLUTE path keeps that $0-relative lookup anchored.
    (node/npm/npx DO canonicalise $0, so they stay plain symlinks; only pnpm
    needs this.) Regenerated on every converge with the freshly-resolved path."""
    return f"""#!/bin/sh
# Managed by VIDE (vide/node.py emit_pnpm_launcher). pnpm's shim is $0-relative
# and not symlink-safe; invoke it by absolute path so its payload stays under
# the shared pnpm home. Regenerated on every converge.
exec "{abs_pnpm}" "$@"
"""


# A path SEGMENT list, not a path: relative, no traversal, no shell
# metacharacter. Anchored with \Z, never $, so a trailing newline cannot smuggle
# a second line — the same reasoning as oauth2proxy._DNS_NAME.
_SUBDIR = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z")


def check_pnpm_subdir(global_subdir: str) -> str:
    """Shape-gate before interpolation. This value comes from VIDE_PNPM_GLOBAL_SUBDIR
    and lands inside a double-quoted assignment in /etc/profile.d, which EVERY
    login shell on the box sources, root's included — one `"` closes the
    assignment and the rest of the row is shell running as whoever logged in.
    The checkout gate is the primary control; this is the belt to its braces, so
    that a gate bypass is a bug rather than a root shell."""
    if not _SUBDIR.fullmatch(global_subdir) or ".." in global_subdir.split("/"):
        raise ConfigError(
            f"VIDE_PNPM_GLOBAL_SUBDIR must be a relative path of plain segments "
            f"([A-Za-z0-9._-], '/'-joined, no '..'): {global_subdir!r}")
    return global_subdir


def emit_pnpm_profile_snippet(global_subdir: str, binsub: str = "bin") -> str:
    """POSIX-sh (dash-safe) /etc/profile.d content giving each user a WRITABLE
    pnpm global home + PATH (the shared /opt/pnpm is root-owned, so
    `pnpm add -g` there is EACCES). binsub is the global-bin subdir RELATIVE to
    PNPM_HOME, learned at converge — pnpm drops `add -g` shims there, so that,
    not PNPM_HOME itself, belongs on PATH."""
    check_pnpm_subdir(global_subdir)
    return f"""# Managed by VIDE — per-user pnpm global home + PATH. POSIX sh (sourced by /bin/sh).
if [ -n "${{HOME:-}}" ]; then
  PNPM_HOME="$HOME/{global_subdir}"
  export PNPM_HOME
  case ":${{PATH:-}}:" in
    *":$PNPM_HOME/{binsub}:"*) ;;
    *) PATH="$PNPM_HOME/{binsub}:${{PATH:-}}"; export PATH ;;
  esac
fi
"""


# ---- converge driver (install iff missing/forced, ALWAYS re-heal) ------------


def ensure_node_pnpm(cfg: Config, ex: Executor, rep: Reporter,
                     force: bool | None = None) -> None:
    """`force` is the wizard's per-invocation override of cfg.toolchain_force
    (None = the config value). An explicit parameter, NOT a Config rebuild —
    a rebound cfg mid-sequence is how two halves of one install end up seeing
    different worlds."""
    force = cfg.toolchain_force if force is None else force
    _ensure_node(cfg, ex, rep, force)
    _ensure_pnpm(cfg, ex, rep, force)


def _reconcile_perms(ex: Executor, path: Path) -> None:
    """World-traversable; heals umask rot. `chmod -R a+rX` as a subprocess —
    do NOT reimplement X semantics with os.walk ('execute iff directory or
    already-executable' is easy to get wrong). Routed through run() so it
    always announces itself in a preview."""
    ex.run(["chmod", "-R", "a+rX", str(path)])


def _ensure_node(cfg: Config, ex: Executor, rep: Reporter, force: bool) -> None:
    bindir = nvm_resolve_bindir(cfg.nvm_dir, cfg.node_major)
    if bindir is None or force:
        if force and bindir is not None:
            # nvm install <major> is idempotent, so it won't repair a corrupted
            # version tree; on --force wipe for a clean reinstall.
            rep.info(f"force: removing existing Node versions under {cfg.nvm_dir} "
                     "for a clean reinstall")
            ex.run(["rm", "-rf", str(cfg.nvm_dir / "versions/node")])
        _install_node(cfg, ex)  # <-- the ONLY network step for Node
        bindir = nvm_resolve_bindir(cfg.nvm_dir, cfg.node_major)
    else:
        rep.info(f"node present under {cfg.nvm_dir}; re-pointing without network")
    # Branch on DATA (did we resolve a bin dir?), not on dry-run — on a
    # converged box the preview lists exactly the real mutations. On a fresh
    # box a preview cannot know the post-install path, so it says so once.
    if bindir is not None:
        for b in ("node", "npm", "npx"):
            ex.run(["ln", "-sfn", str(bindir / b), str(cfg.bin_dir / b)])
        _reconcile_perms(ex, cfg.nvm_dir)
        node_link = cfg.bin_dir / "node"
        ex.verify(lambda: node_link.is_file() and bool(node_link.stat().st_mode & 0o111),
                  f"{node_link} not usable after re-point")
    else:
        ex.verify(lambda: False, f"no usable Node >={cfg.node_major} under {cfg.nvm_dir}")
        # Deliberately does NOT enumerate the remaining steps: a second,
        # hand-maintained description of the mutations is exactly the drift
        # the executor removed. Unlistable only because the target path does
        # not exist yet.
        rep.info("(preview) remaining steps depend on the bin dir resolved after install")


def _install_node(cfg: Config, ex: Executor) -> None:
    ex.ensure_dir(cfg.nvm_dir, mode=0o755)
    # nvm/npm writes must be born world-readable even on hardened hosts.
    ex.run_setup_script(cfg.nvm_installer_url, "VIDE_NVM_INSTALLER_URL", ["bash"],
                        env={"NVM_DIR": str(cfg.nvm_dir), "PROFILE": "/dev/null"},
                        umask=0o022)
    # nvm.sh is NOT written for set -e/-u/pipefail — run it under a bash -c
    # with those RELAXED (bash -c gives none of them by default; do not "fix"
    # this by adding set -e). No die inside: success is asserted by the caller
    # re-resolving the on-disk layout at parent scope.
    # The body is a CONSTANT and both values travel through env=, per the
    # executor's own rule that coreutils argv stays argv. Interpolating
    # cfg.nvm_dir into the string made this the only shell command in the
    # package built by concatenation — and Path() sanitizes nothing, so a
    # VIDE_NVM_DIR carrying a quote closed the assignment and the rest ran as
    # root. `.env` can already point the installer URL at a script VIDE runs as
    # root by design, so the marginal gain was small; the inconsistency was not.
    ex.run(["bash", "-c",
            '. "$NVM_DIR/nvm.sh"; nvm install "$VIDE_NODE_MAJOR"'],
           env={"NVM_DIR": str(cfg.nvm_dir),
                "VIDE_NODE_MAJOR": str(cfg.node_major)},
           umask=0o022)


def _ensure_pnpm(cfg: Config, ex: Executor, rep: Reporter, force: bool) -> None:
    binp = pnpm_resolve_bin(cfg.pnpm_home)
    if binp is None or force:
        if force and binp is not None:
            # pnpm setup --force overwrites in place but won't clear a binary
            # left at a now-stale path by an older installer layout; wipe the
            # whole dir for a clean reinstall (removing the dir itself — not
            # /* — also sweeps any dot-prefixed layout). Per-user global
            # installs are unaffected (they live in each $HOME).
            rep.info(f"force: clearing existing pnpm under {cfg.pnpm_home} "
                     "for a clean reinstall")
            ex.run(["rm", "-rf", str(cfg.pnpm_home)])
        _install_pnpm(cfg, ex)  # <-- the ONLY network step for pnpm
        binp = pnpm_resolve_bin(cfg.pnpm_home)
    else:
        rep.info(f"pnpm present under {cfg.pnpm_home}; re-pointing without network")
    if binp is not None:
        # A wrapper, NOT a symlink (see emit_pnpm_launcher). Rewritten each
        # converge with the freshly-resolved path, so it adopts a relocated bin
        # and heals a stale target.
        ex.atomic_write(cfg.bin_dir / "pnpm", emit_pnpm_launcher(binp),
                        mode=0o755, owner=("root", "root"))
        _reconcile_perms(ex, cfg.pnpm_home)
        install_pnpm_profile(cfg, ex)
    else:
        ex.verify(lambda: False, f"no usable pnpm binary under {cfg.pnpm_home}")
        rep.info("(preview) remaining steps depend on the pnpm binary resolved after install")


def _install_pnpm(cfg: Config, ex: Executor) -> None:
    ex.ensure_dir(cfg.pnpm_home, mode=0o755)
    # Throwaway HOME: get.pnpm.io runs `pnpm setup`, which appends a `# pnpm`
    # block to the invoker's shell rc chosen from $HOME + $SHELL. A temp HOME
    # (deleted after) keeps /root/.bashrc clean; PNPM_HOME still governs where
    # the binary lands. XDG_* are REMOVED (env -u semantics, not set-empty) so
    # setup can't reach the real root config.
    ex.run_setup_script(cfg.pnpm_installer_url, "VIDE_PNPM_INSTALLER_URL", ["sh"],
                        env={"PNPM_HOME": str(cfg.pnpm_home), "SHELL": "/bin/bash"},
                        clear_env=("XDG_CONFIG_HOME", "XDG_DATA_HOME"),
                        throwaway_home=True, umask=0o022)


def pnpm_global_bin_subdir(cfg: Config) -> str:
    """The dir (RELATIVE to PNPM_HOME) where `pnpm add -g` drops shims, learned
    once from the live pnpm so the per-user profile tracks pnpm's own layout
    across versions. Probed under a throwaway HOME with XDG_* AND
    npm_config_globalbindir cleared, so a host-local override in root's config
    is never baked into every user's profile. Any failure, or a result outside
    PNPM_HOME, degrades to 'bin' (the v11 answer) — never to breakage."""
    binp = pnpm_resolve_bin(cfg.pnpm_home)
    if binp is None:
        return "bin"
    result = system.pnpm_global_bin_dir(binp, cfg.pnpm_home)
    prefix = str(cfg.pnpm_home) + "/"
    if result.startswith(prefix) and result != prefix:
        return result[len(prefix):]
    return "bin"


def install_pnpm_profile(cfg: Config, ex: Executor) -> None:
    ex.ensure_dir(Path(cfg.pnpm_profile).parent, mode=0o755, owner=("root", "root"))
    ex.atomic_write(cfg.pnpm_profile,
                    emit_pnpm_profile_snippet(cfg.pnpm_global_subdir,
                                              pnpm_global_bin_subdir(cfg)),
                    mode=0o644, owner=("root", "root"))


# ---- read-only health diagnosis (never dies) ---------------------------------


def bin_status(cfg: Config, name: str) -> tuple[str, bool]:
    """Status line for <bin_dir>/<name> + healthy flag. Inspects the fixed path
    directly (not PATH) for a deterministic view."""
    path = cfg.bin_dir / name
    if path.is_symlink() and not path.exists():
        try:
            tgt = str(path.readlink())
        except OSError:
            tgt = "?"
        return f"BROKEN dangling -> {tgt}", False
    if not (path.exists() and path.stat().st_mode & 0o111):
        return "MISSING", False
    # timeout so a wedged binary can't hang the diagnostic during an incident.
    out = system.query([str(path), "--version"], timeout=3.0)
    ver = out.stdout.split()[0] if out.returncode == 0 and out.stdout.split() else ""
    if not ver:
        return "BROKEN (no version output)", False
    if name == "node":
        maj = node_major(ver)
        if maj is not None and maj < cfg.node_major:
            return f"STALE {ver} (< {cfg.node_major})", False
    return f"OK {ver}", True


def toolchain_ok(cfg: Config) -> bool:
    return bin_status(cfg, "node")[1] and bin_status(cfg, "pnpm")[1]


def toolchain_report(cfg: Config, user: str = "") -> tuple[str, bool]:
    """Multi-line human diagnosis; healthy flag. With a user (needs root) also
    cross-checks the user-view to catch the "works for root, dead for regular
    users" traversal failure. The PERM literal is arbiter contract."""
    lines: list[str] = []
    healthy = True
    for b in ("node", "npm", "npx", "pnpm"):
        s, ok = bin_status(cfg, b)
        if not ok:
            healthy = False
        lines.append(f"  {b:<5} {s}")
    # The user-view cross-check needs root (runuser). Bash gated it on
    # EUID==0; dropping that gate makes a non-root `vide doctor` false-report
    # PERM and exit 69 — a lie about a healthy box. Non-root: no user-view
    # line at all, same as bash.
    if user and system.euid() == 0:
        if system.probe_as(user, ["test", "-x", str(cfg.bin_dir / "node")]) \
                and system.query_as(user, ["timeout", "3", str(cfg.bin_dir / "node"),
                                           "--version"], timeout=5.0).returncode == 0:
            lines.append(contract.MSG_USER_VIEW_OK.format(user=user))
        else:
            lines.append(contract.MSG_USER_VIEW_PERM.format(user=user))
            healthy = False
    if healthy:
        lines.append("  status: HEALTHY")
    else:
        lines.append("  status: UNHEALTHY (repair: sudo vide toolchain)")
    return "\n".join(lines), healthy


def toolchain_status_line(cfg: Config) -> str:
    """Compact one-liner for `vide ls`."""
    if toolchain_ok(cfg):
        nodev = system.query([str(cfg.bin_dir / "node"), "--version"], timeout=3.0)
        pnpmv = system.query([str(cfg.bin_dir / "pnpm"), "--version"], timeout=3.0)
        nv = nodev.stdout.strip() or "?"
        pv = pnpmv.stdout.strip() or "?"
        return f"HEALTHY (node {nv}, pnpm {pv})"
    return "UNHEALTHY — run: sudo vide doctor"
