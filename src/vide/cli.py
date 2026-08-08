"""The management CLI: verb table + dispatch. Reads the registry from the
system, never from the repo.

The command table is an explicit in-repo tuple — NOT discovery, NOT plugins
(anti-goal). The dispatcher grants uniformly: global flags parsed BEFORE the
verb (bash parity), the dry-run banner, root gate, destructive confirmation,
exit-code mapping. Handlers return an exit code; the ONLY module that writes
sys.stdout is this one (plus install_flow's snippet emission) — everything
else reports to stderr through Reporter.

Argument parsing is hand-rolled to mirror the bash loops exactly: argparse
exits 2 on errors (contract says 64), auto-generates help (contract freezes
usage text), and abbreviates flags (contract says unknown flag dies). Not
worth fighting a framework for two loops of ten lines.
"""
from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from . import (caddy, codeserver, contract, node, oauth2proxy, ports, preflight,
               registry, secrets, sso, sysd, system, users)
from . import __version__
from .config import Config, load_config
from .confirm import Confirmer, require_root
from .errors import CommandFailed, Ex, StateError, UsageError, VideError
from .executor import Executor
from .install_flow import (USAGE as INSTALL_USAGE, DESTROY_PROMPT, ROTATE_PROMPT,
                           destroy_instance, rotate_instance, run_install,
                           upgrade_instance)
from .prompter import PlainPrompter, check_password
from .reporter import Reporter

USAGE = """Usage: vide [--dry-run] [--yes] [--debug] <command> [args]

Commands:
  install [opts]         install/converge an instance (same as sudo ./install.sh)
  ls                     list all instances (user, active, port, version)
  status [user]          per-instance state + /healthz + recent logs (all if omitted)
  info <user>            re-emit the Caddy snippet + port for an instance
  down <user>            stop + disable an instance (data preserved)
  destroy <user>         remove an instance's code-server/config/port (NOT $HOME)
  upgrade <user>         reinstall latest code-server for a user, then restart it
  rotate <user>          regenerate password + cookie-suffix, restart (kill switch)
  doctor [--quiet]       read-only health diagnosis (toolchain + instances +
                         the shared SSO proxy when any SSO instance exists)
  toolchain [--force]    (re)install/repair the shared Node+pnpm toolchain
                         (no instance is restarted); --force reinstalls latest
  allow <email> <user>   permit an email on ONE SSO instance's whitelist (reloads caddy)
  revoke <email> <user>  remove an email from ONE SSO instance's whitelist (reloads caddy)
  rotate-sso             rotate the shared SSO cookie secret (signs out ALL users)
  upgrade-sso            upgrade + restart the shared oauth2-proxy binary
  help                   this help

Global flags: --dry-run, --yes, --debug, and --version (print the version and
exit — quote it in a bug report; a clone's history names no revision).
Destructive commands require an explicit <user> and never guess a target.
"""


# Parsed by main() BEFORE the verb (bash parity). Named here so the dispatcher
# can tell "you put a real flag in the wrong place" from "no such flag".
_GLOBAL_FLAGS = ("--dry-run", "--yes", "-y", "--debug")


@dataclass(frozen=True)
class Context:
    cfg: Config
    ex: Executor
    rep: Reporter
    conf: Confirmer


# ---- verb handlers -----------------------------------------------------------


def cmd_ls(ctx: Context, args: list[str]) -> int:
    print(f"{'USER':<16} {'ACTIVE':<7} {'PORT':<7} VERSION")
    for u in registry.list_instances(ctx.cfg):
        a = "up" if registry.instance_active(u) else "down"
        # Binding.display keeps password rows byte-identical (digits) and prints
        # a distinct 'unix' token for socket instances — never '?', which means
        # a torn record.
        p = registry.instance_binding(ctx.cfg, u).display
        v = registry.instance_version(u)
        print(f"{u:<16} {a:<7} {p:<7} {v}")
    # One shared-toolchain line so a fleet-wide Node/pnpm outage can't be missed.
    print(f"toolchain: {node.toolchain_status_line(ctx.cfg)}")
    return 0


def cmd_status(ctx: Context, args: list[str]) -> int:
    instances = [args[0]] if args else registry.list_instances(ctx.cfg)
    # Shared workspace toolchain first — code-server answers /healthz on its
    # OWN bundled Node, so this is a DIFFERENT health question from "IDE up".
    print("== workspace toolchain (shared, all instances) ==")
    report, _ = node.toolchain_report(ctx.cfg)
    print(report)
    print()
    if not instances:
        ctx.rep.info("no VIDE instances found")
        return 0
    for u in instances:
        print(f"== {u} ==")
        print(f"  state:  {system.unit_state(f'code-server@{u}.service')}")
        b = registry.instance_binding(ctx.cfg, u)
        if b.kind == "unix":
            print(contract.MSG_BIND_UNIX.format(socket=b.socket))
        else:
            print(f"  port:   {b.display}")
        health = registry.instance_health(ctx.cfg, u)
        if health is None:
            print(contract.MSG_IDE_UNOBSERVABLE)
        elif health:
            print("  IDE (code-server): healthz OK")
        else:
            print("  IDE (code-server): unreachable")
        print("  logs:")
        # 25, not 5: the ExecStartPost refusal is followed by code-server's own
        # SIGTERM output, and a status command that truncates away the one line
        # explaining the failure is worse than printing no logs at all.
        logs = system.query(["journalctl", "-u", f"code-server@{u}.service",
                             "-n", "25", "--no-pager"])
        for line in logs.stdout.splitlines():
            print(f"    {line}")
    return 0


def _sso_present(ctx: Context, instances: list[str]) -> bool:
    return (oauth2proxy.provisioned(ctx.cfg)
            or any(registry.instance_mode(ctx.cfg, u) == "sso" for u in instances))


# An instance is a FAULT when systemd is meant to be keeping it up and it is not.
# Two halves, and both are load-bearing:
#   * branch on the is-active WORD, never on unit_is_active's boolean. That
#     boolean is False for `activating` and `deactivating` too, so a cron run
#     during boot — or during the operator's own `systemctl restart` — would go
#     red on a healthy box. A monitoring hook that cries wolf once is a hook
#     nobody reads again.
#   * require `enabled`. `vide down` DISABLES the unit (sysd), so a deliberately
#     stopped instance stays silent. That is the discriminator between "the
#     operator turned it off" and "it died", and there is no other one.
_DOWN_STATES = ("failed", "inactive")


def _instance_down(user: str, state: str | None = None) -> bool:
    unit = f"code-server@{user}.service"
    word = state if state is not None else system.unit_state(unit)
    # "unknown" is systemd saying NOTHING — a query that failed, no systemctl on
    # PATH, a wedged manager. It is a fault, not a pass: list_instances enumerates
    # from /etc/vide/*.env, so a recorded instance whose unit cannot even be
    # described is a box that cannot answer the question doctor exists to ask, and
    # this tree's rule is that a diagnostic which cannot see must not report green.
    # The enable-state check below cannot carry it — it returns "unknown" too, and
    # would therefore fail OPEN on exactly this box.
    if word == "unknown":
        return True
    if word not in _DOWN_STATES:
        return False
    return system.unit_enable_state(unit) == "enabled"


def cmd_doctor(ctx: Context, args: list[str]) -> int:
    instances = registry.list_instances(ctx.cfg)
    sso_present = _sso_present(ctx, instances)
    if args[:1] == ["--quiet"]:
        # stable scriptable code, matches full doctor. The shared proxy folds in
        # ONLY when an SSO instance exists — a password-only box keeps today's
        # exact semantics.
        ok = node.toolchain_ok(ctx.cfg)
        # Instances are consulted on password and SSO boxes ALIKE. This verb is
        # the documented cron hook, and cron mails on OUTPUT, not on exit status —
        # so a --quiet that returned 0 with every instance dead was silent by
        # construction, which is also the shape the socket freeze's own worst case
        # takes (an ExecStartPost refusal lands the unit in `failed`). The verb
        # table and the README both already promise "toolchain + instances".
        ok = ok and not any(_instance_down(u) for u in instances)
        if sso_present:
            # --quiet must not depend on github.com latency: skip the staleness HEAD.
            pok, plines = oauth2proxy.proxy_health(ctx.cfg, check_staleness=False)
            # THE ALARM HAS TO REACH THE CHANNEL THAT GREPS FOR IT. The word
            # BYPASS is guarded across contract.py as the token an operator
            # skims for and a monitoring grep keys on — and this verb, "the
            # documented monitoring hook, run by root cron", used to discard
            # every line and return an exit code. Cron mails on OUTPUT: so a
            # fleet-wide authorization bypass produced NO TEXT AT ALL, and the
            # routine restart that fires a hundred times more often produced the
            # identical 69. That is alert fatigue designed in.
            #
            # Only on failure, so a clean run stays silent and cron stays quiet
            # — `--quiet` speaks exactly when `ok` is already False. The lines
            # go to stdout because that is what cron mails; the exit code is
            # unchanged for anything that scripts against it.
            if not pok:
                print("== sso proxy (shared) ==")
                print("\n".join(plines))
            ok = ok and pok and _sockets_ok(ctx, instances)
        return 0 if ok else int(Ex.UNAVAILABLE)
    rc = 0
    print("== workspace toolchain (shared) ==")
    firstuser = instances[0] if instances else ""
    report, healthy = node.toolchain_report(ctx.cfg, firstuser)
    print(report)
    if not healthy:
        rc = int(Ex.UNAVAILABLE)
    if sso_present:
        print("\n== sso proxy (shared) ==")
        pok, lines = oauth2proxy.proxy_health(ctx.cfg)
        for ln in lines:
            print(ln)
        if not pok:
            rc = int(Ex.UNAVAILABLE)
    print("\n== instances ==")
    for u in instances:
        state = system.unit_state(f"code-server@{u}.service")
        b = registry.instance_binding(ctx.cfg, u)
        print(f"  {u:<16} unit={state:<10} bind={b.display}")
        if _instance_down(u, state):
            msg = (contract.MSG_INSTANCE_UNKNOWN if state == "unknown"
                   else contract.MSG_INSTANCE_DOWN)
            print(msg.format(user=u, state=state))
            rc = int(Ex.UNAVAILABLE)
        if b.kind == "unix" and not _socket_line(ctx, u, b, printit=True):
            rc = int(Ex.UNAVAILABLE)
    print("\nRepair: shared toolchain -> sudo vide toolchain [--force]")
    # A DOWN instance is deliberately NOT sent here: once a unit has burned its
    # start limit, systemd refuses a plain start — and a converge ends in one, so
    # this footer was the repair systemd rejects. The per-instance line above
    # carries the reset-failed that actually works; this one stays for the case it
    # was written for, a misconfigured or half-installed instance.
    print("        a misconfigured one -> sudo ./install.sh (VIDE_USER=<user>)")
    print("        one systemd refuses to start -> see its line above first")
    return rc


def _socket_line(ctx: Context, user: str, binding, *, printit: bool) -> bool:
    """The per-socket doctor rows; returns True iff healthy. TWO rows, because
    there are two different facts: the socket's own perms decide which PROCESS
    may connect, and its DIRECTORY decides who may decide what is at the other
    end of the path. The second is the control the first was mistaken for."""
    ok = True
    active = registry.instance_active(user)
    import grp
    try:
        want_gid = grp.getgrnam("vide-proxy").gr_gid
    except KeyError:
        want_gid = -1
    # THE DIRECTORY FIRST, and deliberately NOT behind the root gate below.
    # /run/vide is root-owned 0755, so an lstat of /run/vide/<user> answers for
    # any caller — it is the socket INSIDE the frozen directory that stops being
    # readable, not the directory itself. Gating this would have hidden the one
    # row a non-root operator can still get a true answer from, and it is the row
    # that says an upgraded box has instances still running the old template: the
    # freeze is per-ACTIVATION state (RuntimeDirectory + RuntimeDirectoryPreserve
    # =no) and a converge rewrites the unit without restarting anything.
    # Gated on `active` only because the directory legitimately does not exist
    # while the unit is stopped.
    if active:
        parent = Path(str(binding.socket)).parent
        d = system.path_facts(parent)
        frozen = (d is not None and d.is_dir and not d.is_symlink
                  and d.uid == 0 and d.gid == want_gid and d.mode == 0o2750)
        # …unless the lstat failed for PERMISSION reasons. path_facts maps every
        # OSError to None, so without this an unreadable parent reads as MISSING
        # — which is the same "cannot see reported as a fault" conflation this
        # round fixed for the socket rows, reappearing one level up now that this
        # row is allowed to run without root. Unobservable is not a fault.
        if not frozen and d is None and system.path_is_denied(parent):
            if printit:
                print(contract.MSG_SOCKET_DIR_UNOBSERVABLE.format(user=user, dir=parent))
        elif not frozen:
            ok = False
            if printit and d is None:
                # UNFROZEN's sentence is about who OWNS the directory, which says
                # nothing about one that is not there.
                print(contract.MSG_SOCKET_DIR_MISSING.format(user=user, dir=parent))
            elif printit:
                print(contract.MSG_SOCKET_DIR_UNFROZEN.format(
                    user=user, dir=parent,
                    found=f"{oct(d.mode)[2:]} {d.uid}:{d.gid}"))
    if not system.is_root():
        # Everything BELOW is EACCES for a non-root caller — including the
        # instance user, who could stat their own socket before the freeze.
        # socket_stat maps EACCES to None, which the reaped branch would report
        # as MISSING on a perfectly healthy box. node.py:319 records the same
        # class: dropping a gate makes a non-root doctor FALSE-report. An
        # unobservable property is not a fault, so this does not touch `ok`.
        if printit:
            print(contract.MSG_SOCKET_UNOBSERVABLE.format(user=user))
        return ok
    st = system.socket_stat(binding.socket)
    if st is None:
        if active and printit:
            print(contract.MSG_SOCKET_REAPED.format(user=user))
        return ok and not active
    import pwd as _pwd
    try:
        want_uid = _pwd.getpwnam(user).pw_uid
    except KeyError:
        want_uid = -1
    perms_ok = (st.is_socket and st.mode == 0o660
                and st.gid == want_gid and st.uid == want_uid)
    if not perms_ok and printit:
        owner = f"{st.uid}:{st.gid}"
        msg = contract.MSG_SOCKET_PERM if st.is_socket else contract.MSG_SOCKET_SWAPPED
        print(msg.format(user=user, socket=binding.socket,
                         mode=oct(st.mode)[2:], owner=owner))
    elif printit:
        print(contract.MSG_SOCKET_OK.format(user=user, socket=binding.socket))
    return ok and perms_ok


def _sockets_ok(ctx: Context, instances: list[str]) -> bool:
    for u in instances:
        b = registry.instance_binding(ctx.cfg, u)
        if b.kind == "unix" and not _socket_line(ctx, u, b, printit=False):
            return False
    return True


def cmd_toolchain(ctx: Context, args: list[str]) -> int:
    cfg = ctx.cfg
    # toolchain_force is config-loaded; --force is its argv override — an
    # explicit parameter, not a Config rebuild (one cfg per invocation).
    force = True if args[:1] == ["--force"] else None
    ctx.rep.info("converging system-wide Node+pnpm toolchain (no instance is restarted)")
    node.ensure_node_pnpm(cfg, ctx.ex, ctx.rep, force=force)
    ctx.rep.info(f"toolchain: {node.toolchain_status_line(cfg)}")
    return 0


def cmd_info(ctx: Context, args: list[str]) -> int:
    user = args[0]
    mode = registry.instance_mode(ctx.cfg, user)
    if mode is None:
        raise StateError(f"no VIDE instance recorded for '{user}'")
    home = system.user_home(user)
    b = registry.instance_binding(ctx.cfg, user)
    if mode == "sso":
        parent = sso.parent_domain(ctx.cfg) or ""
        # The instance record persists VIDE_FQDN precisely so this re-emit is
        # real (contract SOCKET_RECORD) — the record is the truth, and it wins:
        # cfg.fqdn here can only come from env/.env (info parses no --fqdn), and
        # a stale .env row must not silently re-head EVERY instance's snippet.
        # A pre-slice record without VIDE_FQDN falls back to cfg.fqdn, then the
        # placeholder (resolve treats the same contradiction as a ConfigError —
        # install_flow._resolve_sso; info must not be the one place it wins).
        fqdn = sso.recorded_fqdn(ctx.cfg, user) or ctx.cfg.fqdn
        ctx.rep.info(f"instance '{user}' (SSO): socket {b.socket}; config "
                     f"{home or f'/home/{user}'}/.config/code-server/config.yaml")
        signout = contract.SIGNOUT_URL.format(domain=parent or "<DOMAIN>")
        ctx.rep.info(contract.MSG_SIGNOUT.format(url=signout))
        ctx.rep.info(f"the shared auth block imports {ctx.cfg.sso_dir}/caddy/auth.caddy, "
                     "which VIDE owns and rewrites — you paste the block once, ever")
        print()
        sys.stdout.write(caddy.emit_snippet(user, b, fqdn,
                                            sso_dir=str(ctx.cfg.sso_dir),
                                            parent_domain=parent))
        # Re-emit the SHARED block too. It used to be re-rendered here because a
        # converge would not refresh the operator's pasted copy, making this print
        # the ONLY way a changed block (the 2026-07-27 auth-root fix) could reach
        # an installed fleet. That is no longer why: the block is now a site header
        # and an import, the body behind it is VIDE's to rewrite, and this print
        # exists simply so an operator rebuilding a Caddyfile can get the three
        # lines back without hunting through docs.
        if parent:
            # AND THE WARNING THAT USED TO GUARD THIS PRINT IS GONE, deliberately.
            # It existed because the emitted text CONTAINED the hop: on a moved-pin
            # box, pasting it aimed the whole login flow at an address nothing
            # held, published under the operator's real TLS by the paste this verb
            # invited. The text now names no port at all — `caddy.hops()` on it
            # returns the empty set, which is asserted — so the paste cannot carry
            # a stale address anywhere. Whatever the pin is doing, the operator
            # ends up importing the body VIDE actually wrote, which is the same
            # artifact doctor reads. The two can no longer give opposite orders,
            # because there is only one of them left.
            print()
            sys.stdout.write(caddy.emit_auth_block(parent,
                                                   sso_dir=str(ctx.cfg.sso_dir)))
        return 0
    ctx.rep.info(f"instance '{user}': port {b.port}; config "
                 f"{home or f'/home/{user}'}/.config/code-server/config.yaml")
    ctx.rep.info(f"password is hashed on disk — if lost, run: vide rotate {user}")
    print()
    sys.stdout.write(caddy.emit_snippet(user, b, ctx.cfg.fqdn))
    return 0


def cmd_down(ctx: Context, args: list[str]) -> int:
    user = args[0]
    ctx.rep.info(f"stopping + disabling code-server@{user} (data preserved)")
    sysd.stop_instance(ctx.ex, user)
    sysd.disable_instance(ctx.ex, user)
    return 0


def cmd_destroy(ctx: Context, args: list[str]) -> int:
    # One implementation shared with the wizard's reinstall branch — see
    # install_flow.destroy_instance.
    destroy_instance(ctx.cfg, ctx.ex, ctx.rep, args[0])
    return 0


def cmd_upgrade(ctx: Context, args: list[str]) -> int:
    # Shared with the wizard's shortcut branch — see install_flow.
    upgrade_instance(ctx.cfg, ctx.ex, ctx.rep, args[0])
    return 0


def cmd_rotate(ctx: Context, args: list[str]) -> int:
    user = args[0]
    pw = rotate_instance(ctx.cfg, ctx.ex, ctx.rep, user)
    # The domain returns the plaintext; the presentation layer announces it
    # (the SHOWN-ONCE contract line must not originate where a wizard-mode
    # log pane could paint it — see secrets.rotate_config).
    if pw is not None:
        ctx.rep.info(contract.MSG_PASSWORD_ROTATED.format(user=user, pw=pw))
    return 0


def _sso_verb_args(args: list[str]) -> tuple[str, str, bool]:
    """allow/revoke take <email> <user> (+ optional --force-restart). The
    argument ORDER is enforced: emails carry '@', usernames don't, so a swap is
    caught with a clear message instead of a mysterious StateError."""
    force = "--force-restart" in args
    pos = [a for a in args if a != "--force-restart"]
    if len(pos) < 2:
        raise UsageError("usage: vide allow|revoke <email> <user> [--force-restart]")
    email, user = pos[0], pos[1]
    if "@" not in email:
        raise UsageError(f"expected: <email> <user> — '{email}' does not look like an email")
    if "@" in user:
        raise UsageError(f"expected: <email> <user> — '{user}' looks like an email, not a user")
    return email, user, force


def _require_sso_instance(ctx: Context, user: str) -> None:
    mode = registry.instance_mode(ctx.cfg, user)
    if mode is None:
        raise StateError(f"'{user}' has no VIDE instance")
    if mode != "sso":
        raise StateError(f"'{user}' is a password-mode instance — the SSO whitelist "
                         "does not apply (its auth is the code-server password)")


def cmd_allow(ctx: Context, args: list[str]) -> int:
    email, user, force = _sso_verb_args(args)
    _require_sso_instance(ctx, user)
    sso.allow(ctx.cfg, ctx.ex, ctx.rep, user, email, force_restart=force)
    return 0


def cmd_revoke(ctx: Context, args: list[str]) -> int:
    email, user, force = _sso_verb_args(args)
    _require_sso_instance(ctx, user)
    # Revoking the LAST email makes the instance deny-all: gate it like destroy.
    if sso.would_empty(ctx.cfg, user, email) and not ctx.conf.confirm_destructive(
            contract.REVOKE_LAST_PROMPT.format(user=user)):
        raise UsageError("aborted")
    sso.revoke(ctx.cfg, ctx.ex, ctx.rep, user, email, force_restart=force)
    return 0


def cmd_rotate_sso(ctx: Context, args: list[str]) -> int:
    oauth2proxy.rotate_sso(ctx.cfg, ctx.ex, ctx.rep)
    return 0


def cmd_upgrade_sso(ctx: Context, args: list[str]) -> int:
    oauth2proxy.upgrade_sso(ctx.cfg, ctx.ex, ctx.rep)
    return 0


# ---- the command table ---------------------------------------------------------


@dataclass(frozen=True)
class Command:
    name: str
    handler: Callable[[Context, list[str]], int]
    needs_root: bool
    min_args: int = 0
    usage: str = ""
    # Confirmation prompt template — only destroy + rotate carry one. `down`
    # stays friction-free: it is trivially reversible.
    destructive: str = ""
    # Every flag this verb accepts AFTER its name. The dispatcher refuses
    # anything else that starts with '-' — see the note in main().
    flags: tuple[str, ...] = ()


COMMANDS: tuple[Command, ...] = (
    Command("ls", cmd_ls, needs_root=False),
    Command("status", cmd_status, needs_root=False),
    Command("info", cmd_info, needs_root=False, min_args=1, usage="vide info <user>"),
    Command("down", cmd_down, needs_root=True, min_args=1, usage="vide down <user>"),
    Command("destroy", cmd_destroy, needs_root=True, min_args=1,
            usage="vide destroy <user>",
            destructive=DESTROY_PROMPT),
    Command("upgrade", cmd_upgrade, needs_root=True, min_args=1, usage="vide upgrade <user>"),
    Command("rotate", cmd_rotate, needs_root=True, min_args=1, usage="vide rotate <user>",
            # rotate is the kill switch: it invalidates every live session —
            # same argv-gated guard as destroy.
            destructive=ROTATE_PROMPT),
    Command("doctor", cmd_doctor, needs_root=False, flags=("--quiet",)),
    Command("toolchain", cmd_toolchain, needs_root=True, flags=("--force",)),
    # --- SSO (slice 2). allow/revoke take an EMAIL (not a user) — their arg
    # check lives in the handler; they carry no static destructive gate (the
    # last-email revoke is gated in-handler on state the table cannot see).
    Command("allow", cmd_allow, needs_root=True, min_args=2,
            usage="vide allow <email> <user> [--force-restart]",
            flags=("--force-restart",)),
    Command("revoke", cmd_revoke, needs_root=True, min_args=2,
            usage="vide revoke <email> <user> [--force-restart]",
            flags=("--force-restart",)),
    Command("rotate-sso", cmd_rotate_sso, needs_root=True,
            destructive=contract.ROTATE_SSO_PROMPT),
    Command("upgrade-sso", cmd_upgrade_sso, needs_root=True),
)


def main(argv: list[str], repo_dir: Path) -> int:
    # Global flags then subcommand — parity with the bash loop, including:
    # unknown flag dies EX_USAGE; `--` ends flag parsing; bare `vide` prints
    # usage and exits EX_USAGE. Control levers express PER-INVOCATION intent:
    # `yes` exists only in this scope, never in Config, so no ambient value
    # can pre-seed it.
    yes = False
    argv_env: dict[str, str] = {}
    rest = list(argv)
    while rest:
        a = rest[0]
        if a == "--dry-run":
            argv_env["VIDE_DRY_RUN"] = "1"
        elif a in ("--yes", "-y"):
            yes = True
        elif a == "--debug":
            argv_env["VIDE_DEBUG"] = "1"
        elif a in ("-h", "--help", "help"):
            print(USAGE, end="")
            return 0
        elif a == "--version":
            # Answered HERE, before load_config and before any root gate: the
            # reports worth the most come from a box where the config or the
            # privileges are precisely what broke, and a --version that needs a
            # working box answers only when it is least needed.
            print(f"vide {__version__}")
            return 0
        elif a == "--":
            rest.pop(0)
            break
        elif a.startswith("-"):
            raise UsageError(f"unknown global flag: {a} (see: vide help)")
        else:
            break
        rest.pop(0)

    # THE snapshot of the exported environment, taken before ANY .env injection.
    # load_config setdefaults every .env row into os.environ, so after the call
    # below an exported VIDE_* and a .env row are indistinguishable — and R1 in
    # _install_entry has to tell them apart (per-run intent vs fleet config).
    # It used to snapshot on its own, one line too late, because main() had
    # already injected: a VIDE_SSO_PARENT_DOMAIN row in .env then refused EVERY
    # install with EX_USAGE. Its guard test called _install_entry directly and
    # never saw main(), which is why it stayed green.
    exported_env = dict(os.environ)

    # BEFORE load_config, and for EVERY verb — not only the mutating ones.
    # Before, because an untrusted .env must never be parsed at all: load_config
    # setdefaults every row into os.environ, from where it is inherited by every
    # child process, including one that runs as the instance user. Every verb,
    # because `doctor --quiet` is the documented monitoring hook and is run by
    # root cron, and a hostile VIDE_BIN_DIR row makes node.bin_status exec an
    # arbitrary binary from that cron. --version and help answered above, so
    # they stay reachable on a box the gate would refuse — which is what makes a
    # refusal diagnosable.
    if os.geteuid() == 0:
        preflight.checkout_gate(
            repo_dir,
            # Argv and the process environment, never the .env row it is
            # judging — a gate that reads its own policy out of the artifact it
            # gates is not a gate. All three real channels must be seen: the
            # global flag, an exported VIDE_DRY_RUN, and `--dry-run` AFTER the
            # verb, which is the only form install.sh can produce (it execs
            # `__main__.py install "$@"`, so the flag always lands past it).
            dry_run=(argv_env.get("VIDE_DRY_RUN") == "1"
                     or os.environ.get("VIDE_DRY_RUN") == "1"
                     or "--dry-run" in argv),
            rep=Reporter(debug=argv_env.get("VIDE_DEBUG") == "1"),
            trusted_uids=preflight.trusted_uids_from_env(os.environ))

    cfg = load_config(repo_dir, argv_env)
    rep = Reporter(debug=cfg.debug)
    ex = Executor(dry_run=cfg.dry_run, reporter=rep, cfg=cfg)
    conf = Confirmer(yes_argv=yes, environ=os.environ, reporter=rep)
    ctx = Context(cfg=cfg, ex=ex, rep=rep, conf=conf)

    if not rest:
        print(USAGE, end="")
        return int(Ex.USAGE)

    verb, *args = rest

    # An inherited VIDE_DRY_RUN=1 must never be silent — but the install
    # sequencer emits its own banner (it can also be entered via ./install.sh),
    # so emitting here too would double it.
    if cfg.dry_run and verb != "install":
        rep.warn("DRY-RUN MODE ACTIVE — no changes will be made (VIDE_DRY_RUN=1)")

    if verb == "install":
        # The GLOBAL flags travel too: dropping argv_env here once made
        # `vide --dry-run install` print the banner and then run a REAL
        # install — the exact betrayal --dry-run exists to prevent.
        return _install_entry(args, repo_dir, yes, dict(argv_env), exported_env)

    for cmd in COMMANDS:
        if cmd.name == verb:
            break
    else:
        raise UsageError(f"unknown command: {verb} (see: vide help)")

    # Unknown post-verb flags are REFUSED, never ignored. Only `install` has its
    # own argv parser, so every other handler used to read `args` positionally
    # and drop the rest — which made `vide toolchain --dry-run` converge FOR
    # REAL, `vide upgrade u --dry-run` restart a live instance and
    # `vide upgrade-sso --dry-run` bounce the fleet's auth gate, none of them
    # prompting. That is the same betrayal the note above records for
    # `vide --dry-run install`, which was fixed for install alone. Refusing is
    # sufficient and is what the module docstring already promises ("unknown
    # flag dies EX_USAGE"); honouring the suffix form is deliberately NOT done,
    # because one accepted position is easier to keep true than two.
    for a in args:
        if a.startswith("-") and a not in cmd.flags:
            hint = (f" — a global flag must PRECEDE the verb: vide {a} {verb} …"
                    if a in _GLOBAL_FLAGS else
                    (f" (accepts: {', '.join(cmd.flags)})" if cmd.flags else ""))
            raise UsageError(f"unknown argument for '{verb}': {a}{hint}")

    if len(args) < cmd.min_args:
        raise UsageError(f"usage: {cmd.usage}")
    if cmd.needs_root:
        require_root(cfg.dry_run, rep, f"vide {verb}")
    if cmd.destructive:
        # Zero-arg destructive verbs (rotate-sso) carry no {user} — formatting
        # with args[0] would IndexError after the root gate. Only pass a user
        # when the verb actually takes one.
        prompt = cmd.destructive.format(user=args[0]) if args else cmd.destructive
        if not conf.confirm_destructive(prompt):
            raise UsageError("aborted")
    return cmd.handler(ctx, args)


def _install_entry(args: list[str], repo_dir: Path, yes_from_global: bool = False,
                   global_argv_env: dict[str, str] | None = None,
                   exported_env: Mapping[str, str] | None = None) -> int:
    """The second sequencer, with its own argv surface (--user/--fqdn), kept
    OUT of the verb table: forcing it in would either leak install-only flags
    into the global parser or demand an arg-spec DSL. Global flags already
    parsed by main() (--dry-run/--debug) arrive via global_argv_env.

    --no-gui and --password-stdin are LOCALS like `yes`, never Config fields:
    both express per-invocation intent (I6's config-vs-control separation),
    and non-tty contexts force plain mode anyway, so an env row would buy
    automation nothing."""
    yes = yes_from_global
    no_gui = False
    password_stdin = False
    sso_secrets_stdin = False
    sso_client_id = ""
    sso_allow = ""
    sso_reaffirm = False
    argv_env: dict[str, str] = dict(global_argv_env or {})
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--dry-run":
            argv_env["VIDE_DRY_RUN"] = "1"
        elif a in ("--yes", "-y"):
            yes = True
        elif a == "--debug":
            argv_env["VIDE_DEBUG"] = "1"
        elif a == "--no-gui":
            no_gui = True
        elif a == "--password-stdin":
            password_stdin = True
        elif a == "--sso-secrets-stdin":
            sso_secrets_stdin = True
        elif a == "--sso-reaffirm":
            # The only recovery path for a wrong Google client secret. Nothing
            # on this box can detect one — it fails at token exchange, on
            # Google's side — so doctor has no trigger and the lever has to be
            # explicit. A flag rather than a verb: credentials are solicited
            # only behind the Asker port, and cli.Context carries no prompter,
            # so a verb would need a second copy of the tty/wizard/--no-gui gate
            # that lives here, and would put an ask-point below the mutation
            # boundary resolve_plan/apply_plan exists to hold.
            sso_reaffirm = True
        elif a == "--auth":
            i += 1
            if i >= len(args):
                raise UsageError("--auth needs a value (password|sso)")
            argv_env["VIDE_AUTH"] = args[i]
        elif a.startswith("--auth="):
            argv_env["VIDE_AUTH"] = a.partition("=")[2]
        elif a == "--parent-domain":
            i += 1
            if i >= len(args):
                raise UsageError("--parent-domain needs a value")
            argv_env["VIDE_SSO_PARENT_DOMAIN"] = args[i]
        elif a.startswith("--parent-domain="):
            argv_env["VIDE_SSO_PARENT_DOMAIN"] = a.partition("=")[2]
        elif a == "--sso-client-id":
            i += 1
            if i >= len(args):
                raise UsageError("--sso-client-id needs a value")
            sso_client_id = args[i]
        elif a.startswith("--sso-client-id="):
            sso_client_id = a.partition("=")[2]
        elif a == "--sso-allow":
            i += 1
            if i >= len(args):
                raise UsageError("--sso-allow needs a value")
            sso_allow = args[i]
        elif a.startswith("--sso-allow="):
            sso_allow = a.partition("=")[2]
        elif a == "--user":
            i += 1
            if i >= len(args):
                raise UsageError("--user needs a value")
            argv_env["VIDE_USER"] = args[i]
        elif a.startswith("--user="):
            argv_env["VIDE_USER"] = a.partition("=")[2]
        elif a == "--fqdn":
            i += 1
            if i >= len(args):
                raise UsageError("--fqdn needs a value")
            argv_env["VIDE_FQDN"] = args[i]
        elif a.startswith("--fqdn="):
            argv_env["VIDE_FQDN"] = a.partition("=")[2]
        elif a in ("-h", "--help"):
            print(INSTALL_USAGE, end="")
            return 0
        else:
            raise UsageError(f"unknown argument: {a} (see --help)")
        i += 1

    # SSO mode is passwordless by definition: the two stdin channels are
    # mutually exclusive (two consumers of one stream is a contradiction).
    if password_stdin and sso_secrets_stdin:
        raise UsageError("--password-stdin and --sso-secrets-stdin are mutually "
                         "exclusive (SSO mode is passwordless)")

    # The EXPORTED parent domain, read from main()'s pre-injection snapshot.
    # Reading os.environ HERE would be too late: main() ran load_config before
    # dispatching, so every .env row is already in os.environ by now. The
    # fallback exists only for a direct call from a test — and a test that takes
    # it is testing a path no entry point uses, which is exactly how the
    # EX_USAGE bug survived its own regression test.
    env_sso_parent = (exported_env if exported_env is not None
                      else os.environ).get("VIDE_SSO_PARENT_DOMAIN", "")
    cfg = load_config(repo_dir, argv_env)

    # R1: the SSO flags only make sense under sso mode; a forgotten --auth would
    # silently make them dead in a password install. Check the RESOLVED mode
    # (argv > env > .env), so a fleet-default VIDE_AUTH=sso in .env satisfies it.
    # The parent-domain trigger is per-run channels ONLY (argv + exported env):
    # VIDE_SSO_PARENT_DOMAIN in .env is fleet CONFIG for future SSO installs,
    # not a request on THIS run — gating on cfg.sso_parent_domain falsely
    # refused a legitimate converge (e.g. `vide install --user u` of a recorded
    # SSO instance, whose mode resolve_plan reads from the record, not --auth).
    if cfg.auth.strip().lower() != "sso" and (sso_secrets_stdin or sso_client_id
                                              or sso_allow
                                              or argv_env.get("VIDE_SSO_PARENT_DOMAIN")
                                              or env_sso_parent):
        raise UsageError("the --sso-* flags require --auth sso")

    supplied_pw: str | None = None
    sso_secret: str | None = None
    if password_stdin:
        # Consumes stdin, so it structurally forces plain mode. The one
        # sanctioned plaintext channel besides the wizard's masked field —
        # never argv (/proc is world-readable), never env, never .env.
        no_gui = True
        supplied_pw = sys.stdin.readline().rstrip("\n")
        warn = check_password(supplied_pw)  # <8 chars dies EX_USAGE
        if warn is not None:
            Reporter(debug=cfg.debug).warn(warn)
    if sso_secrets_stdin:
        no_gui = True
        # Dry-run must NOT consume stdin (it mutates nothing and would print
        # nothing it read) — narrate the keys instead. Precedent:
        # secrets.ensure_config narrates before minting.
        if cfg.dry_run:
            Reporter(debug=cfg.debug).info(
                f"[dry-run] would read {contract.SSO_STDIN_CLIENT_SECRET} "
                f"(and optionally {contract.SSO_STDIN_CLIENT_ID}) from stdin")
        else:
            stdin_id, sso_secret = oauth2proxy.parse_sso_secrets(sys.stdin.read())
            # R8: each value from exactly one source. A stdin client id AND an
            # argv --sso-client-id that DIFFER is an ambiguity, not a merge.
            if stdin_id:
                if sso_client_id and sso_client_id != stdin_id:
                    raise UsageError("--sso-client-id was given on both argv and "
                                     "stdin with different values")
                sso_client_id = stdin_id
            # Shape warnings, parity with --password-stdin's warn (never echo the
            # value): a GOCSPX-less secret or a non-…apps.googleusercontent.com id
            # otherwise surfaces only as a deferred browser-login failure.
            from .prompter import check_client_id, check_client_secret
            for warn in (check_client_id(sso_client_id) if sso_client_id else None,
                         check_client_secret(sso_secret) if sso_secret else None):
                if warn is not None:
                    Reporter(debug=cfg.debug).warn(warn)

    # The gate. Function-level import (I7): the plain path must work on a box
    # whose Python lacks _curses — tui/__init__ itself is curses-free, and
    # the heavy modules load only after probe() passes. The euid pre-check
    # exists because forgetting sudo is the most common first-touch mistake:
    # it must get the plain one-line "re-run with sudo" remediation, never a
    # curses session whose only exit is an unwinnable retry loop (dry-run
    # stays wizard-able: require_root only warns there).
    stdin_tty, stdout_tty = os.isatty(0), os.isatty(1)
    from .tui import wizard_eligible
    if (wizard_eligible(stdin_tty, stdout_tty, no_gui)
            and (os.geteuid() == 0 or cfg.dry_run)):
        from . import tui
        try:
            tui.probe(os.environ.get("TERM", ""))
        except tui.TuiUnavailable as e:
            if not e.degrade:
                # A real but incapable terminal on an interactive session is
                # TOLD (with the paste-ready twin), not guessed around.
                rep = Reporter(debug=cfg.debug)
                rep.err(f"terminal cannot host the interactive installer: {e.reason}")
                rep.info("run the equivalent non-interactive install instead:")
                rep.info(f"  sudo ./install.sh --no-gui"
                         f"{_twin_flags(argv_env, sso_client_id=sso_client_id, sso_allow=sso_allow)}")
                return int(Ex.UNAVAILABLE)
            rep = Reporter(debug=cfg.debug)
            rep.info(f"interactive wizard unavailable ({e.reason}) — running plain install")
        else:
            return _run_wizard(cfg, yes, sso_client_id=sso_client_id,
                               sso_allow=sso_allow, sso_reaffirm=sso_reaffirm)

    rep = Reporter(debug=cfg.debug)
    if not no_gui and not (stdin_tty and stdout_tty):
        # Redirected/piped stdio is scripted intent: fall to plain silently
        # save for this one line (which must never collide with the arbiter's
        # grep shapes — it carries no 'SHOWN ONCE' and no '): ').
        rep.info("no interactive terminal detected — running the plain install "
                 "(pass --no-gui to make that explicit)")
    ex = Executor(dry_run=cfg.dry_run, reporter=rep, cfg=cfg)
    conf = Confirmer(yes_argv=yes, environ=os.environ, reporter=rep)
    pr = PlainPrompter(rep, password=supplied_pw, sso_secret=sso_secret,
                       sso_client_id=sso_client_id, sso_allow=sso_allow,
                       sso_reaffirm=sso_reaffirm)
    return run_install(cfg, ex, rep, conf, prompter=pr)


def _twin_flags(argv_env: dict[str, str], *, sso_client_id: str = "",
                sso_allow: str = "") -> str:
    """The already-supplied flags, re-rendered for the paste-ready command.
    The SSO client SECRET is never here (the paste re-solicits it on stdin);
    the client id is public and safe to render."""
    # shlex.quote: paste-ready — a value carrying a space or metacharacter
    # must survive the operator's shell as one argument. Benign values render
    # unchanged (same rule as the wizard's equivalent_command).
    out = ""
    if argv_env.get("VIDE_USER"):
        out += f" --user {shlex.quote(argv_env['VIDE_USER'])}"
    if argv_env.get("VIDE_AUTH"):
        out += f" --auth {shlex.quote(argv_env['VIDE_AUTH'])}"
    if argv_env.get("VIDE_FQDN"):
        out += f" --fqdn {shlex.quote(argv_env['VIDE_FQDN'])}"
    if argv_env.get("VIDE_SSO_PARENT_DOMAIN"):
        out += f" --parent-domain {shlex.quote(argv_env['VIDE_SSO_PARENT_DOMAIN'])}"
    if sso_client_id:
        out += f" --sso-client-id {shlex.quote(sso_client_id)}"
    if sso_allow:
        out += f" --sso-allow {shlex.quote(sso_allow)}"
    if argv_env.get("VIDE_AUTH") == "sso":
        # the secret is re-solicited on stdin; the paste carries the channel flag
        out += " --sso-secrets-stdin"
    if argv_env.get("VIDE_DRY_RUN"):
        out += " --dry-run"
    return out


def _run_wizard(cfg: Config, yes: bool, *, sso_client_id: str = "",
                sso_allow: str = "", sso_reaffirm: bool = False) -> int:
    """The wizard composition root: everything is constructed INSIDE the
    session so the Reporter's constructor-time isatty sees the captured fd
    (colorless buffer → byte-faithful replay) and the Confirmer's channel is
    the curses modal (its /dev/tty opener must never run while curses owns
    the terminal). The sequencer is the SAME run_install the plain path runs.

    Argv-supplied SSO answers (--sso-client-id / --sso-allow) travel in as
    field PREFILLS: dropping them re-asked the operator for data already given
    on the command line. The wizard still shows each ask — argv is a default
    here, never a skip.

    Error model: a KeyboardInterrupt here is ALWAYS a confirmed operator
    abort (the session's abort modal asked first, a second ^C means leave
    NOW) — it exits straight through the funnel, never into the error panel.
    The panel is for real failures only; its retry re-runs the whole
    converge (idempotent steps no-op — that is the repair path)."""
    from .errors import SoftwareError
    from .tui.screens import TuiPrompter, error_panel
    from .tui.session import CursesError, Session

    try:
        with Session(dry_run=cfg.dry_run) as session:
            rep = Reporter(debug=cfg.debug)
            ex = Executor(dry_run=cfg.dry_run, reporter=rep, cfg=cfg, tick=session.tick)
            session.on_abort = ex.kill_current_child
            conf = Confirmer(yes_argv=yes, environ=os.environ, reporter=rep,
                             tty_opener=session.channel_opener)
            pr = TuiPrompter(session, sso_client_id=sso_client_id,
                             sso_allow=sso_allow, sso_reaffirm=sso_reaffirm)
            while True:
                try:
                    return run_install(cfg, ex, rep, conf, prompter=pr)
                except KeyboardInterrupt:
                    session.defer_note("\ninstall aborted — completed steps are safe; "
                                       "resume with:\n  " + pr.equivalent_command())
                    raise
                except (VideError, CommandFailed) as e:
                    if error_panel(session, "install step failed", str(e)) == "retry":
                        continue
                    rep.err(str(e))  # into the capture → replayed with context
                    session.defer_note("\nfix the cause, then resume with:\n  "
                                       + pr.equivalent_command())
                    raise
    except CursesError as e:
        # A mid-session rendering failure (hung-up pty, broken terminfo edge)
        # is not a VideError; without this it reaches __main__ as a raw
        # traceback. The session funnel has already restored the terminal
        # and replayed the log by the time this re-raise happens.
        raise SoftwareError(f"terminal rendering failed mid-wizard: {e} — "
                            "re-run with --no-gui") from e
