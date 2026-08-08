"""The install/converge sequencer. The order is AUTHORED, one call per line,
readable on a single screen;
there is deliberately no step scheduler (a DAG solves dependency resolution
VIDE does not have).

The platform → prereqs → tools straddle is load-bearing (see preflight.py) and
pinned by a sequence test.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import (caddy, codeserver, contract, node, oauth2proxy, ports, preflight,
               registry, secrets, sso, sysd, system, transport, users)
from .config import Config
from .confirm import Confirmer, require_root
from .errors import CommandFailed, ConfigError, StateError, UsageError
from .executor import Executor
from .prompter import (Announcer, Asker, EXPOSURE_BANNER, InstanceAction,
                       InstanceFacts, InstallSummary, PlainPrompter, Prompter,
                       SsoCredentials, SsoFacts, ToolchainFacts, UserFacts,
                       require_answer)
from .reporter import Reporter

USAGE = """Usage: sudo ./install.sh [options]

Installs/converges one code-server instance for a target OS user, bound to
127.0.0.1 on an auto-allocated port, managed by systemd (code-server@<user>).

On an interactive terminal (stdin AND stdout are ttys) this opens a curses
wizard; redirected/piped stdio falls back to the plain flow automatically.
Both front-ends drive the SAME install sequence.

Target user resolution (highest precedence first):
  VIDE_USER / --user <name>     explicit target user
  sudo-invoking non-root user   the user who ran `sudo ./install.sh`
  bare root                     falls back to dedicated non-root 'vide'
                                (set VIDE_ALLOW_ROOT=1 to run a root instance)

Options:
  --user <name>       target OS user (same as VIDE_USER)
  --fqdn <name>       public FQDN for this instance (fills the Caddy snippet + probe)
  --auth <mode>       'password' (default) or 'sso' (passwordless Google SSO);
                      immutable per instance (switch = destroy + reinstall)
  --no-gui            never open the wizard; fully non-interactive plain flow
  --password-stdin    read the code-server password from stdin (one line, min 8
                      chars; implies --no-gui). Never pass secrets via argv/env.
  --parent-domain <d> (sso) the shared *.domain for the cookie + redirect
                      (derived from --fqdn if omitted)
  --sso-client-id <id>   (sso) the Google OAuth client id (public; safe on argv)
  --sso-secrets-stdin (sso) read VIDE_SSO_CLIENT_ID / VIDE_SSO_CLIENT_SECRET as
                      KEY=VALUE lines from stdin (implies --no-gui; mutually
                      exclusive with --password-stdin). Never secrets via argv/env.
  --sso-allow <email> (sso) the initial whitelisted email for this instance
  --sso-reaffirm      (sso) re-ask for the Google client id/secret and restart
                      the shared proxy — the recovery path for a wrong secret,
                      which fails at Google and so cannot be detected here. The
                      recorded cookie secret is preserved: nobody is signed out.
  --dry-run           preview every action, mutate nothing
  --yes, -y           confirm destructive prompts non-interactively (argv-only)
  --debug             verbose logging
  -h, --help          this help

Reverse proxy, TLS, DNS and the IP-whitelist are YOUR responsibility (your Caddy).
VIDE only binds loopback and prints a ready Caddy snippet. See docs/reverse-proxy.md.
"""


def ensure_prereqs(ex: Executor, rep: Reporter) -> None:
    """apt-install what is missing. Who needs each tool, so nobody "trims":
    argon2 — password hashing (offline, no Node needed); curl + git —
    the UPSTREAM installers (nvm, get.pnpm.io, code-server.dev) fetch with
    them at run time, urllib replacing curl for VIDE's own fetches changes
    nothing about theirs; ca-certificates — TLS for everyone including
    Python's ssl module (same /etc/ssl/certs bundle); libatomic1 — pnpm's
    standalone binary is dynamically linked against libatomic.so.1, Node is
    not, so a box without it installs Node happily and then dies at
    `pnpm --version`. It is Priority: optional, ships in NEITHER debian:13
    nor ubuntu:24.04, and exists on most real boxes only incidentally.
    Probed via ldconfig (not dpkg) so a box that got the .so another way is
    not forced to install a package."""
    need: list[str] = []
    if not system.have_cmd("argon2"):
        need.append("argon2")
    if not system.have_cmd("curl"):
        need.append("curl")
    if not system.have_cmd("git"):
        need.append("git")
    if not Path("/etc/ssl/certs/ca-certificates.crt").exists():
        need.append("ca-certificates")
    if not system.ldconfig_has("libatomic.so.1"):
        need.append("libatomic1")
    if not need:
        rep.debug("apt prerequisites present")
        return
    rep.info(f"installing apt prerequisites: {' '.join(need)}")
    _apt_install(ex, need)


def _apt_install(ex: Executor, pkgs: list[str]) -> None:
    """The one apt idiom: update first — hygienic images clean
    /var/lib/apt/lists, so a bare install can fail on a fresh box — then
    install, both debconf-noninteractive."""
    ex.run(["apt-get", "update", "-qq"], env={"DEBIAN_FRONTEND": "noninteractive"})
    ex.run(["apt-get", "install", "-y", *pkgs],
           env={"DEBIAN_FRONTEND": "noninteractive"})


def ensure_sudo(ex: Executor, rep: Reporter) -> None:
    """The dedicated-user feature IS password-sudo, and minimal/cloud images
    ship the sudo GROUP (gid 27, base-passwd) without the sudo PACKAGE — so
    `useradd -G sudo` succeeds while sudo/visudo do not exist and the journey
    dies a minute later at visudo validation (the first live smoke §1 walk).
    Membership recorded before the package lands becomes effective the moment
    it does; ordering here is for the visudo dependency, not group semantics."""
    if system.have_cmd("sudo") and system.visudo_cmd():
        rep.debug("sudo package present")
        return
    rep.info("installing 'sudo' (the dedicated user's password-sudo needs the "
             "package, not just the base-passwd group)")
    _apt_install(ex, ["sudo"])


def link_cli(cfg: Config, ex: Executor, rep: Reporter) -> None:
    # The symlink target is the repo-root `vide` shim — the SAME path as the
    # bash era, so pre-rewrite and post-rewrite symlinks are indistinguishable
    # and a rollback flip needs no cleanup.
    ex.run(["ln", "-sfn", str(cfg.repo_dir / "vide"), str(cfg.cli_link)])
    if not ex.dry_run:
        rep.info(f"CLI available as: vide (symlinked to {cfg.cli_link})")


# Confirmation copy shared between the verb table and the wizard's modal —
# same words in both UIs, one constant, two renderers.
DESTROY_PROMPT = ("Destroy VIDE instance '{user}'? Removes its code-server "
                  "install, config (incl. password hash) and port record. "
                  "Does NOT delete the user's $HOME/workspace.")
ROTATE_PROMPT = ("Rotate credentials for '{user}'? This invalidates ALL "
                 "live sessions and prints a NEW password once.")


def destroy_instance(cfg: Config, ex: Executor, rep: Reporter, user: str) -> None:
    """Remove one instance's unit state, port record and code-server artifacts
    (NOT $HOME). Shared by `vide destroy` and the wizard's reinstall branch —
    one implementation, so the two can't drift. Confirmation is the CALLER'S
    duty (verb table / wizard modal)."""
    # SSO branch: tombstone the imported Caddy body (NEVER delete — a dangling
    # import fails the operator's whole Caddy load) and drop the allow-list.
    # The shared proxy is a durable singleton and is deliberately untouched.
    if registry.instance_mode(cfg, user) == "sso":
        sso.tombstone_instance(cfg, ex, rep, user)
    for op in (lambda: sysd.stop_instance(ex, user),
               lambda: sysd.disable_instance(ex, user)):
        try:
            op()
        except CommandFailed:
            pass  # a never-started unit must not block its own destruction
    # BOTH per-instance state files. Leaving <user>.pwset behind made a rebuilt
    # dedicated user permanently unable to log in: useradd creates the account
    # locked, set_user_password sees the stale marker and returns None without
    # minting, install_sudoers grants password-sudo anyway, and apply_plan
    # prints no password — so nothing signals it either.
    ex.run(["rm", "-f", str(cfg.state_dir / f"{user}.env"),
            str(cfg.state_dir / f"{user}.pwset")])
    # User-scope removals run AS the user (their glob, their privileges) —
    # the same symlink-attack reasoning as write_as_user.
    try:
        ex.run_as(user, ["bash", "-c",
                         'rm -rf "$HOME/.local/lib/code-server-"* '
                         '"$HOME/.local/bin/code-server" "$HOME/.config/code-server"'])
    except CommandFailed:
        pass
    rep.info(f"destroyed VIDE artifacts for '{user}' ($HOME/workspace left intact)")


def upgrade_instance(cfg: Config, ex: Executor, rep: Reporter, user: str) -> None:
    """Upgrade + restart, shared by `vide upgrade` and the wizard's shortcut
    branch — one implementation, like destroy_instance."""
    codeserver.upgrade_code_server(cfg, ex, rep, user)
    sysd.restart_instance(ex, user)
    rep.info(f"upgraded and restarted code-server@{user}")


def rotate_instance(cfg: Config, ex: Executor, rep: Reporter, user: str) -> str | None:
    """Rotate + restart, shared by `vide rotate` and the wizard's shortcut
    branch. Returns the new plaintext; the CALLER announces it (presentation
    owns presentation — see secrets.rotate_config)."""
    if registry.instance_mode(cfg, user) == "sso":
        raise StateError(contract.MSG_ROTATE_ON_SSO.format(user=user))
    pw = secrets.rotate_config(cfg, ex, rep, user)
    sysd.restart_instance(ex, user)
    rep.info(f"rotated credentials and restarted code-server@{user} "
             "(old sessions invalidated)")
    return pw


def _binding_display(b) -> str:
    if b.kind == "unix":
        return f"socket {b.socket}"
    if b.kind == "tcp":
        return f"127.0.0.1:{b.port}"
    return "no binding recorded"


def _instance_facts(cfg: Config, user: str) -> InstanceFacts:
    b = registry.instance_binding(cfg, user)
    return InstanceFacts(user=user, port=b.port,
                         active=registry.instance_active(user),
                         version=registry.instance_version(user),
                         auth=registry.instance_mode(cfg, user) or "password",
                         binding=_binding_display(b))


def _all_instance_facts(cfg: Config) -> tuple[InstanceFacts, ...]:
    # version deliberately unresolved ("?"): it would spawn a ~1s
    # `code-server --version` PER instance just to decorate a menu row.
    out = []
    for u in registry.list_instances(cfg):
        b = registry.instance_binding(cfg, u)
        out.append(InstanceFacts(user=u, port=b.port,
                                 active=registry.instance_active(u),
                                 version="?",
                                 auth=registry.instance_mode(cfg, u) or "password",
                                 binding=_binding_display(b)))
    return tuple(out)


@dataclass(frozen=True)
class InstallPlan:
    """The frozen decision every ask-point produced, resolved BEFORE the first
    mutation. resolve_plan builds it (no Executor); apply_plan carries it out
    (no Asker). 'resolve decides, apply announces' — every rep.*/stdout write
    keeps its position in apply so the frozen arbiter's stream is byte-identical."""
    target: str
    action: InstanceAction
    mode: str                              # "password" | "sso"
    toolchain_force: bool | None = None
    is_root_fallback: bool = False         # apply announces the 'vide' fallback
    fqdn: str = ""
    # operator-supplied plaintext (None = generate). repr-suppressed: the plan
    # rides into tracebacks/logs and must never echo a login password — the same
    # hazard SsoCredentials.client_secret is hardened against.
    password: str | None = field(default=None, repr=False)
    # sso
    parent_domain: str = ""
    persist_parent: bool = False           # this run records fleet.env
    sso_bootstrap: bool = False            # the box's FIRST SSO install: print the block
    sso_credentials_needed: bool = False   # this run must solicit the Google secret
    sso_credentials: SsoCredentials | None = None
    whitelist_email: str = ""              # "" = allow-list already populated


def run_install(cfg: Config, ex: Executor, rep: Reporter, conf: Confirmer,
                prompter: Prompter | None = None) -> int:
    """ONE authored sequencer for both front-ends, now in two provable halves:
    resolve_plan performs EVERY ask-point with no Executor in scope (it cannot
    mutate, so a --no-gui run missing a required flag dies before the first
    apt-get), then apply_plan carries the plan out with no Asker (it cannot
    solicit). The plain flow and the wizard run the SAME two functions; there is
    deliberately no second driver to drift."""
    pr: Prompter = prompter if prompter is not None else PlainPrompter(rep)

    if cfg.dry_run:  # an inherited VIDE_DRY_RUN=1 must never be silent
        rep.warn("DRY-RUN MODE ACTIVE — no changes will be made (VIDE_DRY_RUN=1)")
    require_root(cfg.dry_run, rep, "./install.sh")
    rep.banner(EXPOSURE_BANNER)

    preflight.platform_gate(cfg, ex, rep)   # refuse a wrong box BEFORE any mutation
    plan = resolve_plan(cfg, rep, conf, pr)  # EVERY ask; no Executor in scope; refuses EX_USAGE here
    ensure_prereqs(ex, rep)                 # the first mutation, now provably after the last ask
    preflight.tools_gate(ex, rep)           # curl was just installed — confirm, not pre-refuse
    return apply_plan(cfg, ex, rep, pr, plan)


def resolve_plan(cfg: Config, rep: Reporter, conf: Confirmer, pr: Asker) -> InstallPlan:
    """The plan phase: performs every ask-point and raises every operator-fault
    refusal (UsageError/ConfigError/StateError) with NO Executor parameter — it
    is structurally incapable of mutating the host. Pinned by I8 (no Executor
    param, no ex. access) and I9 (its ask-points never reappear in apply_plan)."""
    pr.acknowledge_exposure()

    euid = os.geteuid()
    sudo_user = os.environ.get("SUDO_USER", "")
    import pwd as _pwd
    current = _pwd.getpwuid(euid).pw_name
    default = users.resolve_target_user(cfg.vide_user, sudo_user, euid,
                                        cfg.allow_root, current)
    facts = UserFacts(
        default=default, sudo_user=sudo_user, current_user=current,
        allow_root=cfg.allow_root,
        instances=lambda: _all_instance_facts(cfg),
        user_exists=system.user_exists)
    while True:
        target = pr.choose_target_user(facts)
        if target == "root":
            try:
                conf.confirm_root_instance()
            except UsageError:
                # a mistyped/declined ROOT challenge is a changed mind, not a
                # failure — an interactive prompter returns to the question
                if pr.can_reask():
                    continue
                raise
        break
    is_root_fallback = (target == default and target != "root" and
                        users.is_root_fallback(cfg.vide_user, sudo_user, euid,
                                               cfg.allow_root))

    # VIDE only auto-creates the 'vide' fallback; any other target must exist.
    if target != "vide" and not system.user_exists(target):
        if cfg.dry_run:
            rep.warn(f"target user '{target}' does not exist; a real run would "
                     "require it (only 'vide' is auto-created)")
        else:
            raise ConfigError(f"target user '{target}' does not exist — create it "
                              "first, or omit VIDE_USER to use the 'vide' fallback")

    # Existing instance → the wizard offers the management shortcuts; the
    # plain answer is CONVERGE, i.e. exactly today's re-assert semantics. An
    # SSO instance has NO port record, so detect by mode (not get_port), or a
    # socket instance would look fresh and re-run the whole install.
    action = InstanceAction.CONVERGE
    recorded_mode = registry.instance_mode(cfg, target)
    if recorded_mode is not None:
        while True:
            action = pr.existing_instance_action(_instance_facts(cfg, target))
            if action is InstanceAction.REINSTALL:
                # The wizard's modal renders the SAME prompt constant the verb
                # uses; --yes waives it with the same argv-only discipline.
                if not conf.confirm_destructive(DESTROY_PROMPT.format(user=target)):
                    if pr.can_reask():
                        continue  # declining is a changed mind, not a failure
                    raise UsageError("aborted")
            break

    # Shortcut journeys carry no further asks; apply runs the verb + summary.
    if action in (InstanceAction.UPGRADE, InstanceAction.ROTATE):
        return InstallPlan(target=target, action=action,
                           mode=recorded_mode or "password",
                           is_root_fallback=is_root_fallback)

    # REINSTALL destroys in apply; from here resolve reads the POST-destroy world
    # (a reinstall is a fresh install and must resolve its own mode/inputs, never
    # inherit the destroyed instance's).
    fresh = action is InstanceAction.REINSTALL
    if fresh:
        recorded_mode = None

    # Toolchain: a fork exists only when something satisfying is already
    # installed and no force was configured — otherwise there is nothing to
    # ask (a missing toolchain is installed, a forced one reinstalled).
    tc_force: bool | None = None
    tc_bindir = node.nvm_resolve_bindir(cfg.nvm_dir, cfg.node_major)
    if tc_bindir is not None and not cfg.toolchain_force:
        tc_force = pr.toolchain_reinstall(
            ToolchainFacts(node_version=tc_bindir.parent.name,
                           node_bindir=str(tc_bindir),
                           pnpm_ok=node.pnpm_resolve_bin(cfg.pnpm_home) is not None),
            cfg.toolchain_force)

    # Auth mode is resolved ONCE here, immutably: a recorded mode wins; a
    # conflicting request dies naming destroy+reinstall (mode is immutable this
    # slice). A bare --no-gui run resolves to password (facts.default =
    # cfg.auth or "password"), byte-identical to the frozen contract.
    requested = (cfg.auth or "").strip().lower() or None
    if requested not in (None, "password", "sso"):
        raise UsageError(f"--auth must be 'password' or 'sso', not {requested!r}")
    if recorded_mode and requested and recorded_mode != requested:
        raise StateError(contract.MSG_MODE_IMMUTABLE.format(
            user=target, recorded=recorded_mode, requested=requested))
    mode = recorded_mode or pr.auth_mode(SsoFacts(
        default=requested or "password",
        proxy_configured=oauth2proxy.provisioned(cfg),
        parent_domain=sso.parent_domain(cfg) or ""))

    if mode == "sso":
        return _resolve_sso(cfg, pr, target, action, fresh, tc_force,
                            is_root_fallback)

    # ---- password branch (byte-identical to the frozen contract) ------------
    # The password question applies only when a config will actually be minted,
    # i.e. when one is not already recorded (never-regenerate guard). A REINSTALL
    # is a fresh install, so it always mints — resolve reads the pre-destroy
    # config, so it cannot use it here. The decision lives here only — apply
    # calls ensure_config unconditionally and its OWN guard no-ops on a recorded
    # config, so the plan carries just the resolved password.
    mint_password = True if fresh else not secrets.has_password_config(cfg, target)
    password = pr.password_choice(target) if mint_password else None
    fqdn = pr.choose_fqdn(cfg.fqdn)
    return InstallPlan(target=target, action=action, mode="password",
                       toolchain_force=tc_force, is_root_fallback=is_root_fallback,
                       fqdn=fqdn, password=password)


def _resolve_sso(cfg: Config, pr: Asker, target: str, action: InstanceAction,
                 fresh: bool, tc_force: bool | None,
                 is_root_fallback: bool) -> InstallPlan:
    """The SSO ask cluster, resolved before any mutation. Every refusal here
    (fqdn/parent contradictions, fqdn-under-parent, missing required flags) is
    an operator fault and fires before the first apt-get."""
    persisted_fqdn = "" if fresh else sso.recorded_fqdn(cfg, target)
    # An explicit --fqdn that contradicts the persisted one on a converge is an
    # error, not a silent no-op (the fqdn is baked into the redirect/cookie).
    if persisted_fqdn and cfg.fqdn and cfg.fqdn != persisted_fqdn:
        raise ConfigError(
            f"--fqdn {cfg.fqdn} contradicts '{target}'s recorded FQDN "
            f"'{persisted_fqdn}' — the redirect/cookie are built from it; "
            f"reinstall to change: vide destroy {target} && vide install ...")
    fqdn = require_answer(pr.choose_fqdn(persisted_fqdn or cfg.fqdn, required=True),
                          "--fqdn")
    # D3: shape-check BEFORE any mutation. Presence alone is not enough — an
    # upper-case fqdn passes every presence check, then dies in render_proxy_toml's
    # lowercase-only _DNS_NAME AFTER fleet.env has permanently pinned the (poisoned)
    # parent domain, with no reset verb. Reject it here instead.
    oauth2proxy.check_dns_name(fqdn, "fqdn")
    # Same reasoning for the issuer, which is the FLEET's root of trust: a value
    # render_proxy_toml will refuse must fail HERE, not after fleet.env has
    # pinned it. The pin is what makes the refusal permanent — there is no reset
    # verb — so the one moment this can be an operator's correctable mistake is
    # before the first write.
    oauth2proxy.check_url(cfg.sso_issuer_url.rstrip("/"), "VIDE_SSO_ISSUER_URL")

    # Parent domain: an explicit --parent-domain override wins, else the
    # persisted fleet value, else derived from the fqdn. A contradicting
    # override fails closed.
    persisted_parent = sso.parent_domain(cfg)
    override = cfg.sso_parent_domain.strip()
    if override and persisted_parent and override != persisted_parent:
        raise ConfigError(
            f"--parent-domain {override} contradicts the box's shared SSO domain "
            f"'{persisted_parent}' (set once at first SSO install; it is immutable)")
    parent = persisted_parent or override or pr.sso_parent_domain(_derive_parent(fqdn))
    oauth2proxy.check_dns_name(parent)   # the derived/overridden parent, pre-mutation
    if not fqdn.endswith("." + parent):
        raise ConfigError(
            f"--fqdn {fqdn} is not under the shared SSO domain '{parent}' — the "
            "shared cookie/redirect only cover that domain")

    # TWO questions, deliberately kept apart after they were once one boolean.
    #
    # `needs_creds` — must this run solicit the Google credentials? It keys on
    # credentials_needed, not the fail-open three-file provisioned(), so a
    # torn/empty proxy.env can never be silently inherited. `--sso-reaffirm`
    # forces it True: a wrong client secret is only detectable at token exchange
    # on Google's side, so nothing on this box can discover it, and without an
    # explicit lever the only recovery was hand-editing proxy.env or deleting it
    # and signing out the whole fleet.
    #
    # `first` — is this the box's FIRST SSO install? It decides one thing only:
    # whether to print the auth block the operator pastes by hand once. It must
    # NOT gate provisioning; that is the latch this split exists to remove.
    needs_creds = pr.sso_reaffirm or oauth2proxy.credentials_needed(cfg)
    first = not oauth2proxy.provisioned(cfg)
    creds = pr.sso_credentials("") if (needs_creds and not cfg.dry_run) else None

    needs_whitelist = fresh or not sso.read_allowlist(cfg, target)
    whitelist = pr.whitelist_email(target, "") if needs_whitelist else ""

    return InstallPlan(target=target, action=action, mode="sso",
                       toolchain_force=tc_force, is_root_fallback=is_root_fallback,
                       fqdn=fqdn, parent_domain=parent,
                       persist_parent=persisted_parent is None,
                       sso_bootstrap=first, sso_credentials_needed=needs_creds,
                       sso_credentials=creds, whitelist_email=whitelist)


def apply_plan(cfg: Config, ex: Executor, rep: Reporter, ann: Announcer,
               plan: InstallPlan) -> int:
    """The apply phase: today's mutation sequence, verbatim, consuming the plan.
    Takes only an Announcer (I9: no ask-point can appear here). Every rep.*/
    stdout write keeps its position so the frozen arbiter's stream is unchanged."""
    target = plan.target
    if plan.is_root_fallback:
        rep.warn("invoked as bare root with no VIDE_USER and VIDE_ALLOW_ROOT unset "
                 "— using dedicated non-root user 'vide'")
    rep.info(f"target instance user: {target}")

    if plan.action in (InstanceAction.UPGRADE, InstanceAction.ROTATE):
        # Shortcut journeys: the same operations the verbs run, then straight
        # to the summary — no re-walk of the full rail.
        if plan.action is InstanceAction.UPGRADE:
            upgrade_instance(cfg, ex, rep, target)
            version = "upgraded to latest"
        else:
            pw = rotate_instance(cfg, ex, rep, target)
            if pw is not None:
                ann.deliver_secret(contract.MSG_PASSWORD_ROTATED.format(user=target, pw=pw))
            version = "existing (unchanged)"
        b = registry.instance_binding(cfg, target)
        ann.finish(_summary(cfg, ex, target, b, cfg.fqdn, version, plan.action,
                            mode=plan.mode))
        return 0

    if plan.action is InstanceAction.REINSTALL:
        destroy_instance(cfg, ex, rep, target)

    node.ensure_node_pnpm(cfg, ex, rep, force=plan.toolchain_force)

    if target == "vide":
        ensure_sudo(ex, rep)
        users.ensure_user(ex, rep, "vide")
        if plan.mode != "sso":
            login_pw = users.set_user_password(cfg, ex, rep, "vide")
            if login_pw is not None:
                ann.deliver_secret(contract.MSG_LOGIN_PASSWORD.format(user="vide", pw=login_pw))
            users.install_sudoers(ex, rep, "vide")
            rep.warn(f"the '{target}' user has password-sudo: under IDE compromise this "
                     "is THREAT-EQUIVALENT TO ROOT (a terminal/extension can capture the "
                     "sudo password). It is a speed bump, not containment.")

    if plan.mode == "sso":
        return _apply_sso(cfg, ex, rep, ann, plan)

    # ---- password branch (byte-identical to the frozen contract) ------------
    version = codeserver.ensure_code_server(cfg, ex, rep, target)
    port = ports.claim_port(cfg, ex, rep, target)
    new_pw = secrets.ensure_config(cfg, ex, rep, target, port, password=plan.password)
    if new_pw is not None:
        ann.deliver_secret(contract.MSG_PASSWORD.format(user=target, pw=new_pw))
    elif plan.password is not None:
        rep.info(f"config for '{target}' written with the operator-supplied "
                 "password (only the hash is stored)")
    sysd.install_unit(cfg, ex, rep)
    sysd.enable_start(ex, target)
    link_cli(cfg, ex, rep)

    rep.info(f"instance 'code-server@{target}' is up on 127.0.0.1:{port}")
    rep.info(f"paste the following into YOUR Caddy (re-emit anytime with: vide info {target}):")
    print(flush=True)
    # stdout is the machine channel: the snippet, and nothing else, lands there.
    sys.stdout.write(caddy.emit_snippet(target, registry.Binding.tcp(port), plan.fqdn))
    sys.stdout.flush()
    print(flush=True)
    # Announced because parts of the probe (DNS, https, the curl WS check)
    # block without ticking — the wizard's spinner freezes in 2-10s slices
    # and this line, visible in the pane, says why.
    rep.info("probing transport (loopback healthz + public reachability); "
             "this can take up to ~30s")
    transport.probe_transport(cfg, ex, rep, registry.Binding.tcp(port), plan.fqdn)
    ann.finish(_summary(cfg, ex, target, registry.Binding.tcp(port), plan.fqdn, version, plan.action))
    return 0


def _apply_sso(cfg: Config, ex: Executor, rep: Reporter, ann: Announcer,
               plan: InstallPlan) -> int:
    """Passwordless SSO apply: a unix-socket instance behind the shared
    oauth2-proxy, gated by a per-instance email whitelist. Every decision
    (fqdn, parent, bootstrap, credentials, whitelist) was resolved before the
    first mutation; this half only carries it out."""
    target = plan.target
    parent = plan.parent_domain
    fqdn = plan.fqdn

    # Sampled ONCE, before this run's first write, and consumed by BOTH readers
    # below. converge_proxy runs `enable --now`, so an observation taken after it
    # says only "we just started it" — which is how every first install came to
    # announce a pending restart for a proxy about to start fresh, and how the
    # re-affirm restart came to fire on a box that had no old process to correct.
    # It is also why converge_proxy takes it as a required keyword rather than
    # reading it itself: the one place that can answer honestly is here.
    was_active = system.unit_is_active(oauth2proxy.UNIT)

    # The credential half stays gated — it is the only part that needs a secret.
    creds_changed = False
    if plan.sso_credentials_needed:
        if ex.dry_run:
            # A preview never solicits a secret and never provisions; narrate.
            creds = SsoCredentials(client_id="<client-id>", client_secret="<preview>")
            rep.info("[dry-run] would record the Google client id/secret and "
                     "generate a cookie secret for the shared oauth2-proxy")
        else:
            creds = plan.sso_credentials
            # resolve always solicits credentials for a live (non-dry) bootstrap;
            # narrow the Optional so the deref below is checker-clean, not just
            # runtime-safe.
            assert creds is not None, "resolve provides credentials for a live bootstrap"
        creds_changed = oauth2proxy.record_credentials(
            cfg, ex, rep, client_id=creds.client_id, client_secret=creds.client_secret)

    # The credential-FREE half runs on every SSO apply, first install or not.
    # That is the whole fix for the fleet's root of trust having been written
    # once and never again: the unit's hardening and proxy.toml now reach boxes
    # that already exist, and a bootstrap that died half-way heals on a re-run
    # instead of latching, because nothing branches on "did it finish?".
    block = oauth2proxy.converge_proxy(cfg, ex, rep, parent_domain=parent,
                                       was_active=was_active)

    # …but the PRINT stays gated on the first install. The block is pasted by
    # hand exactly once, and tests/sso-mode reads everything from the first
    # `# --- VIDE` marker to EOF — printing it on every converge appends a
    # duplicate auth.<parent> site to the operator's Caddyfile.
    if plan.sso_bootstrap:
        # Points at `vide info`, not at auth.caddy: that file is the BODY, and
        # what the operator needs here is the three-line block that imports it.
        # `vide info` renders those fresh from code; auth.caddy would give them
        # the wrong artefact to paste.
        #
        # DELIBERATELY UNGUARDED, unlike `vide info`'s copy of this print. The
        # state worth warning about — a leftover reservation loaded on another
        # address while THIS box is being SSO-installed fresh — is already loud
        # in the same run, because install_proxy_socket_unit printed
        # MSG_PROXY_PIN_MOVE_REFUSED a few lines earlier. The file-only predicate
        # cannot see it (a first install's records are written at the new pin),
        # and the live one would go False on any ordinary first install whose
        # socket start was tolerated-failing or previewed — a warning against the
        # common path to catch a rare one, which is the trade this module refuses
        # everywhere else.
        rep.info("paste the shared SSO auth block into YOUR Caddy ONCE "
                 f"(re-emit anytime with: sudo vide info {plan.target}):")
        print(flush=True)
        sys.stdout.write(block)
        sys.stdout.flush()
        print(flush=True)

    # A corrected secret is inert until the process re-reads it: oauth2-proxy
    # loads proxy.env at startup, and `enable --now` never restarts a running
    # unit. This is the one restart a converge performs, and it is safe to do
    # here because it only happens when THIS run supplied credentials — an
    # explicit act, never a side effect of installing an unrelated user.
    # Gated on the proxy being LIVE, not on "this is not a first install". Those
    # differ: a box whose proxy.toml was lost reads as un-provisioned while the
    # process keeps running with the old secret, and `enable --now` never
    # restarts a running unit — so the corrected secret would land on disk
    # unread, which is precisely the failure this lever exists to undo.
    if creds_changed and not ex.dry_run and was_active:
        rep.info("re-affirmed credentials — restarting the shared proxy so it "
                 "reads them (sessions survive; the cookie secret is unchanged)")
        ex.run(["systemctl", "restart", oauth2proxy.UNIT])

    if not ex.dry_run:
        oauth2proxy.proxy_ready(cfg, ex, rep)

    # D3: record the immutable parent domain only after it is validated (resolve)
    # and the proxy is affirmed — its first reader (sso.allow -> _render_all) is
    # below, so a run that fails before here never pins a domain.
    if plan.persist_parent:
        sso.persist_parent_domain(cfg, ex, parent)

    version = codeserver.ensure_code_server(cfg, ex, rep, target)
    binding = sso.claim_binding(cfg, ex, rep, target, fqdn)
    secrets.ensure_sso_config(cfg, ex, rep, target)

    # D5: establish the authorization policy (allow-list + rendered Caddy body)
    # BEFORE the auth:none code-server is enabled and started — an instance must
    # never be startable while its whitelist is empty. (root takes this same path
    # — the explicit grant plus the typed-ROOT ceremony is the only extra gate.)
    if plan.whitelist_email:
        sso.allow(cfg, ex, rep, target, plan.whitelist_email)

    sysd.install_unit(cfg, ex, rep)
    sysd.enable_start(ex, target)
    link_cli(cfg, ex, rep)

    rep.info(f"instance 'code-server@{target}' is up on {binding.socket} (SSO)")
    rep.info(f"paste the following into YOUR Caddy (re-emit anytime with: vide info {target}):")
    print(flush=True)
    sys.stdout.write(caddy.emit_snippet(target, binding, fqdn,
                                        sso_dir=str(cfg.sso_dir), parent_domain=parent))
    sys.stdout.flush()
    print(flush=True)
    signout = contract.SIGNOUT_URL.format(domain=parent)
    rep.info(contract.MSG_SIGNOUT.format(url=signout))
    rep.info("probing transport (loopback socket healthz + public reachability)")
    transport.probe_transport(cfg, ex, rep, binding, fqdn)
    ann.finish(_summary(cfg, ex, target, binding, fqdn, version, plan.action,
                        mode="sso", parent_domain=parent,
                        whitelist=", ".join(sso.read_allowlist(cfg, target)),
                        signout_url=signout))
    return 0


def _derive_parent(fqdn: str) -> str:
    """The shared domain is the FQDN minus its leftmost label
    (u.example.com -> example.com). A bare TLD or a dotless name is refused."""
    parts = fqdn.split(".")
    if len(parts) < 3:
        raise ConfigError(
            f"cannot derive a shared SSO domain from '{fqdn}' — use a subdomain "
            "like u.example.com, or pass --parent-domain explicitly")
    return ".".join(parts[1:])


def _summary(cfg: Config, ex: Executor, user: str, binding, fqdn: str,
             version: str, action: InstanceAction, *, mode: str = "password",
             parent_domain: str = "", whitelist: str = "",
             signout_url: str = "") -> InstallSummary:
    home = system.user_home(user)
    return InstallSummary(
        user=user, port=binding.port, fqdn=fqdn, version=version,
        config_path=f"{home or f'/home/{user}'}/.config/code-server/config.yaml",
        toolchain=node.toolchain_status_line(cfg),
        action=action, dry_run=ex.dry_run, mode=mode,
        binding=_binding_display(binding), parent_domain=parent_domain,
        whitelist=whitelist, signout_url=signout_url)
