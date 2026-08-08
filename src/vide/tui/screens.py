"""TuiPrompter — the wizard's implementation of the Prompter port, plus the
error panel. Screen flow only: every answer goes back into the ONE sequencer
(install_flow.run_install); nothing here mutates, decides policy, or touches
a domain module (I7).

The wizard is also a COMMAND BUILDER: every answer records its argv/env twin,
and the summary (and every error exit) shows the exact equivalent
`--no-gui` command — dry-run's take-away artifact, and the scripted path for
whoever automates what they just clicked through.
"""
from __future__ import annotations

import shlex

from ..errors import UsageError
from ..prompter import (EXPOSURE_BANNER, ROOT_BANNER, InstanceAction, InstanceFacts,
                        InstallSummary, SsoCredentials, SsoFacts, ToolchainFacts,
                        UserFacts, check_client_id, check_client_secret, check_password)
from .session import Session
from .widgets import menu, password_field, text_field


def _ascii(text: str) -> str:
    """Drawn copy is ASCII-only (C-locale rule); shared constants keep their
    original bytes for the plain path — fold only at render time."""
    return (text.replace("—", "-").replace("–", "-")
            .encode("ascii", "replace").decode())


class TuiPrompter:
    def __init__(self, session: Session, *, sso_client_id: str = "",
                 sso_allow: str = "", sso_reaffirm: bool = False) -> None:
        self.s = session
        self.sso_reaffirm = sso_reaffirm  # from --sso-reaffirm
        # remembered answers: a retry re-runs the sequencer, and every ask
        # re-offers the previous choice as the preselected default.
        self._prev: dict[str, str] = {}
        # argv-supplied SSO answers pre-fill their fields exactly like a
        # remembered answer (acknowledge_exposure clears the command-builder
        # transcript but never _prev, so the prefill survives a retry). The
        # wizard still shows the ask — argv is a default, never a skip.
        if sso_client_id:
            self._prev["sso_cid"] = sso_client_id
        if sso_allow:
            self._prev["sso_email"] = sso_allow
        self._env: dict[str, str] = {}       # equivalent-command env prefix
        self._flags: dict[str, str] = {}     # equivalent-command flags (LAST answer wins)
        self._verb_equiv = ""                # upgrade/rotate: the verb IS the twin
        self._reinstall_user = ""            # reinstall: destroy && install twin

    def can_reask(self) -> bool:
        return True  # a human is here: declining a confirm returns to the menu

    # ---- port methods, in journey order --------------------------------------

    def acknowledge_exposure(self) -> None:
        # First ask of every sequencer run — reset the command-builder
        # transcript so a RETRY rebuilds it from this run's answers instead
        # of accumulating duplicates or a stale destroy from a changed mind.
        self._env.clear()
        self._flags.clear()
        self._verb_equiv = ""
        self._reinstall_user = ""
        title = _ascii(EXPOSURE_BANNER).strip("\n") + (
            "\n\nThis will install a loopback code-server instance managed by systemd."
            + ("\nPREVIEW - nothing will be changed." if self.s.dry_run else ""))
        self.s.set_status("welcome")
        menu(self.s, title, [("I understand - continue",
                              "the IP whitelist in YOUR proxy is the real gate")])

    def choose_target_user(self, facts: UserFacts) -> str:
        # Same void-then-set rule as existing_instance_action: a declined
        # typed-ROOT challenge re-enters this ask, and a quit here must not
        # leak the unratified answer — VIDE_CONFIRM_ROOT is a full
        # non-interactive waiver that even --yes deliberately cannot grant.
        # The confirmed return path re-sets all three below.
        self._flags.pop("--user", None)
        self._env.pop("VIDE_ALLOW_ROOT", None)
        self._env.pop("VIDE_CONFIRM_ROOT", None)
        self.s.set_status("target user")
        insts = {i.user: i for i in facts.instances()}

        def inst_desc(i: InstanceFacts) -> str:
            # An SSO instance has no port by design; its healthy state is
            # "socket", not the "no port record" anomaly (which stays reserved
            # for a genuinely torn password record).
            if i.auth == "sso":
                bind = "socket"
            elif i.port is not None:
                bind = f"port {i.port}"
            else:
                bind = "no port record"
            return f"existing instance ({'up' if i.active else 'down'}, {bind})"

        labels: list[str] = []
        opts: list[tuple[str, str]] = []

        def add(label: str, desc: str) -> None:
            if label not in labels:
                labels.append(label)
                opts.append((label, desc))

        d = facts.default
        d_desc = ("you (invoked via sudo)" if d == facts.sudo_user else "detected target")
        if d in insts:
            d_desc += f"; {inst_desc(insts[d])}"
        elif d not in ("vide", "root") and not facts.user_exists(d):
            # the wizard prevents what the plain flow can only raise
            d_desc += " - does NOT exist (only 'vide' is auto-created)"
        add(d, d_desc)
        for u, inst in sorted(insts.items()):
            add(u, inst_desc(inst))
        add("vide", "dedicated user, created if missing - gets PASSWORD-SUDO "
                    "(threat-equivalent to root under IDE compromise)")
        add("(other)", "type an existing username - only 'vide' is auto-created")
        # always offered; the typed-ROOT challenge still gates it downstream
        add("root", "DANGEROUS: compromise = uncontained root on this box")

        prev = self._prev.get("user", d)
        default_idx = labels.index(prev) if prev in labels else 0
        while True:
            sel = menu(self.s, "Who is this instance for?", opts, default_idx)
            choice = labels[sel]
            if choice == "(other)":
                choice = text_field(self.s, "Target user",
                                    "existing username", self._prev.get("user", ""))
                if not choice:
                    continue
            if choice == "root":
                # the consequence text AT the decision point; the Confirmer's
                # typed-ROOT challenge still gates downstream (same constant,
                # second renderer)
                if menu(self.s, _ascii(ROOT_BANNER).strip("\n"),
                        [("Back - choose another user", ""),
                         ("Continue with a ROOT instance",
                          "the typed-ROOT challenge follows")]) == 0:
                    continue
            elif choice != "vide" and not facts.user_exists(choice):
                menu(self.s, f"user '{choice}' does not exist - only 'vide' is "
                             "auto-created; create it first, or pick another",
                     [("back", "")])
                continue
            self._prev["user"] = choice
            self._flags["--user"] = choice
            if choice == "root":
                self._env["VIDE_ALLOW_ROOT"] = "1"
                self._env["VIDE_CONFIRM_ROOT"] = "ROOT"
            else:
                self._env.pop("VIDE_ALLOW_ROOT", None)
                self._env.pop("VIDE_CONFIRM_ROOT", None)
            return choice

    def existing_instance_action(self, inst: InstanceFacts) -> InstanceAction:
        # Entering an ask VOIDS its previous answer: the twins reflect only
        # CONFIRMED answers, so a quit mid-ask (q at this menu right after a
        # DECLINED destroy — the live smoke §5 finding) exposes the plain
        # converge twin, never the destruction the user just refused.
        # _prev is UI memory (the preserved highlight) and survives.
        self._verb_equiv = ""
        self._reinstall_user = ""
        self.s.set_status(f"existing instance: {inst.user}")
        bind = inst.binding or (f"port {inst.port}" if inst.port is not None else "socket")
        state = f"{'up' if inst.active else 'down'}, {bind}, {inst.version}"
        # The Rotate row is a per-instance PASSWORD rotation and is meaningless
        # for a passwordless SSO instance — hide it; cookie-secret rotation is
        # box-wide (vide rotate-sso) and does not belong on a per-instance menu.
        rows = [("Converge / repair", "re-assert everything, keep version & binding"),
                ("Upgrade code-server", "latest version - RESTARTS the live session")]
        actions = [InstanceAction.CONVERGE, InstanceAction.UPGRADE]
        if inst.auth != "sso":
            rows.append(("Rotate password",
                         "invalidates ALL live sessions, prints a new password"))
            actions.append(InstanceAction.ROTATE)
        rows.append(("Reinstall", "destroy its artifacts (asks again), then fresh install"))
        actions.append(InstanceAction.REINSTALL)
        title = f"An instance for '{inst.user}' already exists ({state})."
        if inst.auth == "sso":
            title += "\ncookie-secret rotation is box-wide: sudo vide rotate-sso"
        # Keyed menu memory (not a raw index): the row COUNT now varies by mode,
        # so a remembered index from a password instance would preselect the
        # wrong row on an SSO one. Remember the ACTION, map back to an index.
        prev_action = self._prev.get("instance_action_key", "converge")
        default_idx = next((n for n, a in enumerate(actions) if a.value == prev_action), 0)
        sel = menu(self.s, title, rows, default_idx)
        action = actions[sel]
        self._prev["instance_action_key"] = action.value
        if action is InstanceAction.UPGRADE:
            self._verb_equiv = f"sudo vide upgrade {shlex.quote(inst.user)}"
        elif action is InstanceAction.ROTATE:
            self._verb_equiv = f"sudo vide rotate {shlex.quote(inst.user)}"
        elif action is InstanceAction.REINSTALL:
            # honest twin: a plain `--no-gui` install CONVERGES an existing
            # instance; reinstall's scripted form is destroy-then-install —
            # composed at build time so post-fork answers (fqdn, password
            # mode) still land in the install half.
            self._reinstall_user = inst.user
        self.s.set_status("working")
        return action

    def toolchain_reinstall(self, facts: ToolchainFacts, default: bool) -> bool:
        # void-then-set, uniform across every twin-writing ask
        self._env.pop("VIDE_TOOLCHAIN_FORCE", None)
        self.s.set_status("toolchain")
        pn = "pnpm ok" if facts.pnpm_ok else "pnpm MISSING (will be installed)"
        sel = menu(self.s,
                   f"Node {facts.node_version} found in {facts.node_bindir} ({pn}).",
                   [("Keep it", "no network, re-point symlinks only"),
                    ("Reinstall latest", "wipes and reinstalls Node+pnpm (minutes, network)")],
                   1 if self._prev.get("tc") == "1" else 0)
        self._prev["tc"] = str(sel)
        if sel == 1:
            self._env["VIDE_TOOLCHAIN_FORCE"] = "1"
        self.s.set_status("working")
        return sel == 1

    def password_choice(self, user: str) -> str | None:
        self.s.set_status("password")
        if self.s.dry_run:
            # honest preview copy: no secret is generated (the narrate guard
            # stands), and soliciting a masked secret a preview would discard
            # is worse than not asking.
            menu(self.s, f"code-server password for '{user}':",
                 [("Generate (preview)",
                   "a REAL run generates it and prints it once after the wizard closes")])
            self.s.set_status("working")
            return None
        while True:
            sel = menu(self.s, f"code-server password for '{user}':",
                       [("Generate a strong password (recommended)",
                         "printed ONCE after the wizard closes - copy it from scrollback"),
                        ("Type my own",
                         "hidden entry; it will NOT be reprinted - you know it")],
                       int(self._prev.get("pw_mode", "0")))
            self._prev["pw_mode"] = str(sel)
            self._flags.pop("--password-stdin", None)
            if sel == 0:
                self.s.set_status("working")
                return None
            first = password_field(self.s, f"Password for '{user}'", "password")
            try:
                warn = check_password(first)
            except UsageError as e:
                menu(self.s, f"refused: {e}", [("try again", "")])
                continue
            if warn is not None and not self.s.modal_confirm(f"{warn} - use anyway? [y/N]"):
                continue
            second = password_field(self.s, "Confirm password", "again")
            if first != second:
                menu(self.s, "passwords do not match", [("try again", "")])
                continue
            self._flags["--password-stdin"] = ""
            self.s.set_status("working")
            return first

    def choose_fqdn(self, default: str, *, required: bool = False) -> str:
        self.s.set_status("proxy")
        prompt = ("Public FQDN for this instance (fills the Caddy snippet "
                  "and the transport probe).")
        prompt += ("\nSSO needs a real public name - the login redirect and the "
                   "shared cookie are built from it." if required
                   else "\nEnter with the field empty to use a placeholder.")
        while True:
            got = text_field(self.s, prompt, "fqdn", self._prev.get("fqdn", default))
            if required and not got:
                menu(self.s, "SSO needs a real public name (e.g. u.example.com) - "
                             "the redirect and the shared cookie are built from it",
                     [("try again", "")])
                continue
            break
        self._prev["fqdn"] = got
        if got:
            self._flags["--fqdn"] = got
        else:
            self._flags.pop("--fqdn", None)
        self.s.set_status("working")
        return got

    # ---- SSO ask-points ------------------------------------------------------

    def auth_mode(self, facts: SsoFacts) -> str:
        # void-then-set: a mode change invalidates the whole SSO flag cluster.
        for k in ("--auth", "--sso-client-id", "--sso-secrets-stdin",
                  "--parent-domain", "--sso-allow", "--password-stdin"):
            self._flags.pop(k, None)
        self.s.set_status("auth mode")
        if facts.proxy_configured:
            sso_row = (f"Join existing SSO (.{facts.parent_domain})",
                       "no Google setup needed - this box already runs the shared proxy")
        else:
            sso_row = ("Passwordless - Google SSO",
                       "first SSO install sets up ONE shared login service for this whole box")
        default_idx = 1 if facts.default == "sso" else 0
        sel = menu(self.s, "How is this instance protected?",
                   [("Per-instance password (recommended)",
                     "a generated or typed password in front of code-server"),
                    sso_row],
                   int(self._prev.get("auth_mode", str(default_idx))))
        self._prev["auth_mode"] = str(sel)
        self.s.set_status("working")
        if sel == 1:
            self._flags["--auth"] = "sso"
            return "sso"
        self._flags["--auth"] = "password"
        return "password"

    def sso_parent_domain(self, default: str) -> str:
        self.s.set_status("sso domain")
        # Derived from the (already-validated) FQDN; shown for confirmation. To
        # change it, the operator re-runs with a different FQDN — the parent is
        # DERIVED, so there is one source of truth, not two.
        menu(self.s,
             f"Shared SSO domain: .{default}\n"
             f"(login service auth.{default}; every future SSO instance must "
             "live under it; the Google redirect URI is registered once).",
             [("Confirm", f"use .{default} for the shared cookie + redirect")])
        self._flags.pop("--parent-domain", None)   # persisted box-wide, not per-run
        self.s.set_status("working")
        return default

    def sso_credentials(self, default_client_id: str) -> SsoCredentials:
        self.s.set_status("sso credentials")
        if self.s.dry_run:
            menu(self.s, "Google OAuth credentials:",
                 [("Preview",
                   "a REAL run asks for the Google client id + secret; a preview "
                   "never solicits a secret")])
            self.s.set_status("working")
            self._flags["--sso-client-id"] = "<client-id>"
            self._flags["--sso-secrets-stdin"] = ""
            return SsoCredentials(client_id="<client-id>", client_secret="<preview>")
        while True:
            cid = text_field(self.s, "Google OAuth client id (public - printed in "
                             "every auth URL).", "client_id",
                             self._prev.get("sso_cid", default_client_id))
            warn = check_client_id(cid)
            if warn is not None and not self.s.modal_confirm(f"{warn} - use anyway? [y/N]"):
                continue
            self._prev["sso_cid"] = cid   # public: safe to prefill
            # RECORDED HERE, BEFORE THE SECRET IS ASKED FOR, and the placement is
            # the whole point. Both used to be set after the secret was accepted,
            # so a Ctrl-C on the secret field — the single most likely place to
            # abort, since it is where you go hunting for a value — produced a
            # resume command carrying NEITHER, and the operator re-entered a
            # client id VIDE had already validated and remembered one line above
            # for prefill. A note whose job is to save re-entry may not drop the
            # one value it already trusts enough to prefill.
            #
            # `--sso-secrets-stdin` moves with it rather than staying behind: on
            # its own the client id would yield a resume command that dies at
            # "missing required value: pass --sso-secrets-stdin". The flag is not
            # a claim that a secret was given, it is the statement that the
            # resume run must supply one on stdin — true from the moment this
            # path is entered.
            #
            # The client id is public -> a literal twin flag; the secret is
            # NEVER in any twin (the paste re-solicits it on stdin).
            self._flags["--sso-client-id"] = cid
            self._flags["--sso-secrets-stdin"] = ""
            secret = password_field(self.s, "Google OAuth client secret (hidden; "
                                    "never reprinted).", "client_secret")
            warn = check_client_secret(secret)
            if warn is not None and not self.s.modal_confirm(f"{warn} - use anyway? [y/N]"):
                continue
            self.s.set_status("working")
            return SsoCredentials(client_id=cid, client_secret=secret)

    def whitelist_email(self, user: str, default: str) -> str:
        self.s.set_status("whitelist")
        while True:
            email = text_field(self.s,
                               f"Google account allowed into THIS instance ('{user}').\n"
                               f"Add more later: sudo vide allow <email> {user}",
                               "email", self._prev.get("sso_email", default))
            e = email.strip().lower()
            if "@" not in e or "." not in e.partition("@")[2]:
                menu(self.s, "that does not look like an email address", [("try again", "")])
                continue
            self._prev["sso_email"] = e
            self._flags["--sso-allow"] = e
            self.s.set_status("working")
            return e

    def deliver_secret(self, line: str) -> None:
        # Never the pane, never the capture: the session prints it after
        # endwin, last before the prompt.
        self.s.defer_secret(line)

    def finish(self, summary: InstallSummary) -> None:
        self.s.set_status("done")
        # the success summary is the reproduce-this-run artifact: every gate
        # was passed, so the fully-scripted (waived) form is honest here
        cmd = self.equivalent_command(waive_confirms=True)
        heads = {InstanceAction.CONVERGE: "Install complete",
                 InstanceAction.UPGRADE: "Upgrade complete",
                 InstanceAction.ROTATE: "Password rotated",
                 InstanceAction.REINSTALL: "Reinstall complete"}
        head = ("Preview complete - no changes were made" if summary.dry_run
                else heads[summary.action])
        # kept compact deliberately: at the 80x24 floor the whole body —
        # including the equivalent command, the wizard's take-away — must fit
        # the interaction region without the [...more] clamp.
        if summary.mode == "sso":
            # No password, no port. Compact to fit the 80x24 floor (<=11 title
            # lines): the gate story, the 30-day session, and the FLEET-WIDE
            # sign_out are what an SSO operator needs to keep. The scrollback
            # note (defer_note) carries the same facts durably.
            facts = (f"{head}\n"
                     f"  user {summary.user} . {summary.binding} . {summary.version}\n"
                     f"  auth Google SSO . allowed {summary.whitelist} "
                     f"(+ sudo vide allow <email> {summary.user})\n"
                     f"  fqdn {summary.fqdn} . cookie .{summary.parent_domain} "
                     f". toolchain {summary.toolchain}\n"
                     "Gates: Google sign-in + email whitelist + your Caddy IP whitelist.\n"
                     "Session ~30 days; then one redirect + account-chooser click.\n"
                     f"Wrong account? {summary.signout_url} (signs out EVERY SSO "
                     "instance on this box)\n"
                     f"Equivalent non-interactive command:\n  {cmd}")
            enter_line = "\nEnter closes the wizard and prints the log + Caddy snippet."
        else:
            facts = (f"{head}\n"
                     f"  user {summary.user} . 127.0.0.1:{summary.port} . {summary.version}\n"
                     f"  fqdn {summary.fqdn or '(placeholder in snippet)'}\n"
                     f"  config {summary.config_path}\n"
                     f"  toolchain {summary.toolchain}\n"
                     "The IP whitelist in your Caddy is the real gate. Verify it.\n"
                     f"Equivalent non-interactive command:\n  {cmd}")
            enter_line = ("\nEnter closes the wizard and prints:\n"
                          "  the full log, any SHOWN-ONCE password, the Caddy snippet.")
        # The Enter line is a live-screen affordance — LAST, adjacent to the
        # Finish action it explains, and never in the deferred note: replayed
        # after exit it would describe a wizard that no longer exists.
        body = facts + enter_line
        menu(self.s, body, [("Finish", "close the wizard and print the artifacts")])
        self.s.defer_note(f"\n== VIDE install summary ==\n{facts}\n")

    # ---- the command builder ---------------------------------------------------

    def equivalent_command(self, *, waive_confirms: bool = False) -> str:
        """The paste-ready --no-gui twin of THIS run's answers. `_flags` is a
        dict so a retry's changed answer REPLACES, never accumulates.

        TRUST RULE: a paste-ready command must never carry more destructive
        authority than the user confirmed in-session. The DEFAULT form (what
        abort/error resume notes get) therefore emits NO confirmation
        waivers — the reinstall half without `--yes` and the env prefix
        without VIDE_CONFIRM_ROOT — so the pasted command re-asks its own
        gates. Only finish() may pass waive_confirms=True: by the time the
        summary renders, every gate was actually passed."""
        if self._verb_equiv:
            return self._verb_equiv
        env_items = sorted(self._env.items())
        if not waive_confirms:
            env_items = [(k, v) for k, v in env_items if k != "VIDE_CONFIRM_ROOT"]
        # shlex.quote: the twin is a PASTE-READY command — a value carrying a
        # space or a shell metacharacter must arrive as one argument, not be
        # re-parsed by the operator's shell. Benign values render unchanged.
        env = " ".join(f"{k}={shlex.quote(v)}" for k, v in env_items)
        flags = " ".join(f"{k} {shlex.quote(v)}" if v else k
                         for k, v in self._flags.items())
        # "then Ctrl-D" IS THE LOAD-BEARING HALF, and it was missing. Both flags
        # read stdin to EOF. Piped, EOF arrives on its own — which is why every
        # automated tier feeds them through a pipe and why none of them could
        # ever have found this. On a terminal the operator pastes the line the
        # note told them to paste, presses Enter, and sits in front of a program
        # that looks hung: nothing printed, nothing asked, no cursor moved.
        # Walked by a human on 2026-08-08, reported as "does nothing whatever I
        # type into stdin". A resume note that hangs the resume is worse than no
        # note, because it costs the operator their confidence in the rest of it.
        if "--password-stdin" in self._flags:
            note = "   # supply the password on stdin, then Ctrl-D"
        elif "--sso-secrets-stdin" in self._flags:
            note = "   # paste VIDE_SSO_CLIENT_SECRET=<value> on stdin, then Ctrl-D"
        else:
            note = ""
        cmd = f"sudo {env + ' ' if env else ''}./install.sh --no-gui {flags}{note}".rstrip()
        if self._reinstall_user:
            yes = " --yes" if waive_confirms else ""
            cmd = f"sudo vide destroy {shlex.quote(self._reinstall_user)}{yes} && {cmd}"
        return cmd


def error_panel(session: Session, headline: str, detail: str) -> str:
    """Failure/interrupt funnel: retry re-runs the WHOLE converge (idempotent
    ensure_* steps make completed work a no-op — that IS the repair path);
    there is no step-level resume to pretend to. Returns 'retry' | 'abort'."""
    session.set_status("failed")
    body = (f"{headline}\n\n{detail}\n\n"
            "Completed steps are safe to re-run: the install converges.\n"
            "If apt/dpkg was interrupted, a retry may first need: dpkg --configure -a")
    while True:
        sel = menu(session, body,
                   [("Retry", "re-run the install from the top (converge)"),
                    ("View full log", ""),
                    ("Abort", "close, replay the log, keep what completed")])
        if sel == 0:
            session.set_status("retrying")
            return "retry"
        if sel == 1:
            session.log_view()
            continue
        return "abort"
