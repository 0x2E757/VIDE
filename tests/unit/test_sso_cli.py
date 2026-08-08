"""CLI-surface pins for the SSO verbs and flags: argument-order enforcement,
the zero-arg-destructive dispatcher fix, the stdin protocol's mutual exclusion
and dry-run-doesn't-read rule, and the mode-immutability StateError."""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from vide import cli  # noqa: E402
from vide.errors import UsageError  # noqa: E402


def _scrub_vide_env() -> None:
    """Call INSIDE a mock.patch.dict('os.environ', ...) block: drops ambient
    VIDE_* exports so these tests are shell- and order-independent (patch.dict
    restores them on exit)."""
    for k in [k for k in os.environ if k.startswith("VIDE_")]:
        os.environ.pop(k)


class TestVerbArgOrder(unittest.TestCase):
    def test_email_first_user_second_enforced(self) -> None:
        e, u, force = cli._sso_verb_args(["a@x.com", "alice"])
        self.assertEqual((e, u, force), ("a@x.com", "alice", False))

    def test_swapped_args_named_clearly(self) -> None:
        with self.assertRaises(UsageError) as cm:
            cli._sso_verb_args(["alice", "a@x.com"])
        self.assertIn("does not look like an email", str(cm.exception))

    def test_force_restart_flag_parsed(self) -> None:
        e, u, force = cli._sso_verb_args(["a@x.com", "alice", "--force-restart"])
        self.assertTrue(force)


def _gate_off():
    """Neutralise the checkout gate for tests that drive main() as root.

    The gate has its own suite (test_preflight.TestCheckoutGate). Here it would
    refuse every fixture correctly and for a reason that has nothing to do with
    what is under test: a temp repo lives under /tmp, and /tmp is 0o1777."""
    return mock.patch.object(cli.preflight, "checkout_gate")


class TestDispatcherZeroArgDestructive(unittest.TestCase):
    def test_rotate_sso_confirm_does_not_indexerror(self) -> None:
        # The bug: cmd.destructive.format(user=args[0]) crashes when a
        # destructive verb takes zero args. Drive main() through the real
        # dispatcher: rotate-sso (no args, no --yes, no tty) must reach its
        # confirm and abort cleanly (UsageError), NOT IndexError.
        with tempfile.TemporaryDirectory() as t:
            with _gate_off(), \
                 mock.patch.object(cli.os, "geteuid", return_value=0), \
                 mock.patch.object(cli, "require_root"), \
                 mock.patch.object(cli.Confirmer, "confirm_destructive", return_value=False):
                with self.assertRaises(UsageError) as cm:
                    cli.main(["rotate-sso"], Path(t))
        self.assertIn("aborted", str(cm.exception))

    def test_rotate_sso_reaches_handler_when_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            with _gate_off(), \
                 mock.patch.object(cli.os, "geteuid", return_value=0), \
                 mock.patch.object(cli, "require_root"), \
                 mock.patch.object(cli.Confirmer, "confirm_destructive", return_value=True), \
                 mock.patch.object(cli.oauth2proxy, "rotate_sso") as rot:
                rc = cli.main(["rotate-sso"], Path(t))
        self.assertEqual(rc, 0)
        rot.assert_called_once()


class TestParseSsoSecrets(unittest.TestCase):
    def test_secret_only_ok_id_optional(self) -> None:
        from vide import oauth2proxy as o
        self.assertEqual(o.parse_sso_secrets("VIDE_SSO_CLIENT_SECRET=GOCSPX-x\n"),
                         ("", "GOCSPX-x"))
        self.assertEqual(
            o.parse_sso_secrets("VIDE_SSO_CLIENT_ID=cid\nVIDE_SSO_CLIENT_SECRET=GOCSPX-x\n"),
            ("cid", "GOCSPX-x"))

    def test_refusals_never_echo_the_value(self) -> None:
        from vide import oauth2proxy as o
        for bad in ("VIDE_SSO_CLIENT_ID=cid\n",              # missing secret
                    "X=1\nVIDE_SSO_CLIENT_SECRET=GOCSPX-x\n",  # unknown key
                    "noequals\n",                             # malformed
                    "VIDE_SSO_CLIENT_SECRET=\n"):             # empty value
            with self.assertRaises(UsageError) as cm:
                o.parse_sso_secrets(bad)
            self.assertNotIn("GOCSPX-x", str(cm.exception))
            self.assertNotIn("cid", str(cm.exception))


class TestLastEmailRevokeGate(unittest.TestCase):
    def _ctx(self, tmp, allowlist):
        from fakes import make_config, quiet_reporter
        from vide.confirm import Confirmer
        from vide.executor import Executor
        cfg = make_config(Path(tmp))
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        (cfg.sso_dir / "allowlists").mkdir(parents=True, exist_ok=True)
        (cfg.sso_dir / "allowlists" / "alice").write_text("".join(e + "\n" for e in allowlist))
        rep = quiet_reporter()
        conf = Confirmer(yes_argv=False, environ={}, reporter=rep)
        ex = Executor(dry_run=True, reporter=rep, cfg=cfg)
        return cli.Context(cfg=cfg, ex=ex, rep=rep, conf=conf)

    def test_revoking_the_last_email_without_yes_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ctx = self._ctx(t, ["a@x.com"])   # a@x is the ONLY email → deny-all
            # Force the confirm to decline WITHOUT opening /dev/tty (the real
            # Confirmer would block/flip on an interactive runner). The last
            # email must never be removed.
            with mock.patch.object(cli.registry, "instance_mode", return_value="sso"), \
                 mock.patch.object(ctx.conf, "confirm_destructive", return_value=False), \
                 mock.patch.object(cli.sso, "revoke") as rv:
                with self.assertRaises(UsageError):
                    cli.cmd_revoke(ctx, ["a@x.com", "alice"])
            rv.assert_not_called()

    def test_revoking_a_non_last_email_is_not_gated(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ctx = self._ctx(t, ["a@x.com", "b@x.com"])
            with mock.patch.object(cli.registry, "instance_mode", return_value="sso"), \
                 mock.patch.object(cli.sso, "revoke") as rv:
                rc = cli.cmd_revoke(ctx, ["a@x.com", "alice"])
            self.assertEqual(rc, 0)
            rv.assert_called_once()


class TestDoctorSeesADeadInstance(unittest.TestCase):
    """`vide doctor --quiet` is the documented cron hook, and cron mails on
    OUTPUT rather than on exit status — so a --quiet that exits 0 with every
    instance dead is silent by construction. It is also exactly the shape the
    socket-directory freeze's own worst case takes: a refused ExecStartPost lands
    the unit in `failed`, so shipping that change without these rows would have
    made its failure mode invisible on the only monitoring surface the box has."""

    def _down(self, active: str, enabled: str) -> bool:
        with mock.patch.object(cli.system, "unit_state", return_value=active), \
             mock.patch.object(cli.system, "unit_enable_state", return_value=enabled):
            return cli._instance_down("alice")

    def test_a_failed_enabled_instance_is_a_fault(self) -> None:
        self.assertTrue(self._down("failed", "enabled"))

    def test_an_inactive_enabled_instance_is_a_fault(self) -> None:
        self.assertTrue(self._down("inactive", "enabled"))

    def test_a_healthy_instance_is_not_a_fault(self) -> None:
        self.assertFalse(self._down("active", "enabled"))

    def test_a_unit_still_moving_is_not_a_fault(self) -> None:
        # THE row that keeps a cron run during boot — or during the operator's own
        # `systemctl restart` — from going red on a healthy box. All three words
        # make unit_is_active False, which is precisely why the verdict branches on
        # the WORD and not on that boolean.
        for word in ("activating", "deactivating", "reloading"):
            self.assertFalse(self._down(word, "enabled"), word)

    def test_a_deliberately_downed_instance_stays_silent(self) -> None:
        # `vide down` DISABLES the unit. That is the only discriminator between
        # "the operator turned it off" and "it died"; without it the cron hook
        # pages on every intentionally-stopped instance and gets muted.
        self.assertFalse(self._down("inactive", "disabled"))
        self.assertFalse(self._down("failed", "disabled"))

    def test_a_box_whose_systemd_says_nothing_is_a_fault(self) -> None:
        # "unknown" is a query that failed, no systemctl on PATH, or a wedged
        # manager. The enable-state check cannot carry this — it answers "unknown"
        # too and would therefore fail OPEN on exactly the box that most needs the
        # alarm. A diagnostic that cannot see must not report green.
        self.assertTrue(self._down("unknown", "unknown"))
        self.assertTrue(self._down("unknown", "enabled"))

    def _doctor_out(self, active: str, enabled: str) -> str:
        import contextlib
        import types
        from fakes import make_config, quiet_reporter
        from vide.confirm import Confirmer
        from vide.executor import Executor
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            rep = quiet_reporter()
            ctx = cli.Context(cfg=cfg, ex=Executor(dry_run=True, reporter=rep, cfg=cfg),
                              rep=rep, conf=Confirmer(yes_argv=False, environ={},
                                                      reporter=rep))
            binding = types.SimpleNamespace(kind="tcp", display="9797", port=9797)
            buf = io.StringIO()
            with mock.patch.object(cli.registry, "list_instances", return_value=["alice"]), \
                 mock.patch.object(cli.node, "toolchain_report", return_value=("", True)), \
                 mock.patch.object(cli, "_sso_present", return_value=False), \
                 mock.patch.object(cli.registry, "instance_binding", return_value=binding), \
                 mock.patch.object(cli.system, "unit_state", return_value=active), \
                 mock.patch.object(cli.system, "unit_enable_state", return_value=enabled), \
                 contextlib.redirect_stdout(buf):
                cli.cmd_doctor(ctx, [])
            return buf.getvalue()

    def test_an_unknown_state_gets_its_own_line(self) -> None:
        # A wedged manager is not a dead instance. The DOWN line asserts "the unit
        # is enabled" — a fact this arm deliberately never read — and prescribes
        # reset-failed to the very manager that is not answering.
        out = self._doctor_out("unknown", "unknown")
        self.assertIn("UNKNOWN", out)
        self.assertIn("is-system-running", out)
        self.assertNotIn("reset-failed", out)
        # …and the ordinary dead instance still gets the remedy that works.
        dead = self._doctor_out("failed", "enabled")
        self.assertIn("reset-failed", dead)

    def _quiet(self, active: str, enabled: str) -> int:
        from fakes import make_config, quiet_reporter
        from vide.confirm import Confirmer
        from vide.executor import Executor
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            rep = quiet_reporter()
            ctx = cli.Context(cfg=cfg, ex=Executor(dry_run=True, reporter=rep, cfg=cfg),
                              rep=rep, conf=Confirmer(yes_argv=False, environ={},
                                                      reporter=rep))
            with mock.patch.object(cli.registry, "list_instances", return_value=["alice"]), \
                 mock.patch.object(cli.node, "toolchain_ok", return_value=True), \
                 mock.patch.object(cli, "_sso_present", return_value=False), \
                 mock.patch.object(cli.system, "unit_state", return_value=active), \
                 mock.patch.object(cli.system, "unit_enable_state", return_value=enabled):
                return cli.cmd_doctor(ctx, ["--quiet"])

    def test_quiet_folds_instances_in_on_a_password_box_too(self) -> None:
        # A password-only box is the case that was NOT covered: --quiet consulted
        # instances only through the SSO branch. Both arms, because a check that
        # never fires and one that always fires are the same defect with opposite
        # signs.
        self.assertNotEqual(0, self._quiet("failed", "enabled"))
        self.assertEqual(0, self._quiet("active", "enabled"))


class TestDoctorObservesTheSocketDirectory(unittest.TestCase):
    """The freeze is per-ACTIVATION state and a converge never restarts an
    instance, so after an upgrade every already-running SSO instance is still
    unfrozen. Observed rather than recorded, for the reason proc_no_new_privs
    argues: a "restart pending" marker goes stale the moment an operator restarts
    by hand, which is how a diagnostic teaches people to stop reading it."""

    class _B:
        kind = "unix"
        socket = Path("/run/vide/alice/code-server.sock")

    _MISSING = object()

    def _line(self, dirfacts, *, euid=0, stat=_MISSING, printit=False,
              denied=False) -> bool:
        from vide.system import SocketStat
        # `stat` is a parameter, not an outer patch: an outer
        # mock.patch(system.socket_stat) would be SHADOWED by the one below and
        # both branches would see the same healthy stat — which is exactly how
        # this row first shipped without teeth.
        st = (SocketStat(is_socket=True, uid=4242, gid=60000, mode=0o660)
              if stat is self._MISSING else stat)
        with mock.patch.object(cli.system, "is_root", return_value=euid == 0), \
             mock.patch.object(cli.system, "socket_stat", return_value=st), \
             mock.patch.object(cli.registry, "instance_active", return_value=True), \
             mock.patch.object(cli.system, "path_facts", return_value=dirfacts), \
             mock.patch.object(cli.system, "path_is_denied", return_value=denied), \
             mock.patch("grp.getgrnam") as g, mock.patch("pwd.getpwnam") as p:
            g.return_value = type("G", (), {"gr_gid": 60000})
            p.return_value = type("P", (), {"pw_uid": 4242})
            return cli._socket_line(None, "alice", self._B(), printit=printit)

    @staticmethod
    def _facts(uid: int, mode: int, *, gid: int = 60000,
               is_dir: bool = True, is_symlink: bool = False):
        from vide.system import PathFacts
        return PathFacts(is_symlink=is_symlink, is_dir=is_dir, is_file=False,
                         uid=uid, gid=gid, mode=mode)

    def test_a_frozen_directory_is_healthy(self) -> None:
        self.assertTrue(self._line(self._facts(0, 0o2750)))

    def test_a_symlinked_directory_is_a_fault(self) -> None:
        # lstat, so this is the entry itself. A root-owned symlink named
        # /run/vide/<user> pointing somewhere else satisfies every other conjunct
        # and is exactly the shape the freeze exists to make impossible.
        self.assertFalse(self._line(self._facts(0, 0o2750, is_symlink=True)))

    def test_a_directory_that_is_not_a_directory_is_a_fault(self) -> None:
        self.assertFalse(self._line(self._facts(0, 0o2750, is_dir=False)))

    def test_a_directory_that_cannot_be_read_is_not_called_unfrozen(self) -> None:
        # path_facts maps EVERY OSError to None, so "the directory is gone" and
        # "I may not look at it" arrive identically. Both arms: denied is not a
        # fault, genuinely absent is — otherwise the row cannot tell them apart
        # any better than the code it is pinning.
        self.assertTrue(self._line(None, denied=True))
        self.assertFalse(self._line(None, denied=False))

    def test_a_directory_group_owned_by_anything_else_is_a_fault(self) -> None:
        # The group is what lets Caddy traverse at all; a different one is either
        # a wedged instance or someone else's grant.
        self.assertFalse(self._line(self._facts(0, 0o2750, gid=60001)))

    def test_a_user_owned_directory_is_a_fault(self) -> None:
        # The pre-freeze posture, which is what an upgraded-but-not-restarted box
        # still has. Everything else about the instance looks perfect.
        self.assertFalse(self._line(self._facts(4242, 0o2750)))

    def test_a_widened_directory_is_a_fault(self) -> None:
        self.assertFalse(self._line(self._facts(0, 0o777)))

    def test_a_non_root_caller_is_told_it_cannot_see_rather_than_lied_to(self) -> None:
        # The frozen directory is 2750 root:vide-proxy, so a non-root doctor gets
        # EACCES and socket_stat maps that to None — which the reaped branch would
        # report as MISSING on a perfectly healthy box, sending the operator to
        # restart a working instance. An unobservable property is not a fault.
        self.assertTrue(self._line(self._facts(0, 0o2750), euid=1000, stat=None))
        # …and the same EACCES seen by root really would be reported as a fault,
        # so the row above cannot pass just because nothing is ever a fault.
        self.assertFalse(self._line(self._facts(0, 0o2750), euid=0, stat=None))

    def test_status_says_unobservable_rather_than_unreachable(self) -> None:
        # `vide status` is documented as runnable without sudo. After the freeze
        # the socket is unreadable to everyone but root and vide-proxy, and
        # socket_stat maps EACCES to None — collapsing that into False made every
        # healthy SSO instance report `unreachable` to a non-root operator. Both
        # arms, because a third state that is always returned is no better.
        from fakes import make_config
        from vide import registry
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            with mock.patch.object(registry, "instance_binding", return_value=self._B()), \
                 mock.patch.object(registry.system, "socket_stat", return_value=None):
                with mock.patch.object(registry.system, "is_root", return_value=False):
                    self.assertIsNone(registry.instance_health(cfg, "alice"))
                with mock.patch.object(registry.system, "is_root", return_value=True):
                    self.assertIs(False, registry.instance_health(cfg, "alice"))

    def _status(self, health) -> str:
        """`vide status` for one instance, with everything host-shaped stubbed.
        Nothing in this tier called cmd_status at all before, which is how its
        three-way health branch — the operator-visible half of the whole
        unobservable-vs-unhealthy fix — shipped with no falsifier."""
        import contextlib
        import types
        from fakes import make_config, quiet_reporter
        from vide.confirm import Confirmer
        from vide.executor import Executor
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            rep = quiet_reporter()
            ctx = cli.Context(cfg=cfg, ex=Executor(dry_run=True, reporter=rep, cfg=cfg),
                              rep=rep, conf=Confirmer(yes_argv=False, environ={},
                                                      reporter=rep))
            buf = io.StringIO()
            with mock.patch.object(cli.node, "toolchain_report", return_value=("", True)), \
                 mock.patch.object(cli.registry, "instance_binding", return_value=self._B()), \
                 mock.patch.object(cli.registry, "instance_health", return_value=health), \
                 mock.patch.object(cli.system, "unit_state", return_value="active"), \
                 mock.patch.object(cli.system, "query",
                                   return_value=types.SimpleNamespace(stdout="",
                                                                      returncode=0)), \
                 contextlib.redirect_stdout(buf):
                cli.cmd_status(ctx, ["alice"])
            return buf.getvalue()

    def test_status_distinguishes_all_three_health_answers(self) -> None:
        # All three arms, in one row, because two of them passing is exactly how
        # the third went missing: a branch nothing asserts is a branch that can be
        # deleted at full green.
        self.assertIn("not observable without root", self._status(None))
        self.assertIn("healthz OK", self._status(True))
        self.assertIn("unreachable", self._status(False))
        # …and the two failure words must not be the same word.
        self.assertNotIn("unreachable", self._status(None))

    def test_the_new_lines_format_with_exactly_the_keys_their_callers_pass(self) -> None:
        """Not one of these templates was formatted by any tier when it shipped —
        every row here uses printit=False — so a renamed placeholder would reach
        the operator as a KeyError traceback out of the diagnostic they ran
        because something was already wrong. Two halves: the placeholder sets are
        pinned against what the call sites pass, and the printing paths run."""
        import string
        from vide import contract
        for msg, keys in (
                (contract.MSG_INSTANCE_DOWN, {"user", "state"}),
                (contract.MSG_INSTANCE_UNKNOWN, {"user"}),
                (contract.MSG_SOCKET_DIR_UNFROZEN, {"user", "dir", "found"}),
                (contract.MSG_SOCKET_DIR_UNOBSERVABLE, {"user", "dir"}),
                (contract.MSG_SOCKET_DIR_MISSING, {"user", "dir"}),
                (contract.MSG_SOCKET_UNOBSERVABLE, {"user"}),
                (contract.MSG_SOCKET_SWAPPED, {"user", "socket", "mode", "owner"}),
                (contract.MSG_TEMPLATE_RESTART_PENDING, set()),
                (contract.MSG_IDE_UNOBSERVABLE, set())):
            found = {f for _, f, _, _ in string.Formatter().parse(msg) if f}
            self.assertEqual(keys, found, msg[:70])

    def test_the_new_lines_really_print(self) -> None:
        import contextlib
        from vide.system import SocketStat
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._line(self._facts(4242, 0o2750), printit=True)
            self._line(self._facts(0, 0o2750), euid=1000, printit=True)
            self._line(self._facts(0, 0o2750), printit=True,
                       stat=SocketStat(is_socket=False, uid=0, gid=0, mode=0o777))
        out = buf.getvalue()
        for needle in ("UNFROZEN", "not observable without root", "SWAPPED",
                       "caddy pools connections", "ONE AT A TIME"):
            self.assertIn(needle, out)

    def test_path_is_denied_really_distinguishes_the_two_failures(self) -> None:
        """The seam itself, against a real filesystem. Every other row stubs it,
        which means `return False` re-opens the defect it exists to close while
        those rows stay green — the exact shape this task has hit six times.

        The denied arm needs a non-root euid: root's CAP_DAC_OVERRIDE reads
        through a 0000 directory, so the function correctly returns False there
        and the case is unobservable rather than broken. It is skipped LOUDLY
        instead of silently passing, because a row that cannot run is not
        evidence and should not look like it."""
        from vide import system as _sys
        with tempfile.TemporaryDirectory() as t:
            absent = Path(t) / "nope"
            self.assertFalse(_sys.path_is_denied(absent))          # ENOENT, not EACCES
            self.assertIsNone(_sys.path_facts(absent))             # …and both look alike
            walled = Path(t) / "walled"
            walled.mkdir()
            (walled / "x").write_text("")
            walled.chmod(0o000)
            try:
                if os.geteuid() == 0:
                    self.skipTest("running as root: CAP_DAC_OVERRIDE reads through "
                                  "0000, so the denied arm cannot be observed here")
                self.assertTrue(_sys.path_is_denied(walled / "x"))
                self.assertIsNone(_sys.path_facts(walled / "x"))
            finally:
                # inside the `with`, or TemporaryDirectory cannot remove the tree
                walled.chmod(0o755)

    def test_a_missing_directory_is_not_described_as_the_users_to_rewrite(self) -> None:
        # UNFROZEN's sentence is about who OWNS the directory, which says nothing
        # about one that is not there — and sends the operator looking at
        # permissions for a problem that is an absence.
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._line(None, printit=True)                      # absent
            self._line(None, printit=True, denied=True)         # unreadable
            self._line(self._facts(4242, 0o2750), printit=True)  # genuinely unfrozen
        lines = [ln for ln in buf.getvalue().splitlines() if "socket dir" in ln]
        self.assertEqual(3, len(lines), lines)
        missing, unobservable, unfrozen = lines
        self.assertIn("MISSING", missing)
        # …and it must NOT be the ownership sentence, which is the whole point.
        self.assertNotIn("instance user owns", missing)
        self.assertIn("not observable", unobservable)
        self.assertIn("UNFROZEN", unfrozen)
        self.assertIn("instance user owns", unfrozen)

    def test_socket_stat_answers_about_the_entry_not_its_target(self) -> None:
        # lstat, not stat. Under stat, a symlink planted at the socket path
        # reports the TARGET's type and owner — the entry that was swapped answers
        # for the thing it points at, which is the one question a detector must
        # not get wrong. The freeze is what prevents the swap; this describes what
        # is actually there.
        import socket as _s
        from vide import system as _sys
        with tempfile.TemporaryDirectory() as t:
            real, link = Path(t) / "r.sock", Path(t) / "l.sock"
            s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            self.addCleanup(s.close)
            s.bind(str(real))
            link.symlink_to(real)
            self.assertTrue(_sys.socket_stat(real).is_socket)
            self.assertFalse(_sys.socket_stat(link).is_socket)


class TestStdinProtocol(unittest.TestCase):
    def _run(self, args, stdin_text="", dry=False):
        env_patch = {}
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli.sys, "stdin", io.StringIO(stdin_text)), \
                 mock.patch.object(cli, "run_install", return_value=0) as ri, \
                 mock.patch.object(cli.os, "geteuid", return_value=0), \
                 mock.patch.object(cli.os, "isatty", return_value=False):
                rc = cli._install_entry(args, Path(t), False, env_patch)
            return rc, ri

    def test_mutual_exclusion(self) -> None:
        with self.assertRaises(UsageError) as cm:
            self._run(["--password-stdin", "--sso-secrets-stdin"])
        self.assertIn("mutually exclusive", str(cm.exception))

    def test_secret_reaches_prompter_not_argv(self) -> None:
        rc, ri = self._run(
            ["--auth", "sso", "--user", "u", "--fqdn", "u.example.com",
             "--sso-client-id", "cid.apps.googleusercontent.com", "--sso-secrets-stdin"],
            stdin_text="VIDE_SSO_CLIENT_ID=cid.apps.googleusercontent.com\n"
                       "VIDE_SSO_CLIENT_SECRET=GOCSPX-real\n")
        self.assertEqual(rc, 0)
        pr = ri.call_args.kwargs["prompter"]
        self.assertEqual(pr._sso_secret, "GOCSPX-real")

    def test_dry_run_does_not_read_stdin(self) -> None:
        # A stdin double whose read() raises: the dry-run narration must NOT
        # consume it.
        class Boom(io.StringIO):
            def read(self, *a):
                raise AssertionError("dry-run consumed stdin")

        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli.sys, "stdin", Boom()), \
                 mock.patch.object(cli, "run_install", return_value=0), \
                 mock.patch.object(cli.os, "geteuid", return_value=0), \
                 mock.patch.object(cli.os, "isatty", return_value=False):
                rc = cli._install_entry(
                    ["--auth", "sso", "--user", "u", "--fqdn", "u.example.com",
                     "--sso-secrets-stdin", "--dry-run"], Path(t), False, {})
        self.assertEqual(rc, 0)


class TestSsoReaffirm(unittest.TestCase):
    """The only recovery path for a wrong Google client secret. Nothing on the
    box can detect one — it fails at token exchange on Google's side — so doctor
    has no trigger, and before this the only way out was hand-editing proxy.env
    or deleting it, which loses the cookie secret and signs out the fleet."""

    def test_the_flag_forces_a_re_ask_on_a_fully_provisioned_box(self) -> None:
        pr = cli.PlainPrompter(cli.Reporter(), sso_reaffirm=True)
        self.assertTrue(pr.sso_reaffirm)
        # …and the default stays off, so an ordinary converge never re-asks.
        self.assertFalse(cli.PlainPrompter(cli.Reporter()).sso_reaffirm)

    def test_the_flag_is_accepted_and_reaches_the_prompter(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli, "run_install", return_value=0) as ri, \
                 mock.patch.object(cli.os, "geteuid", return_value=0), \
                 mock.patch.object(cli.os, "isatty", return_value=False):
                rc = cli._install_entry(["--auth", "sso", "--user", "u",
                                         "--fqdn", "u.example.com",
                                         "--sso-reaffirm", "--dry-run"],
                                        Path(t), False, {})
        self.assertEqual(rc, 0)
        self.assertTrue(ri.call_args.kwargs["prompter"].sso_reaffirm)

    def test_an_unknown_sso_flag_still_dies(self) -> None:
        # The flag list is exact; a typo must not be silently ignored.
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(UsageError):
                cli._install_entry(["--sso-reaffirmm"], Path(t), False, {})


class TestR1GateArgvOnly(unittest.TestCase):
    """R1 refuses --sso-* flags outside sso mode — but its parent-domain leg is
    ARGV-only: VIDE_SSO_PARENT_DOMAIN in .env is fleet CONFIG for future SSO
    installs, not a request on THIS run, and gating on the resolved cfg value
    falsely refused a legitimate converge that omits --auth (resolve_plan reads
    a recorded instance's mode from the record)."""

    def _entry(self, args, repo):
        with mock.patch.object(cli, "run_install", return_value=0) as ri, \
             mock.patch.object(cli.os, "geteuid", return_value=0), \
             mock.patch.object(cli.os, "isatty", return_value=False):
            rc = cli._install_entry(args, repo, False, {})
        return rc, ri

    def test_env_file_parent_domain_does_not_refuse_a_converge(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / ".env").write_text("VIDE_SSO_PARENT_DOMAIN=example.com\n")
            # load_config setdefaults .env rows into os.environ; patch.dict
            # restores it so the fleet value cannot leak into other tests.
            with mock.patch.dict("os.environ", {}, clear=False):
                _scrub_vide_env()
                rc, ri = self._entry(["--user", "u"], Path(t))
        self.assertEqual(rc, 0)
        ri.assert_called_once()

    def test_env_file_parent_domain_survives_the_real_entry_point(self) -> None:
        """The sibling above calls _install_entry DIRECTLY — and that is exactly
        why the shipped path stayed broken while it was green. Every real entry
        goes through main(), which runs load_config before dispatching, so all
        .env rows are already in os.environ by the time _install_entry looks;
        a snapshot taken there sees the fleet row as an exported one. The row
        below is the one .env.example recommends, and with VIDE_AUTH empty (its
        documented default) it made EVERY install — wizard, password, any mode —
        die EX_USAGE naming flags the operator never passed."""
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / ".env").write_text("VIDE_SSO_PARENT_DOMAIN=example.com\n")
            with mock.patch.dict("os.environ", {}, clear=False):
                _scrub_vide_env()
                with _gate_off(), \
                     mock.patch.object(cli, "run_install", return_value=0) as ri, \
                     mock.patch.object(cli.os, "geteuid", return_value=0), \
                     mock.patch.object(cli.os, "isatty", return_value=False):
                    rc = cli.main(["install", "--user", "u"], Path(t))
        self.assertEqual(rc, 0)
        ri.assert_called_once()

    def test_argv_parent_domain_still_requires_auth_sso(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.dict("os.environ", {}, clear=False):
                _scrub_vide_env()
                with self.assertRaises(UsageError) as cm:
                    self._entry(["--user", "u", "--parent-domain", "example.com"],
                                Path(t))
            self.assertIn("--auth sso", str(cm.exception))

    def test_exported_env_parent_domain_still_requires_auth_sso(self) -> None:
        # A shell export is per-run intent (argv-like), NOT fleet config: it
        # stays gated. Snapshotted before load_config's setdefault makes the
        # two channels indistinguishable.
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.dict("os.environ", {}, clear=False):
                _scrub_vide_env()
                os.environ["VIDE_SSO_PARENT_DOMAIN"] = "example.com"
                with self.assertRaises(UsageError) as cm:
                    self._entry(["--user", "u"], Path(t))
            self.assertIn("--auth sso", str(cm.exception))


class TestWizardReceivesArgvSsoSeeds(unittest.TestCase):
    """--sso-client-id/--sso-allow on a wizard-eligible invocation must reach
    the wizard as prefills — only PlainPrompter got them, so the wizard re-asked
    for data already given on the command line."""

    def test_run_wizard_gets_client_id_and_allow(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            with mock.patch.object(cli, "_run_wizard", return_value=0) as rw, \
                 mock.patch.object(cli.os, "geteuid", return_value=0), \
                 mock.patch.object(cli.os, "isatty", return_value=True), \
                 mock.patch("vide.tui.probe"), \
                 mock.patch.dict("os.environ", {}, clear=False):
                _scrub_vide_env()
                rc = cli._install_entry(
                    ["--auth", "sso",
                     "--sso-client-id", "cid.apps.googleusercontent.com",
                     "--sso-allow", "a@x.com"], Path(t), False, {})
        self.assertEqual(rc, 0)
        kw = rw.call_args.kwargs
        self.assertEqual(kw["sso_client_id"], "cid.apps.googleusercontent.com")
        self.assertEqual(kw["sso_allow"], "a@x.com")


class TestRunWizardSeedsTuiPrompter(unittest.TestCase):
    """The MIDDLE hop of the wizard-seed chain: entry→_run_wizard kwargs and
    TuiPrompter prefill behavior are pinned elsewhere, but without this test
    the kwargs could be dropped from the TuiPrompter(...) call site and the
    whole suite stayed green — the exact regression shape of the fixed defect."""

    def test_prompter_constructed_with_seeds(self) -> None:
        from fakes import make_config
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            # _run_wizard imports Session/TuiPrompter function-locally, so the
            # module-path patches take effect at call time.
            with mock.patch("vide.tui.session.Session"), \
                 mock.patch("vide.tui.screens.TuiPrompter") as tp, \
                 mock.patch.object(cli, "run_install", return_value=0):
                rc = cli._run_wizard(cfg, False,
                                     sso_client_id="cid.apps.googleusercontent.com",
                                     sso_allow="a@x.com")
        self.assertEqual(rc, 0)
        kw = tp.call_args.kwargs
        self.assertEqual(kw["sso_client_id"], "cid.apps.googleusercontent.com")
        self.assertEqual(kw["sso_allow"], "a@x.com")


class TestInfoUsesRecordedFqdn(unittest.TestCase):
    """`vide info <sso-user>` must re-emit the snippet from the PERSISTED
    record — claim_binding writes VIDE_FQDN precisely for this — not from the
    current run's cfg.fqdn, which is empty on a bare `vide info` and rendered
    the <SUBDOMAIN> placeholder, breaking the 're-emit anytime' promise."""

    def _info(self, record_text: str, *, served=True, **cfg_overrides) -> str:
        """Run cmd_info against a synthetic SSO record; returns stdout."""
        out, _ = self._info_both(record_text, served=served, **cfg_overrides)
        return out

    def _info_both(self, record_text: str, *, served=True, **cfg_overrides):
        """…and the WARN channel beside it, because the two are the subject of
        the row below: the block goes to stdout and the caveat to stderr, so a
        machine reader of this verb sees byte-identical output either way."""
        import contextlib
        from fakes import capturing_reporter, make_config
        from vide.confirm import Confirmer
        from vide.executor import Executor
        from vide.registry import Binding
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t), **cfg_overrides)
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            cfg.sso_dir.mkdir(parents=True, exist_ok=True)
            (cfg.sso_dir / "caddy").mkdir(parents=True, exist_ok=True)
            (cfg.state_dir / "u.env").write_text(record_text)
            (cfg.sso_dir / "fleet.env").write_text(
                "VIDE_SSO_PARENT_DOMAIN=example.com\n")
            rep, err = capturing_reporter()
            ctx = cli.Context(
                cfg=cfg, ex=Executor(dry_run=True, reporter=rep, cfg=cfg),
                rep=rep, conf=Confirmer(yes_argv=False, environ={}, reporter=rep))
            out = io.StringIO()
            # SEAMED AT THE HOST, not by mocking pin_is_served itself: the
            # mutation rows for this verb target the CALL, and a fixture that
            # replaced the callee would still be honest but would stop
            # exercising the predicate the caveat actually rests on.
            from vide import oauth2proxy, system as _sys
            holders = _sys.HopHolders(
                certain=frozenset({0} if served else set()),
                possible=frozenset(), served=frozenset())
            with mock.patch.object(cli.registry, "instance_mode", return_value="sso"), \
                 mock.patch.object(cli.registry, "instance_binding",
                                   return_value=Binding.unix("/run/vide/u/code-server.sock")), \
                 mock.patch.object(cli.system, "user_home", return_value="/home/u"), \
                 mock.patch.object(oauth2proxy.system, "hop_holders",
                                   return_value=holders), \
                 mock.patch.object(oauth2proxy.system, "user_uid",
                                   return_value=None), \
                 contextlib.redirect_stdout(out):
                rc = cli.cmd_info(ctx, ["u"])
            self.assertEqual(rc, 0)
            return out.getvalue(), err.getvalue()

    def test_a_moved_pin_box_needs_no_caveat_because_the_block_carries_no_hop(self) -> None:
        """THE WARNING THIS REPLACES WAS RIGHT, AND ITS SUBJECT IS GONE. `vide
        info` is the verb every other message names, and while it rendered the
        whole auth body a moved-pin box got a block naming an address nothing
        held — pasting it published the fleet's login flow under the operator's
        real TLS at that address, so the verb had to say DO NOT RE-PASTE.

        It emits a site header and an import now. The port is not in the text at
        all, so there is no stale address a paste can carry: whatever the pin is
        doing, the operator ends up importing the body VIDE actually wrote. The
        caveat went with the hazard rather than being softened, and the row that
        proves it is `hops(...) == set()` — a claim about the artifact, not about
        the absence of a string."""
        from vide import contract
        from vide import caddy as _c
        out, err = self._info_both(
            contract.SOCKET_RECORD.format(
                socket="/run/vide/u/code-server.sock", fqdn="u.example.com"),
            served=False)
        self.assertNotIn("DO NOT RE-PASTE", err)
        self.assertNotIn("DO NOT RE-PASTE", out)
        self.assertIn("auth.example.com", out)
        # The load-bearing half: nothing in what stdout handed over names a hop.
        block = out[out.index("# --- VIDE shared SSO auth endpoint"):]
        self.assertEqual(_c.hops(block), set(),
                         "the pasted block names a port again — the caveat this "
                         "row retired only stayed retired while it did not")

    def test_a_fleet_on_its_pin_is_not_warned(self) -> None:
        """Once the opposite SIGN of a branch keyed on whether the pin was being
        served. There is no branch now — the emitted text names no port, so
        neither box can be handed a stale address and neither is warned. The row
        is kept anyway, and deliberately: it is the tripwire for a re-introduced
        caveat keyed on the pin, which would print on every healthy box in the
        fleet and be ignored by the time it was true."""
        from vide import contract
        out, err = self._info_both(
            contract.SOCKET_RECORD.format(
                socket="/run/vide/u/code-server.sock", fqdn="u.example.com"),
            served=True)
        self.assertNotIn("DO NOT RE-PASTE", err)
        self.assertIn("auth.example.com", out)

    def test_info_emits_recorded_fqdn(self) -> None:
        from vide import contract
        out = self._info(contract.SOCKET_RECORD.format(
            socket="/run/vide/u/code-server.sock", fqdn="u.example.com"))
        self.assertIn("u.example.com {", out)
        self.assertNotIn("<SUBDOMAIN>", out)

    def test_info_emits_the_import_shell_not_the_whole_body(self) -> None:
        # `info` used to be the ONE channel through which a changed auth block
        # reached an installed fleet, because a converge would not refresh the
        # operator's pasted copy — so it rendered the entire body from code. Both
        # halves of that stopped being true: converge re-lands the body now, and
        # what the operator holds is a site header and an import. So the verb
        # emits the shell, and the body it points at is VIDE's to keep current.
        from vide import contract
        out = self._info(contract.SOCKET_RECORD.format(
            socket="/run/vide/u/code-server.sock", fqdn="u.example.com"))
        self.assertIn("auth.example.com {", out)
        self.assertIn("import ", out)
        self.assertIn("caddy/auth.caddy", out)
        # The body's own directives must NOT be here: printing them again would
        # invite the paste this whole change removed.
        self.assertNotIn("handle / {", out)
        self.assertNotIn("forward_auth", out)

    def test_record_beats_a_stale_env_fqdn(self) -> None:
        # A leftover VIDE_FQDN in .env/env must not re-head EVERY instance's
        # snippet: the record is the truth (resolve treats the contradiction
        # as a ConfigError; info must not be the one place it silently wins).
        from vide import contract
        out = self._info(contract.SOCKET_RECORD.format(
            socket="/run/vide/u/code-server.sock", fqdn="u.example.com"),
            fqdn="stale.example.com")
        self.assertIn("u.example.com {", out)
        self.assertNotIn("stale.example.com", out)

    def test_legacy_record_without_fqdn_degrades_to_placeholder(self) -> None:
        # Pre-slice records carry no VIDE_FQDN (contract: old records stay
        # valid): info must fall back to the placeholder, never crash.
        out = self._info("VIDE_MODE=sso\nVIDE_SOCKET=/run/vide/u/code-server.sock\n")
        self.assertIn("<SUBDOMAIN>.example.com {", out)


class TestTwinNeverCarriesSecret(unittest.TestCase):
    def test_twin_flags_render_client_id_never_secret(self) -> None:
        twin = cli._twin_flags({"VIDE_USER": "u", "VIDE_AUTH": "sso",
                                "VIDE_FQDN": "u.example.com"},
                               sso_client_id="cid.apps.googleusercontent.com")
        self.assertIn("--auth sso", twin)
        self.assertIn("--sso-client-id cid.apps.googleusercontent.com", twin)
        self.assertNotIn("GOCSPX", twin)
        self.assertNotIn("--sso-client-secret", twin)


if __name__ == "__main__":
    unittest.main()
