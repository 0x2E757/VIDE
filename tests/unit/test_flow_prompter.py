"""The ask-points in run_install: answers reach the domain calls, secrets are
DELIVERED (not Reporter-emitted by domain code), and the shortcut journeys
(upgrade/rotate/reinstall) run the verb operations. The arbiter-shape
SHOWN-ONCE pin lives here now — it moved out of test_secrets when the domain
stopped announcing its own secrets."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import RecordingExecutor, ScriptedPrompter, make_config  # noqa: E402
from vide import install_flow  # noqa: E402
from vide.confirm import Confirmer  # noqa: E402
from vide.prompter import InstanceAction  # noqa: E402
from vide.reporter import Reporter  # noqa: E402


class _Flow:
    """run_install with the heavy ends stubbed; every stub records."""

    def __init__(self, tmp: Path, *, existing_port=None, provisioned=False,
                 nvm_bindir=None, **cfg_over) -> None:
        self.cfg = make_config(tmp, vide_user=cfg_over.pop("vide_user", "alice"),
                               **cfg_over)
        self.ex = RecordingExecutor()
        self.errs = io.StringIO()
        self.out = io.StringIO()
        self.rep = Reporter(stream=self.errs)
        self.conf = Confirmer(yes_argv=True, environ={}, reporter=self.rep)
        self.calls: list[tuple] = []
        self.ensure_config_kwargs: dict = {}
        self._existing_port = existing_port
        self._provisioned = provisioned
        self._nvm_bindir = nvm_bindir

    def run(self, prompter=None) -> int:
        fl = install_flow

        def rec(name, ret=None):
            def _f(*a, **k):
                self.calls.append((name,) + tuple(k.items()))
                return ret
            return _f

        def fake_ensure_config(cfg, ex, rep, user, port, password=None):
            self.ensure_config_kwargs = {"user": user, "port": port,
                                         "password": password}
            return None if password is not None else "GEN+PW=="

        patches = [
            mock.patch.object(fl, "require_root"),
            mock.patch.object(fl, "ensure_prereqs"),
            mock.patch.object(fl.preflight, "platform_gate"),
            mock.patch.object(fl.preflight, "tools_gate"),
            mock.patch.object(fl.system, "user_exists", return_value=True),
            mock.patch.object(fl.system, "user_home",
                              return_value=Path("/home/alice")),
            mock.patch.object(fl.ports, "get_port",
                              return_value=self._existing_port),
            mock.patch.object(fl.ports, "claim_port", return_value=9797),
            # Existing-instance detection now keys on the mode record, not the
            # bare port (an SSO instance has no port). Mirror the old behavior:
            # a set existing_port means a password instance already exists.
            mock.patch.object(fl.registry, "instance_mode",
                              return_value="password" if self._existing_port else None),
            mock.patch.object(fl.registry, "instance_binding",
                              return_value=install_flow.registry.Binding.tcp(
                                  self._existing_port or 9797)),
            mock.patch.object(fl.registry, "instance_active", return_value=True),
            mock.patch.object(fl.registry, "instance_version", return_value="4.1.0"),
            mock.patch.object(fl.node, "nvm_resolve_bindir",
                              return_value=self._nvm_bindir),
            mock.patch.object(fl.node, "pnpm_resolve_bin", return_value=None),
            mock.patch.object(fl.node, "ensure_node_pnpm",
                              side_effect=rec("ensure_node_pnpm")),
            mock.patch.object(fl.node, "toolchain_status_line",
                              return_value="HEALTHY (stub)"),
            mock.patch.object(fl.codeserver, "ensure_code_server",
                              side_effect=rec("ensure_code_server", "latest")),
            mock.patch.object(fl.codeserver, "upgrade_code_server",
                              side_effect=rec("upgrade")),
            mock.patch.object(fl.secrets, "config_provisioned",
                              return_value=self._provisioned),
            # resolve_plan decides the password question from the Executor-free
            # observer; apply's ensure_config still consults config_provisioned.
            mock.patch.object(fl.secrets, "has_password_config",
                              return_value=self._provisioned),
            mock.patch.object(fl.secrets, "ensure_config",
                              side_effect=fake_ensure_config),
            mock.patch.object(fl.secrets, "rotate_config",
                              side_effect=rec("rotate", "NEW+PW==")),
            mock.patch.object(fl.sysd, "install_unit"),
            mock.patch.object(fl.sysd, "enable_start"),
            mock.patch.object(fl.sysd, "restart_instance",
                              side_effect=rec("restart")),
            mock.patch.object(fl, "link_cli"),
            mock.patch.object(fl, "destroy_instance", side_effect=rec("destroy")),
            mock.patch.object(fl.transport, "probe_transport",
                              side_effect=rec("probe")),
            contextlib.redirect_stdout(self.out),
        ]
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            return fl.run_install(self.cfg, self.ex, self.rep, self.conf,
                                  prompter=prompter)

    def call_names(self) -> list[str]:
        return [c[0] for c in self.calls]


class TestSecretDelivery(unittest.TestCase):
    def test_plain_run_emits_the_arbiter_shape_password_line(self) -> None:
        """The SHOWN-ONCE line the arbiter seds: PlainPrompter must emit it
        byte-exactly where the bash era did (moved here from test_secrets)."""
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td))
            self.assertEqual(f.run(), 0)
            lines = [l for l in f.errs.getvalue().splitlines() if "SHOWN ONCE" in l]
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].endswith("): GEN+PW=="))
            self.assertIn("code-server password for 'alice'", lines[0])

    def test_scripted_password_reaches_ensure_config_and_is_never_echoed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td))
            pr = ScriptedPrompter(password="operatorpw123456")
            self.assertEqual(f.run(pr), 0)
            self.assertEqual(f.ensure_config_kwargs["password"], "operatorpw123456")
            self.assertNotIn("operatorpw123456", f.errs.getvalue())
            self.assertNotIn("SHOWN ONCE", f.errs.getvalue(),
                             "an operator-supplied password must not be reprinted")
            self.assertTrue(pr.consumed())

    def test_vide_login_password_is_delivered_never_reported(self) -> None:
        """The third SHOWN-ONCE secret (the fallback user's login/sudo
        password) rides the same deliver_secret channel: a regression back to
        rep.info() would keep the arbiter green and paint the sudo password
        onto the wizard's log pane."""
        from vide import contract
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), vide_user="vide")
            # ensure_sudo patched too: without it the test would really probe
            # have_cmd("sudo") and become host-dependent
            with mock.patch.object(install_flow, "ensure_sudo"), \
                 mock.patch.object(install_flow.users, "ensure_user"), \
                 mock.patch.object(install_flow.users, "set_user_password",
                                   return_value="LOGIN+PW=="), \
                 mock.patch.object(install_flow.users, "install_sudoers"):
                pr = ScriptedPrompter()
                self.assertEqual(f.run(pr), 0)
        login = [s for s in pr.secrets if "login/sudo" in s]
        self.assertEqual(len(login), 1)
        self.assertEqual(login[0],
                         contract.MSG_LOGIN_PASSWORD.format(user="vide", pw="LOGIN+PW=="))
        self.assertNotIn("LOGIN+PW==", f.errs.getvalue(),
                         "the login password must never transit the Reporter")

    def test_vide_branch_ensures_the_sudo_package_before_the_user(self) -> None:
        """The smoke §1 finding pinned at the sequencer level: minimal images
        ship the sudo GROUP without the PACKAGE, so without this step the
        journey dies at visudo a minute after useradd. Order matters only as
        the visudo dependency, but pinning it makes a reorder a conscious
        act."""
        order: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), vide_user="vide")
            with mock.patch.object(install_flow, "ensure_sudo",
                                   side_effect=lambda *a: order.append("ensure_sudo")), \
                 mock.patch.object(install_flow.users, "ensure_user",
                                   side_effect=lambda *a: order.append("ensure_user")), \
                 mock.patch.object(install_flow.users, "set_user_password",
                                   return_value=None), \
                 mock.patch.object(install_flow.users, "install_sudoers",
                                   side_effect=lambda *a: order.append("install_sudoers")):
                self.assertEqual(f.run(ScriptedPrompter()), 0)
        self.assertEqual(order, ["ensure_sudo", "ensure_user", "install_sudoers"])

    def test_password_question_skipped_when_already_provisioned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), provisioned=True)
            pr = ScriptedPrompter()
            self.assertEqual(f.run(pr), 0)
            self.assertNotIn("password", [a[0] for a in pr.asks],
                             "never ask for a password that will not be minted")


class TestAskPoints(unittest.TestCase):
    def test_exposure_ack_fires_first_and_target_user_answer_wins(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td))
            pr = ScriptedPrompter(target_user="alice")
            self.assertEqual(f.run(pr), 0)
            self.assertEqual(pr.asks[0], ("exposure",))
            self.assertIn("target instance user: alice", f.errs.getvalue())

    def test_full_rail_ask_order_is_pinned(self) -> None:
        """The question journey is a designed surface; an ask-point reorder
        is exactly the drift the parity narration cannot see (asks emit
        nothing). Fresh box (no toolchain, no instance): three asks."""
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td))
            pr = ScriptedPrompter()
            self.assertEqual(f.run(pr), 0)
            self.assertEqual([a[0] for a in pr.asks],
                             ["exposure", "target_user", "auth_mode", "password", "fqdn"])

    def test_toolchain_ask_fires_only_when_a_toolchain_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), nvm_bindir=Path(td) / "versions/node/v26.5.0/bin")
            pr = ScriptedPrompter(toolchain=True)
            self.assertEqual(f.run(pr), 0)
            self.assertIn(("toolchain", "v26.5.0"), pr.asks)
            forced = [c for c in f.calls if c[0] == "ensure_node_pnpm"]
            self.assertEqual(forced[0][1], ("force", True),
                             "the wizard's reinstall answer must reach the domain")

    def test_no_toolchain_no_question(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), nvm_bindir=None)
            pr = ScriptedPrompter()
            f.run(pr)
            self.assertNotIn("toolchain", [a[0] for a in pr.asks],
                             "only ask when a real fork exists")

    def test_fqdn_answer_lands_in_snippet_and_probe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td))
            f.run(ScriptedPrompter(fqdn="ide.example.test"))
            self.assertIn("ide.example.test {", f.out.getvalue())


class TestExistingInstanceActions(unittest.TestCase):
    def test_converge_default_walks_the_full_rail(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), existing_port=9700)
            pr = ScriptedPrompter()
            self.assertEqual(f.run(pr), 0)
            self.assertIn(("existing_instance", "alice"), pr.asks)
            self.assertIn("ensure_code_server", f.call_names())

    def test_upgrade_shortcuts_to_the_verb_operation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), existing_port=9700)
            pr = ScriptedPrompter(existing_instance=InstanceAction.UPGRADE)
            self.assertEqual(f.run(pr), 0)
            names = f.call_names()
            self.assertIn("upgrade", names)
            self.assertIn("restart", names)
            self.assertNotIn("ensure_code_server", names, "no full-rail re-walk")
            self.assertEqual(pr.summary.action, InstanceAction.UPGRADE)

    def test_rotate_delivers_the_new_password_through_the_prompter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), existing_port=9700)
            pr = ScriptedPrompter(existing_instance=InstanceAction.ROTATE)
            self.assertEqual(f.run(pr), 0)
            self.assertEqual(len(pr.secrets), 1)
            self.assertTrue(pr.secrets[0].endswith("): NEW+PW=="))
            self.assertIn("restart", f.call_names())

    def test_reinstall_destroys_then_walks_the_full_rail(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), existing_port=9700)
            pr = ScriptedPrompter(existing_instance=InstanceAction.REINSTALL)
            self.assertEqual(f.run(pr), 0)
            names = f.call_names()
            self.assertIn("destroy", names)
            self.assertIn("ensure_code_server", names)
            self.assertLess(names.index("destroy"), names.index("ensure_code_server"))

    def test_declined_reinstall_without_reask_dies_aborted(self) -> None:
        """The plain-path guard: a scripted/plain prompter cannot re-answer,
        so a declined destroy confirm must DIE (a re-ask would loop forever
        on the same scripted answer). PlainPrompter.can_reask() is pinned
        False here for exactly that reason."""
        from vide.errors import UsageError
        from vide.prompter import PlainPrompter
        from vide.reporter import Reporter
        self.assertFalse(PlainPrompter(Reporter(stream=io.StringIO())).can_reask())
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), existing_port=9700)
            f.conf = Confirmer(yes_argv=False, environ={}, reporter=f.rep,
                               tty_opener=lambda: (io.StringIO(), io.StringIO("n\n")))
            pr = ScriptedPrompter(existing_instance=InstanceAction.REINSTALL)
            self.assertFalse(pr.can_reask())
            with self.assertRaises(UsageError):
                f.run(pr)
            self.assertNotIn("destroy", f.call_names())

    def test_declined_reinstall_with_reask_returns_to_the_menu(self) -> None:
        """The wizard direction of the same fork: decline → the ask fires
        again; a changed mind (CONVERGE) then proceeds without destroying."""
        class ReaskingPrompter(ScriptedPrompter):
            def can_reask(self) -> bool:
                return True
        with tempfile.TemporaryDirectory() as td:
            f = _Flow(Path(td), existing_port=9700)
            f.conf = Confirmer(yes_argv=False, environ={}, reporter=f.rep,
                               tty_opener=lambda: (io.StringIO(), io.StringIO("n\n")))
            pr = ReaskingPrompter()
            pr.answers = {}  # ordered script via a queue instead
            script = [InstanceAction.REINSTALL, InstanceAction.CONVERGE]
            pr.existing_instance_action = lambda inst: script.pop(0)  # type: ignore[method-assign]
            self.assertEqual(f.run(pr), 0)
            self.assertEqual(script, [], "the ask must fire again after a decline")
            names = f.call_names()
            self.assertNotIn("destroy", names)
            self.assertIn("ensure_code_server", names)


if __name__ == "__main__":
    unittest.main()
