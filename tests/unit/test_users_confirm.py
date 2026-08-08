"""User resolution precedence, sudoers validation, and the Confirmer — the
argv-only guard with the /dev/tty open-probe."""
from __future__ import annotations

import io
import subprocess
import sys
import unittest
from errno import ENXIO
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import RecordingExecutor, quiet_reporter  # noqa: E402
from vide import users  # noqa: E402
from vide.confirm import Confirmer  # noqa: E402
from vide.errors import ConfigError, UsageError  # noqa: E402


class TestResolveTargetUser(unittest.TestCase):
    def test_vide_user_wins(self) -> None:
        self.assertEqual(users.resolve_target_user("bob", "alice", 0, False, "x"), "bob")

    def test_explicit_root(self) -> None:
        self.assertEqual(users.resolve_target_user("root", "", 0, False, "x"), "root")

    def test_sudo_non_root_user(self) -> None:
        self.assertEqual(users.resolve_target_user("", "alice", 0, False, "x"), "alice")

    def test_bare_root_falls_back_to_vide(self) -> None:
        self.assertEqual(users.resolve_target_user("", "", 0, False, "root"), "vide")

    def test_bare_root_with_allow_root_is_root(self) -> None:
        self.assertEqual(users.resolve_target_user("", "", 0, True, "root"), "root")

    def test_non_root_bare_is_current_user(self) -> None:
        self.assertEqual(users.resolve_target_user("", "", 1000, False, "carol"), "carol")

    def test_is_root_fallback(self) -> None:
        self.assertTrue(users.is_root_fallback("", "", 0, False))
        self.assertFalse(users.is_root_fallback("bob", "", 0, False))
        self.assertFalse(users.is_root_fallback("", "alice", 0, False))
        self.assertFalse(users.is_root_fallback("", "", 0, True))
        self.assertFalse(users.is_root_fallback("", "", 1000, False))


class TestInstallSudoers(unittest.TestCase):
    def test_validated_then_written_0440(self) -> None:
        ex = RecordingExecutor()
        ok = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(users.system, "visudo_cmd",
                               return_value="/usr/sbin/visudo"), \
             mock.patch.object(users.system, "query", return_value=ok) as q:
            users.install_sudoers(ex, quiet_reporter(), "vide")
        self.assertEqual(q.call_args.args[0][:2], ["/usr/sbin/visudo", "-cf"])
        writes = [a for a in ex.actions if a[0] == "atomic_write"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][2], 0o440)
        self.assertIn("timestamp_timeout=0", ex.contents[writes[0][1]])

    def test_failed_validation_dies_config_78_and_writes_nothing(self) -> None:
        # A malformed sudoers file can lock sudo box-wide. The message must
        # carry visudo's own evidence — the live smoke panel once blamed
        # "validation" when the true cause was a missing binary.
        ex = RecordingExecutor()
        bad = subprocess.CompletedProcess([], 1, stdout="", stderr="syntax error")
        with mock.patch.object(users.system, "visudo_cmd",
                               return_value="/usr/sbin/visudo"), \
             mock.patch.object(users.system, "query", return_value=bad):
            with self.assertRaises(ConfigError) as cm:
                users.install_sudoers(ex, quiet_reporter(), "vide")
        self.assertEqual(ex.actions, [])
        self.assertIn("syntax error", str(cm.exception),
                      "visudo's stderr must reach the operator")

    def test_missing_visudo_dies_naming_the_package_not_validation(self) -> None:
        """The smoke §1 finding: minimal images ship the sudo GROUP without
        the PACKAGE; the failure must say so — not blame the content."""
        ex = RecordingExecutor()
        with mock.patch.object(users.system, "visudo_cmd", return_value=None):
            with self.assertRaises(ConfigError) as cm:
                users.install_sudoers(ex, quiet_reporter(), "vide")
        self.assertEqual(ex.actions, [], "nothing may be written unvalidated")
        msg = str(cm.exception)
        self.assertIn("visudo not found", msg)
        self.assertIn("'sudo' package", msg)
        self.assertNotIn("failed visudo validation", msg,
                         "the two failures must stay distinguishable")

    def test_missing_visudo_in_dry_run_narrates_and_previews_the_write(self) -> None:
        """A preview must run on any box: the pre-fix code hard-failed a
        --dry-run on a sudo-less image (the I2 invariant never saw it — its
        sandbox user dodges the vide branch deliberately)."""
        from vide.executor import Executor
        from vide.reporter import Reporter
        buf = io.StringIO()
        rep = Reporter(stream=buf)
        ex = Executor(dry_run=True, reporter=rep)
        with mock.patch.object(users.system, "visudo_cmd", return_value=None):
            users.install_sudoers(ex, rep, "vide")
        log = buf.getvalue()
        self.assertIn("[dry-run] validate sudoers drop-in", log)
        self.assertIn("[dry-run] atomic_write /etc/sudoers.d/vide-vide", log)


def _tty(reply: str):
    def opener():
        return io.StringIO(), io.StringIO(reply)
    return opener


def _no_tty():
    raise OSError(ENXIO, "No such device or address")


class TestConfirmer(unittest.TestCase):
    def _c(self, *, yes=False, env=None, opener=None) -> Confirmer:
        return Confirmer(yes_argv=yes, environ=env or {}, reporter=quiet_reporter(),
                         tty_opener=opener or _no_tty)

    def test_yes_argv_bypasses_without_a_tty(self) -> None:
        self.assertTrue(self._c(yes=True).confirm_destructive("Destroy?"))

    def test_no_controlling_tty_fails_closed_with_usage_64(self) -> None:
        # The device node is 0666 even under cron/systemd/podman exec; only an
        # OPEN attempt tells the truth (ENXIO). The old -r stat lied.
        with self.assertRaises(UsageError) as cm:
            self._c().confirm_destructive("Destroy?")
        self.assertEqual(int(cm.exception.code), 64)
        self.assertIn("--yes", str(cm.exception))

    def test_whitespace_and_cr_stripped_yes_is_a_yes(self) -> None:
        # 'y \r' from an SSH client must count: silently rejecting a deliberate
        # yes is a rotten failure mode for a destructive prompt.
        self.assertTrue(self._c(opener=_tty("y \r\n")).confirm_destructive("D?"))
        self.assertTrue(self._c(opener=_tty("YES\n")).confirm_destructive("D?"))

    def test_default_is_no(self) -> None:
        self.assertFalse(self._c(opener=_tty("\n")).confirm_destructive("D?"))
        self.assertFalse(self._c(opener=_tty("n\n")).confirm_destructive("D?"))

    def test_assume_yes_env_changes_nothing(self) -> None:
        # The reason the env channel does not exist: .env is shared by both
        # entry points; an env waiver would silently disarm destroy's guard.
        with self.assertRaises(UsageError):
            self._c(env={"VIDE_ASSUME_YES": "1"}).confirm_destructive("D?")

    def test_root_challenge_requires_typed_root(self) -> None:
        with self.assertRaises(UsageError):
            self._c(opener=_tty("yes\n")).confirm_root_instance()
        self._c(opener=_tty("ROOT\n")).confirm_root_instance()  # no raise

    def test_root_challenge_accepts_a_crlf_terminated_root(self) -> None:
        # Pins the reader-AGNOSTIC contract: the real /dev/tty path rarely
        # delivers a CR (line discipline maps CR->NL, text-mode open() adds
        # universal-newlines translation), but the ceremony must not depend on
        # its reader translating — StringIO here IS such a non-translating
        # reader, and a trailing "\r" must not refuse a correctly typed ROOT.
        self._c(opener=_tty("ROOT\r\n")).confirm_root_instance()  # no raise

    def test_root_challenge_stays_strict_beyond_line_endings(self) -> None:
        # Only trailing CR/LF is forgiven — embedded whitespace is still a
        # wrong answer (deliberately stricter than the y/N prompt).
        with self.assertRaises(UsageError):
            self._c(opener=_tty("ROOT \n")).confirm_root_instance()
        with self.assertRaises(UsageError):
            self._c(opener=_tty(" ROOT\n")).confirm_root_instance()

    def test_root_challenge_env_opt_in_is_exact(self) -> None:
        self._c(env={"VIDE_CONFIRM_ROOT": "ROOT"}).confirm_root_instance()
        with self.assertRaises(UsageError):
            self._c(env={"VIDE_CONFIRM_ROOT": "root"}).confirm_root_instance()

    def test_yes_argv_never_waives_the_root_challenge(self) -> None:
        with self.assertRaises(UsageError):
            self._c(yes=True).confirm_root_instance()


if __name__ == "__main__":
    unittest.main()
