"""The tty gate: who gets the wizard, who falls to plain, who is told to use
--no-gui. All hermetic — isatty and the probe are faked; no pty, no curses
init (the frozen arbiter's no-tty run is the system-level negative proof)."""
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

import vide.tui as tui_pkg  # noqa: E402  (curses-free by I7)
from vide import cli  # noqa: E402
from vide.errors import Ex, UsageError  # noqa: E402
from vide.prompter import PlainPrompter  # noqa: E402
from vide.tui import TuiUnavailable, wizard_eligible  # noqa: E402


class TestGateMatrix(unittest.TestCase):
    def test_all_eight_combinations(self) -> None:
        for stdin_tty in (False, True):
            for stdout_tty in (False, True):
                for no_gui in (False, True):
                    want = stdin_tty and stdout_tty and not no_gui
                    self.assertEqual(
                        wizard_eligible(stdin_tty, stdout_tty, no_gui), want,
                        f"gate({stdin_tty}, {stdout_tty}, no_gui={no_gui})")


@contextlib.contextmanager
def _entry(argv, *, tty: bool, stdin_text: str | None = None):
    """Drive cli._install_entry with the heavy ends faked; yields a dict that
    fills with what reached run_install, plus the stderr text."""
    seen: dict = {}

    def fake_run_install(cfg, ex, rep, conf, prompter=None):
        seen["prompter"] = prompter
        seen["cfg"] = cfg
        return 0

    errs = io.StringIO()
    with tempfile.TemporaryDirectory() as td:
        patches = [
            mock.patch.object(cli, "run_install", side_effect=fake_run_install),
            mock.patch.object(cli, "_run_wizard", return_value=42),
            mock.patch.object(cli.os, "isatty", return_value=tty),
            # the euid pre-gate must not steer these tests by which uid runs them
            mock.patch.object(cli.os, "geteuid", return_value=0),
            contextlib.redirect_stderr(errs),
        ]
        if stdin_text is not None:
            patches.append(mock.patch.object(cli.sys, "stdin", io.StringIO(stdin_text)))
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            seen["rc"] = cli._install_entry(argv, Path(td))
        seen["stderr"] = errs.getvalue()
        yield seen


class TestGateBehavior(unittest.TestCase):
    def test_tty_and_probe_ok_opens_the_wizard(self) -> None:
        with mock.patch.object(tui_pkg, "probe", return_value=None):
            with _entry([], tty=True) as seen:
                self.assertEqual(seen["rc"], 42, "the wizard entry was not taken")

    def test_dry_run_on_a_tty_still_opens_the_wizard(self) -> None:
        """Decided policy, pinned: a preview is wizard-able (its product is
        the equivalent command). A 'safety' regression forcing dry-run plain
        would otherwise pass the whole tier."""
        with mock.patch.object(tui_pkg, "probe", return_value=None):
            with _entry(["--dry-run"], tty=True) as seen:
                self.assertEqual(seen["rc"], 42)

    def test_non_root_dry_run_still_opens_the_wizard(self) -> None:
        """The other half of the euid pre-gate: a preview needs no root
        (require_root only warns under dry-run), so non-root + --dry-run on a
        tty is wizard-able — the rehearsal must not demand sudo."""
        with mock.patch.object(tui_pkg, "probe", return_value=None), \
             mock.patch.object(cli.os, "geteuid", return_value=1000), \
             mock.patch.object(cli.os, "isatty", return_value=True), \
             mock.patch.object(cli, "_run_wizard", return_value=42), \
             contextlib.redirect_stderr(io.StringIO()):
            with tempfile.TemporaryDirectory() as td:
                rc = cli._install_entry(["--dry-run"], Path(td))
        self.assertEqual(rc, 42)

    def test_non_root_tty_skips_the_wizard_for_the_plain_sudo_hint(self) -> None:
        """Forgotten sudo is the most common first touch: it must get the
        one-line NoPermError remediation, never a curses session whose only
        exit is an unwinnable retry loop. (Dry-run stays wizard-able.)"""
        with mock.patch.object(tui_pkg, "probe", return_value=None), \
             mock.patch.object(cli.os, "geteuid", return_value=1000), \
             mock.patch.object(cli.os, "isatty", return_value=True), \
             mock.patch.object(cli, "_run_wizard", return_value=42), \
             mock.patch.object(cli, "run_install", return_value=0) as ri, \
             contextlib.redirect_stderr(io.StringIO()):
            with tempfile.TemporaryDirectory() as td:
                rc = cli._install_entry([], Path(td))
        self.assertEqual(rc, 0)
        ri.assert_called_once()  # the plain path (which raises the sudo hint)

    def test_no_gui_forces_plain_even_on_a_tty(self) -> None:
        with mock.patch.object(tui_pkg, "probe", return_value=None):
            with _entry(["--no-gui"], tty=True) as seen:
                self.assertEqual(seen["rc"], 0)
                self.assertIsInstance(seen.get("prompter"), PlainPrompter,
                                      "plain means PlainPrompter, not any prompter")

    def test_redirected_stdio_falls_to_plain_with_one_info_line(self) -> None:
        with _entry([], tty=False) as seen:
            self.assertEqual(seen["rc"], 0)
            self.assertIsInstance(seen.get("prompter"), PlainPrompter)
            self.assertIn("no interactive terminal", seen["stderr"])
            # arbiter-shape safety: the fallback line must never carry the
            # password sed/grep anchors.
            self.assertNotIn("SHOWN ONCE", seen["stderr"])
            self.assertNotIn("): ", seen["stderr"])

    def test_unusable_terminal_stops_with_the_paste_ready_twin(self) -> None:
        with mock.patch.object(tui_pkg, "probe",
                               side_effect=TuiUnavailable("terminal type 'dumb' "
                                                          "lacks cursor addressing")):
            with _entry(["--user", "alice"], tty=True) as seen:
                self.assertEqual(seen["rc"], int(Ex.UNAVAILABLE))
                self.assertIn("--no-gui --user alice", seen["stderr"],
                              "the refusal must hand over a paste-ready command")
                self.assertNotIn("prompter", seen, "must not fall through to plain")

    def test_missing_curses_degrades_to_plain(self) -> None:
        # Behavioral proof of the lazy-import confinement: with the curses
        # module masked, the REAL probe raises degrade=True and the plain
        # path still runs. No reloads — probe imports curses lazily.
        with mock.patch.dict(sys.modules, {"curses": None}):
            with _entry([], tty=True) as seen:
                self.assertEqual(seen["rc"], 0)
                self.assertIn("wizard unavailable", seen["stderr"])
                self.assertIsNotNone(seen.get("prompter"))


class TestPasswordStdin(unittest.TestCase):
    def test_reads_one_line_and_forces_plain(self) -> None:
        with mock.patch.object(tui_pkg, "probe", return_value=None):
            with _entry(["--password-stdin"], tty=True,
                        stdin_text="operator-password-16+\n") as seen:
                self.assertEqual(seen["rc"], 0, "must never open the wizard")
                self.assertEqual(seen["prompter"]._password, "operator-password-16+")

    def test_short_password_dies_usage_64_before_any_work(self) -> None:
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(cli.sys, "stdin", io.StringIO("short\n")), \
             mock.patch.object(cli, "run_install") as ri, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(UsageError):
                cli._install_entry(["--password-stdin"], Path(td))
            ri.assert_not_called()

    def test_weak_password_warns_but_proceeds(self) -> None:
        with _entry(["--password-stdin"], tty=False,
                    stdin_text="only12chars.\n") as seen:
            self.assertEqual(seen["rc"], 0)
            self.assertIn("short", seen["stderr"])


if __name__ == "__main__":
    unittest.main()
