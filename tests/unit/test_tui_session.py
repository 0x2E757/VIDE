"""The session's stderr contract: buffered while active, replayed once on any
exit, secrets ONLY after the replay — tested against real fds (a pipe stands
in for the terminal's fd 2), no curses init anywhere (rendering is the manual
smoke's job; see tests/manual/tui-smoke.md)."""
from __future__ import annotations

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from vide.tui.session import Session, StdioCapture  # noqa: E402


@contextlib.contextmanager
def _fd2_pipe():
    """Swap the process's fd 2 for a pipe so a test can ASSERT what the
    capture ultimately replays to 'the terminal'."""
    r, w = os.pipe()
    saved = os.dup(2)
    sys.stderr.flush()
    os.dup2(w, 2)
    try:
        yield r
    finally:
        sys.stderr.flush()
        os.dup2(saved, 2)
        os.close(saved)
        os.close(w)


def _drain(r: int) -> str:
    chunks = []
    while True:
        b = os.read(r, 1 << 16)
        if not b:
            break
        chunks.append(b)
    os.close(r)
    return b"".join(chunks).decode(errors="replace")


class TestStdioCapture(unittest.TestCase):
    def test_capture_replay_order_and_secret_placement(self) -> None:
        with _fd2_pipe() as r:
            fake_out = io.StringIO()
            with contextlib.redirect_stdout(fake_out):
                cap = StdioCapture()
                cap.start()
                os.write(2, b"raw child chatter\n")     # fd-level, like apt
                print("INFO  reporter line", file=sys.stderr, flush=True)
                print("# --- SNIPPET ---")              # sys.stdout object
                cap.defer_note("== summary ==")
                cap.defer_secret("password (SHOWN ONCE): PW+42==")
                cap.pump()
                self.assertNotIn("PW+42==", "".join(cap.lines),
                                 "a secret leaked into the pane lines")
                cap.stop_and_replay()
        got = _drain(r)
        self.assertIn("raw child chatter", got)
        self.assertIn("INFO  reporter line", got)
        replay_end = got.index("end of replay")
        self.assertLess(got.index("raw child chatter"), replay_end)
        self.assertGreater(got.index("== summary =="), replay_end,
                           "notes must print AFTER the replay")
        self.assertGreater(got.index("PW+42=="), got.index("== summary =="),
                           "the secret prints LAST, closest to the prompt")
        self.assertEqual(got.count("PW+42=="), 1, "a secret must print exactly once")
        # machine channel: the snippet went to the REAL stdout, nothing else
        self.assertEqual(fake_out.getvalue(), "# --- SNIPPET ---\n")

    def test_nothing_reaches_the_terminal_while_active(self) -> None:
        with _fd2_pipe() as r:
            cap = StdioCapture()
            cap.start()
            os.write(2, b"buffered\n")
            # peek: the pipe must be EMPTY while the capture is active
            import select
            ready, _, _ = select.select([r], [], [], 0)
            self.assertEqual(ready, [], "a write escaped the capture onto fd 2")
            cap.stop_and_replay()
        self.assertIn("buffered", _drain(r))

    def test_replay_header_counts_lines_never_pumped(self) -> None:
        """The count must be honest even when nothing ever pumped while the
        capture was live — the first real dry-run walk (which never ticks,
        hence never pumps) printed '(0+ lines' over a forty-line replay."""
        with _fd2_pipe() as r:
            cap = StdioCapture()
            cap.start()
            os.write(2, b"a\nb\nhalf")
            cap.stop_and_replay()
        self.assertIn("replayed (3 ", _drain(r),
                      "2 whole lines + 1 trailing partial must count as 3")

    def test_replay_header_counts_a_lone_partial_line(self) -> None:
        """The '+1 if a partial tail exists' term on its own."""
        with _fd2_pipe() as r:
            cap = StdioCapture()
            cap.start()
            os.write(2, b"half")
            cap.stop_and_replay()
        self.assertIn("replayed (1 ", _drain(r))

    def test_straggler_bytes_arriving_during_the_final_fold_are_replayed(self) -> None:
        """A background child still holds the dup2'd descriptor after fd 2 is
        restored; bytes it appends while the funnel folds the tail must reach
        the replay. The loss shape of the pre-fold snapshot: with NOTHING
        captured before the fold, a size taken first reads 0 and the `if
        size:` gate skips the whole replay — the straggler vanishes. (Bytes
        appended to an already-nonempty file were forgiven by accident: the
        replay preads in 64K chunks and overshoots the bound, so the empty
        case is the one honest red.) Simulated by shadowing pump(): the
        append lands between the fold and the replay's size decision, exactly
        where a straggler write would."""
        with _fd2_pipe() as r:
            cap = StdioCapture()
            cap.start()   # deliberately NOTHING captured before the funnel
            real_pump = cap.pump

            def straggler_pump() -> bool:
                grew = real_pump()
                # the capture file's fd shares the dup2'd write offset, so
                # this appends exactly like a child's inherited fd 2 would
                os.write(cap._file.fileno(), b"late straggler\n")
                return grew

            cap.pump = straggler_pump  # type: ignore[method-assign]
            cap.stop_and_replay()
        got = _drain(r)
        self.assertIn("late straggler", got,
                      "bytes appended during the final fold were dropped "
                      "from the replay")

    def test_cr_progress_and_ansi_are_normalized_for_the_pane(self) -> None:
        with _fd2_pipe() as r:
            cap = StdioCapture()
            cap.start()
            os.write(2, b"progress 1\rprogress 2\r\n\x1b[31mred\x1b[0m\nhalf")
            cap.pump()
            self.assertEqual(cap.lines, ["progress 1", "progress 2", "red"])
            os.write(2, b" line\n")
            cap.pump()
            self.assertEqual(cap.lines[-1], "half line")
            cap.stop_and_replay()
        _drain(r)


class _FakeWindow:
    """The minimum surface _draw_chrome touches; draw calls are no-ops on
    purpose, but ONLY the methods it really uses exist — a permissive
    __getattr__ catch-all would go vacuous-green the day the draw path grows
    a new curses call this fake silently swallows."""

    def __init__(self, lines: int = 24, cols: int = 80) -> None:
        self._hw = (lines, cols)

    def getmaxyx(self) -> tuple[int, int]:
        return self._hw

    def erase(self) -> None:
        pass

    def refresh(self) -> None:
        pass

    def addnstr(self, *args: object, **kwargs: object) -> None:
        pass


class _FakeCurses:
    error = type("error", (Exception,), {})
    A_REVERSE = 0
    A_BOLD = 0


class TestChromePump(unittest.TestCase):
    """Pins the WIRING — one _draw_chrome() call folds capture bytes into the
    pane lines — never the pixels: geometry, colors and keys stay the manual
    smoke's job (tests/manual/tui-smoke.md). A dry-run walk never spawns a
    child, hence never ticks; the repaint itself must pump or the pane sits
    frozen at emptiness for the whole walk (the first live walk's defect)."""

    def _draw_once(self, win: _FakeWindow) -> list[str]:
        from unittest import mock
        from vide.tui import session as sess_mod
        with _fd2_pipe() as r:
            s = Session()
            s._cap.start()
            try:
                os.write(2, b"INFO  early narration\n")
                s.scr = win
                with mock.patch.object(sess_mod, "curses", _FakeCurses):
                    s._draw_chrome()
                lines = list(s._cap.lines)
            finally:
                s._cap.stop_and_replay()
        _drain(r)
        return lines

    def test_repaint_pumps_the_capture_into_the_pane(self) -> None:
        self.assertIn("INFO  early narration", self._draw_once(_FakeWindow()))

    def test_pump_happens_even_below_the_size_floor(self) -> None:
        """The too-small freeze must not stall the read offset: the pane (and
        the log view opened right after enlarging) stays current."""
        self.assertIn("INFO  early narration",
                      self._draw_once(_FakeWindow(10, 40)))


class TestFinishNoteSplit(unittest.TestCase):
    def test_deferred_summary_carries_facts_not_the_enter_instruction(self) -> None:
        """'Enter closes the wizard...' is a live-screen affordance; replayed
        into scrollback after exit it describes a control that no longer
        exists. The note gets facts only; the screen keeps the instruction."""
        from unittest import mock
        from vide.prompter import InstallSummary, InstanceAction
        from vide.tui import screens as screens_mod
        from vide.tui.screens import TuiPrompter

        class StubSession:
            dry_run = False

            def __init__(self) -> None:
                self.notes: list[str] = []
                self.secrets: list[str] = []

            def defer_note(self, line: str) -> None:
                self.notes.append(line)

            def defer_secret(self, line: str) -> None:
                self.secrets.append(line)

            def set_status(self, text: str) -> None:
                pass

        shown: list[str] = []

        def fake_menu(session: object, title: str, options: object,
                      default: int = 0) -> int:
            shown.append(title)
            return 0

        stub = StubSession()
        summary = InstallSummary(
            user="alice", port=9797, fqdn="", version="4.99.0",
            config_path="/home/alice/.config/code-server/config.yaml",
            toolchain="HEALTHY", action=InstanceAction.CONVERGE, dry_run=False)
        with mock.patch.object(screens_mod, "menu", fake_menu):
            TuiPrompter(stub).finish(summary)  # type: ignore[arg-type]
        note = "".join(stub.notes)
        self.assertIn("closes the wizard", shown[0],
                      "the screen must keep the affordance")
        self.assertNotIn("closes the wizard", note,
                         "post-exit scrollback must not describe a dead screen")
        for fact in ("alice", "9797", "4.99.0", "config.yaml"):
            self.assertIn(fact, note)


class _TwinStub:
    """StubSession for the command-builder tests (twin state machine)."""
    dry_run = False

    def __init__(self) -> None:
        self.notes: list[str] = []
        self.secrets: list[str] = []

    def defer_note(self, line: str) -> None:
        self.notes.append(line)

    def defer_secret(self, line: str) -> None:
        self.secrets.append(line)

    def set_status(self, text: str) -> None:
        pass


class _ScriptedMenu:
    """Patched screens.menu: a queue of answers; the KI sentinel is the q→y
    quit raised from INSIDE the menu, before any selection returns."""
    RAISE = object()

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.defaults: list[int] = []

    def __call__(self, session, title, options, default=0):  # noqa: ANN001
        self.defaults.append(default)
        step = self.script.pop(0)
        if step is self.RAISE:
            raise KeyboardInterrupt
        return step


class TestExistingInstanceTwin(unittest.TestCase):
    """The trust rule (live smoke §5 finding): a paste-ready resume command
    must never carry more destructive authority than the user CONFIRMED.
    The user declined the destroy modal, quit at the re-shown menu, and the
    note proposed `sudo vide destroy ... --yes` — the exact destruction they
    refused. Twins must be voided on ask ENTRY and rendered fail-closed."""

    PLAIN = "sudo ./install.sh --no-gui"

    def _prompter(self, script: list) -> tuple:
        from unittest import mock
        from vide.tui import screens as screens_mod
        from vide.tui.screens import TuiPrompter
        pr = TuiPrompter(_TwinStub())  # type: ignore[arg-type]
        fake = _ScriptedMenu(script)
        patcher = mock.patch.object(screens_mod, "menu", fake)
        return pr, fake, patcher

    def _facts(self):
        from vide.prompter import InstanceFacts
        return InstanceFacts(user="alice", port=9700, active=True,
                             version="4.1.0")

    def test_quit_after_declined_reinstall_voids_the_destroy_twin(self) -> None:
        pr, fake, patcher = self._prompter([3, _ScriptedMenu.RAISE])
        with patcher:
            pr.existing_instance_action(self._facts())
            # positive half: the confirmed selection composes the twin
            # (fail-closed default: NO --yes — the pasted command re-asks
            # its own DESTROY_PROMPT)
            self.assertEqual(pr.equivalent_command(),
                             f"sudo vide destroy alice && {self.PLAIN}")
            # the sequencer re-asks after the declined destroy; q→y raises
            with self.assertRaises(KeyboardInterrupt):
                pr.existing_instance_action(self._facts())
        self.assertEqual(pr.equivalent_command(), self.PLAIN,
                         "a quit mid-ask must expose only CONFIRMED answers")
        # the preserved highlight (UI memory) must survive the void:
        # the re-entry menu was offered the last confirmed selection
        self.assertEqual(fake.defaults[-1], 3)

    def test_quit_after_a_verb_selection_voids_the_verb_twin(self) -> None:
        pr, _, patcher = self._prompter([1, _ScriptedMenu.RAISE])
        with patcher:
            pr.existing_instance_action(self._facts())
            self.assertEqual(pr.equivalent_command(), "sudo vide upgrade alice")
            with self.assertRaises(KeyboardInterrupt):
                pr.existing_instance_action(self._facts())
        self.assertEqual(pr.equivalent_command(), self.PLAIN)

    def test_reentry_with_a_new_confirmed_answer_composes_the_new_twin(self) -> None:
        """The changed-mind path: keeps EITHER fix shape honest (entry-only
        or entry+post reset); dropping both goes red."""
        pr, _, patcher = self._prompter([3, 0])
        with patcher:
            pr.existing_instance_action(self._facts())
            pr.existing_instance_action(self._facts())
        self.assertEqual(pr.equivalent_command(), self.PLAIN)

    def test_waiver_split_reinstall(self) -> None:
        """Only finish() may waive: the scripted form with --yes exists, but
        abort/error notes get the re-asking form by default."""
        pr, _, patcher = self._prompter([3])
        with patcher:
            pr.existing_instance_action(self._facts())
        self.assertNotIn("--yes", pr.equivalent_command())
        self.assertIn("--yes", pr.equivalent_command(waive_confirms=True))

    def test_acknowledge_exposure_clears_every_twin_store(self) -> None:
        """The run-start reset is load-bearing beyond entry-resets: after
        destroy RAN and the install half failed, a retry never re-enters
        existing_instance_action (the instance is gone) — only this reset
        stops the old destroy twin from leaking into a later abort note."""
        pr, _, patcher = self._prompter([3, 0])
        with patcher:
            pr.existing_instance_action(self._facts())
            pr.acknowledge_exposure()
        self.assertEqual(pr.equivalent_command(waive_confirms=True), self.PLAIN)

    def test_finish_defers_the_fully_waived_command(self) -> None:
        """The success summary is the reproduce-this-run artifact: by then
        every gate was really passed, so THAT command may carry --yes."""
        from vide.prompter import InstallSummary, InstanceAction
        pr, _, patcher = self._prompter([3, 0])
        with patcher:
            pr.existing_instance_action(self._facts())
            pr.finish(InstallSummary(
                user="alice", port=9700, fqdn="", version="4.1.0",
                config_path="/home/alice/.config/code-server/config.yaml",
                toolchain="HEALTHY", action=InstanceAction.REINSTALL,
                dry_run=False))
        self.assertIn("--yes", "".join(pr.s.notes))


class TestRootTwin(unittest.TestCase):
    """The ux-lens twin of the §5 finding, one screen earlier: a declined
    typed-ROOT challenge re-enters choose_target_user; a quit there must not
    leak VIDE_CONFIRM_ROOT (a full non-interactive waiver even --yes cannot
    grant) into the resume note."""

    def _facts(self):
        from vide.prompter import UserFacts
        return UserFacts(default="alice", sudo_user="", current_user="root",
                         allow_root=False, instances=lambda: (),
                         user_exists=lambda u: True)

    def test_quit_after_declined_root_challenge_voids_the_root_twins(self) -> None:
        from unittest import mock
        from vide.tui import screens as screens_mod
        from vide.tui.screens import TuiPrompter
        pr = TuiPrompter(_TwinStub())  # type: ignore[arg-type]
        # labels: [alice, vide, (other), root] → 3 selects root;
        # consequence screen → 1 = Continue; then the re-entry menu raises
        fake = _ScriptedMenu([3, 1, _ScriptedMenu.RAISE])
        with mock.patch.object(screens_mod, "menu", fake):
            self.assertEqual(pr.choose_target_user(self._facts()), "root")
            cmd = pr.equivalent_command(waive_confirms=True)
            self.assertIn("VIDE_CONFIRM_ROOT=ROOT", cmd)
            self.assertIn("--user root", cmd)
            with self.assertRaises(KeyboardInterrupt):
                pr.choose_target_user(self._facts())
        cmd = pr.equivalent_command()
        for leak in ("VIDE_CONFIRM_ROOT", "VIDE_ALLOW_ROOT", "--user root"):
            self.assertNotIn(leak, cmd,
                             "an unratified root answer leaked into the note")

    def test_confirmed_root_twin_is_fail_closed_by_default(self) -> None:
        """Even a CONFIRMED root selection renders without the typed-ROOT
        waiver in abort/error notes — the pasted command re-asks the
        challenge; only finish() gets the fully-scripted form."""
        from unittest import mock
        from vide.tui import screens as screens_mod
        from vide.tui.screens import TuiPrompter
        pr = TuiPrompter(_TwinStub())  # type: ignore[arg-type]
        with mock.patch.object(screens_mod, "menu", _ScriptedMenu([3, 1])):
            pr.choose_target_user(self._facts())
        self.assertNotIn("VIDE_CONFIRM_ROOT", pr.equivalent_command())
        self.assertIn("VIDE_ALLOW_ROOT=1", pr.equivalent_command(),
                      "the mode flag is not a confirmation waiver — it stays")
        self.assertIn("VIDE_CONFIRM_ROOT=ROOT",
                      pr.equivalent_command(waive_confirms=True))


class TestTwinQuoting(unittest.TestCase):
    """The twin is a PASTE-READY command: a recorded value carrying a space or
    a shell metacharacter must arrive at the pasted process as ONE argument,
    not be re-parsed (or worse, executed) by the operator's shell. The stores
    are poked directly: every public ask-path writes through them, and the
    benign-value rendering is already pinned exactly by the twin tests above."""

    def _pr(self):
        from vide.tui.screens import TuiPrompter
        return TuiPrompter(_TwinStub())  # type: ignore[arg-type]

    def test_metacharacter_values_render_as_single_arguments(self) -> None:
        pr = self._pr()
        pr._flags["--fqdn"] = "ide.example.com; rm -rf /"
        pr._env["VIDE_USER"] = "alice smith"
        cmd = pr.equivalent_command()
        self.assertIn("--fqdn 'ide.example.com; rm -rf /'", cmd)
        self.assertIn("VIDE_USER='alice smith'", cmd)

    def test_flag_only_entries_stay_bare(self) -> None:
        pr = self._pr()
        pr._flags["--password-stdin"] = ""
        cmd = pr.equivalent_command()
        self.assertIn("--password-stdin", cmd)
        self.assertNotIn("--password-stdin ''", cmd,
                         "an empty flag value must not grow a spurious ''")

    def test_benign_values_render_unquoted(self) -> None:
        pr = self._pr()
        pr._flags["--user"] = "alice"
        pr._env["VIDE_ALLOW_ROOT"] = "1"
        cmd = pr.equivalent_command()
        self.assertIn("--user alice", cmd)
        self.assertNotIn("'", cmd, "quoting a benign value is visual noise")


class TestSessionTeardown(unittest.TestCase):
    def test_endwin_runs_before_the_replay_on_any_exit(self) -> None:
        """The pinned order: terminal restored FIRST, then the funnel. Driven
        without initscr: scr is a sentinel, curses.endwin is a recorder."""
        from unittest import mock
        from vide.tui import session as sess_mod
        calls: list[str] = []

        class FakeCurses:
            error = type("error", (Exception,), {})

            @staticmethod
            def endwin() -> None:
                calls.append("endwin")

        with _fd2_pipe() as r:
            s = Session()
            s._cap.start()
            os.write(2, b"line\n")
            s.scr = object()  # sentinel: "a screen exists"
            with mock.patch.object(sess_mod, "curses", FakeCurses):
                s._teardown()
            calls.append("replay-done")
        got = _drain(r)
        self.assertEqual(calls, ["endwin", "replay-done"])
        self.assertIn("line", got)
        self.assertIsNone(s.scr)

    def test_deliver_secret_goes_to_the_deferred_list_never_the_pane(self) -> None:
        """TuiPrompter.deliver_secret is the wizard's only secret channel."""
        from vide.tui.screens import TuiPrompter

        class StubSession:
            dry_run = False

            def __init__(self) -> None:
                self.secrets: list[str] = []
                self.notes: list[str] = []

            def defer_secret(self, line: str) -> None:
                self.secrets.append(line)

            def defer_note(self, line: str) -> None:
                self.notes.append(line)

        stub = StubSession()
        TuiPrompter(stub).deliver_secret("password (SHOWN ONCE): X")  # type: ignore[arg-type]
        self.assertEqual(stub.secrets, ["password (SHOWN ONCE): X"])
        self.assertEqual(stub.notes, [], "a secret must never ride the notes "
                         "channel (notes precede secrets in the funnel)")


if __name__ == "__main__":
    unittest.main()
