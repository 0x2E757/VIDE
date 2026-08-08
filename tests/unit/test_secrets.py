"""Secret generation shapes and the never-regenerate guard."""
from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import RecordingExecutor, make_config, quiet_reporter  # noqa: E402
from vide import secrets as vs  # noqa: E402
from vide.errors import StateError  # noqa: E402


class TestGenerators(unittest.TestCase):
    def test_password_decodes_to_16_bytes(self) -> None:
        self.assertEqual(len(base64.b64decode(vs.gen_password())), 16)

    def test_two_passwords_differ(self) -> None:
        self.assertNotEqual(vs.gen_password(), vs.gen_password())

    def test_cookie_suffix_carries_user_and_random(self) -> None:
        a, b = vs.gen_cookie_suffix("bob"), vs.gen_cookie_suffix("bob")
        self.assertTrue(a.startswith("vide-bob-"))
        self.assertNotEqual(a, b)

    def test_hash_pipes_plaintext_via_stdin_never_argv(self) -> None:
        captured = {}

        def fake_query(argv, *, input_text=None, timeout=None):
            captured["argv"] = list(argv)
            captured["stdin"] = input_text
            return subprocess.CompletedProcess(argv, 0, stdout="$argon2id$X\n", stderr="")

        with mock.patch.object(vs.system, "query", side_effect=fake_query):
            got = vs.hash_password("s3cret")
        self.assertEqual(got, "$argon2id$X")
        self.assertEqual(captured["stdin"], "s3cret")
        self.assertNotIn("s3cret", " ".join(captured["argv"]),
                         "/proc/<pid>/cmdline is world-readable")
        self.assertEqual(captured["argv"][0], "argon2")
        self.assertIn("-id", captured["argv"])
        self.assertIn("-e", captured["argv"])


class TestEnsureConfig(unittest.TestCase):
    def test_never_regenerates_an_existing_credential(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = RecordingExecutor()
            with mock.patch.object(vs.system, "user_home",
                                   return_value=Path(td) / "home"), \
                 mock.patch.object(vs.system, "probe_as", return_value=True):
                vs.ensure_config(cfg, ex, quiet_reporter(), "alice", 9797)
            self.assertEqual(ex.actions, [],
                             "a converge must NEVER silently rotate a saved credential")

    def test_rotate_without_port_record_is_state_75(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = RecordingExecutor()
            with mock.patch.object(vs.system, "user_home",
                                   return_value=Path(td) / "home"):
                with self.assertRaises(StateError):
                    vs.rotate_config(cfg, ex, quiet_reporter(), "ghost")

    def test_generated_password_is_returned_and_never_reported(self) -> None:
        """The domain layer RETURNS the plaintext; announcing it is the
        caller's job (in wizard mode the Reporter stream is an on-screen log
        pane — a secret through it would be displayed mid-run and replayed).
        The arbiter-shape SHOWN-ONCE line is pinned at the sequencer level in
        test_flow_prompter.TestSecretDelivery."""
        import io
        from vide.reporter import Reporter
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = RecordingExecutor()
            errs = io.StringIO()
            rep = Reporter(stream=errs)
            with mock.patch.object(vs, "gen_password", return_value="PW+42=="), \
                 mock.patch.object(vs, "hash_password", return_value="$argon2id$H"), \
                 mock.patch.object(vs.system, "user_home",
                                   return_value=Path(td) / "home"), \
                 mock.patch.object(vs.system, "probe_as", return_value=False):
                got = vs.ensure_config(cfg, ex, rep, "alice", 9797)
            self.assertEqual(got, "PW+42==")
            self.assertNotIn("PW+42==", errs.getvalue(),
                             "the plaintext must never transit the Reporter")

    def test_supplied_password_is_hashed_but_not_echoed_back(self) -> None:
        """An operator-typed password returns None — they already know it, and
        no SHOWN-ONCE line should reprint it into scrollback."""
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = RecordingExecutor()
            hashed = {}
            with mock.patch.object(vs, "hash_password",
                                   side_effect=lambda p: hashed.setdefault("pw", p) and "$h" or "$h"), \
                 mock.patch.object(vs.system, "user_home",
                                   return_value=Path(td) / "home"), \
                 mock.patch.object(vs.system, "probe_as", return_value=False):
                got = vs.ensure_config(cfg, ex, quiet_reporter(), "alice", 9797,
                                       password="operator-chose-this")
            self.assertIsNone(got)
            self.assertEqual(hashed["pw"], "operator-chose-this")


if __name__ == "__main__":
    unittest.main()
