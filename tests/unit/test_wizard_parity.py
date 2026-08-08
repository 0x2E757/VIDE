"""The non-drift pin: the wizard and the plain flow are THE SAME sequencer,
so a scripted wizard answer must produce the byte-identical run as its
argv/env twin. Partially definitional under the single-sequencer structure —
kept anyway as the semantic backstop, exactly the relationship I2 has to I1:
'interleaved ask-points' is precisely the refactor that could silently reorder
or skip a step.

Method: full dry-run converges in the I2 sandbox; the narrated stderr IS the
trace (previews derive from the real argv), stdout carries the snippet."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import ScriptedPrompter, make_config  # noqa: E402
from vide.confirm import Confirmer  # noqa: E402
from vide.executor import Executor  # noqa: E402
from vide.install_flow import run_install  # noqa: E402
from vide.reporter import Reporter  # noqa: E402


def _dry_run(tmp: Path, prompter=None, **cfg_over) -> tuple[str, str]:
    """One full dry-run converge in a sandbox; returns (stderr, stdout) with
    the sandbox path normalized out (by the ACTUAL tempdir string — a /tmp
    regex would break under any non-/tmp TMPDIR)."""
    (tmp / "sandbox").mkdir(exist_ok=True)
    osr = tmp / "os-release"
    osr.write_text('ID=debian\nPRETTY_NAME="Debian test"\n')
    cfg = make_config(tmp / "sandbox", dry_run=True, os_release_file=osr,
                      uname_m="x86_64",
                      vide_user=cfg_over.pop("vide_user", "vide-parity-user"),
                      **cfg_over)
    errs, out = io.StringIO(), io.StringIO()
    rep = Reporter(stream=errs)
    ex = Executor(dry_run=True, reporter=rep, cfg=cfg)
    conf = Confirmer(yes_argv=False, environ={}, reporter=rep)
    with contextlib.redirect_stdout(out):
        rc = run_install(cfg, ex, rep, conf, prompter=prompter)
    assert rc == 0
    if prompter is not None:
        assert prompter.consumed(), f"unconsumed script: {prompter.answers}"
    root = str(tmp)
    return (errs.getvalue().replace(root, "<TMP>"),
            out.getvalue().replace(root, "<TMP>"))


class TestWizardPlainParity(unittest.TestCase):
    def test_default_answers_are_byte_identical_to_plain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plain = _dry_run(Path(td))
        with tempfile.TemporaryDirectory() as td:
            pr = ScriptedPrompter()  # every ask falls to its default
            wizard = _dry_run(Path(td), prompter=pr)
        # Same sandbox shape → the only legitimate diff is the tmpdir path.
        self.assertEqual(plain[0], wizard[0],
                         "default wizard answers diverged from the plain flow")
        self.assertEqual(plain[1], wizard[1])

    def test_user_answer_equals_its_env_twin(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plain = _dry_run(Path(td), vide_user="alice")
        with tempfile.TemporaryDirectory() as td:
            wizard = _dry_run(Path(td), vide_user="",
                              prompter=ScriptedPrompter(target_user="alice"))
        self.assertEqual(plain[0], wizard[0],
                         "wizard 'alice' must equal VIDE_USER=alice")

    def test_fqdn_answer_equals_its_flag_twin(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plain = _dry_run(Path(td), fqdn="ide.example.test")
        with tempfile.TemporaryDirectory() as td:
            wizard = _dry_run(Path(td),
                              prompter=ScriptedPrompter(fqdn="ide.example.test"))
        self.assertEqual(plain[1], wizard[1],
                         "wizard fqdn must fill the snippet exactly like --fqdn")

    def test_wizard_dry_run_mutates_nothing(self) -> None:
        """The I2 sibling for the wizard-driven path (I2 itself stays the
        untouched plain-path pin)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "sandbox").mkdir()

            def snapshot() -> list[tuple[str, int]]:
                return [(str(p), p.stat().st_mode)
                        for p in sorted((tmp / "sandbox").rglob("*"))]

            before = snapshot()
            _, stdout = _dry_run(tmp, prompter=ScriptedPrompter(
                target_user="vide-parity-user", fqdn="x.test"))
            self.assertEqual(before, snapshot(),
                             "a wizard dry-run converge wrote into the sandbox")
            self.assertIn("reverse_proxy 127.0.0.1:", stdout)
            self.assertTrue(stdout.strip().startswith("# --- VIDE per-instance"),
                            "stdout purity broke under a scripted prompter")


if __name__ == "__main__":
    unittest.main()
