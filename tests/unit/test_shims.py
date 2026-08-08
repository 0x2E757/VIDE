"""The bash shims' pre-Python contract, driven at the process level (real
bash, like everything else in this Linux-only tier). The shims run BEFORE the
Python package exists, so their guards cannot live in Python — these tests
build a restricted PATH where python3/apt-get deliberately do not exist and
assert the shims' own decisions.

Covers the two audit mediums: the `vide` shim's missing >=3.10 gate, and
install.sh's dry-run gate ignoring a `.env` row (Python resolves VIDE_DRY_RUN
as argv > env > `.env`; a shim reading only the process env would apt-get
install python3 — a real mutation — while the Python half of the same run
previews)."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# The gate must be byte-identical in both shims: one story, one exit code (78,
# EX_CONFIG), whichever door the operator came through.
PY_GATE = (
    "python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \\\n"
    "  || { printf 'ERROR VIDE needs Python >= 3.10 (found: %s)\\n' \"$(python3 -V 2>&1)\" >&2; exit 78; }"
)


def _bash() -> str:
    bash = shutil.which("bash")
    assert bash, "bash missing from the test image"
    return bash


def _fake_bin(td: Path, tools: tuple[str, ...]) -> Path:
    """A PATH directory holding ONLY the named real tools (symlinks); notably
    python3 and apt-get do not exist there."""
    fake = td / "fakebin"
    fake.mkdir()
    for t in tools:
        real = shutil.which(t)
        assert real, f"{t} missing from the test image"
        (fake / t).symlink_to(real)
    return fake


class TestPyGateParity(unittest.TestCase):
    def test_both_shims_carry_the_identical_version_gate(self) -> None:
        for shim in ("vide", "install.sh"):
            self.assertIn(PY_GATE, (REPO / shim).read_text(),
                          f"{shim} lost (or reworded) the python>=3.10 gate")


class TestCheckoutGateParity(unittest.TestCase):
    """The checkout gate must exist, and be the SAME gate, in both shims.

    install.sh argues that the authoritative Python check cannot be the only one,
    because python3 runs from `$here/src` and a gate living there would be reading
    its own attacker's code. That argument applies word for word to `vide` — the
    door every root management verb comes through — and for a long time `vide` had
    no half at all, which made "VIDE refuses an untrusted checkout" true of one
    entry point and false of the other.

    Duplicated rather than sourced, for the reason above: a shared helper file
    would live in the tree being judged. Duplication is only safe if it cannot
    drift, which is what this row is."""

    MARK_OPEN = "# >>> VIDE-CHECKOUT-GATE"
    MARK_CLOSE = "# <<< VIDE-CHECKOUT-GATE"

    def _block(self, shim: str) -> str:
        body = (REPO / shim).read_text()
        self.assertIn(self.MARK_OPEN, body, f"{shim} has no checkout gate at all")
        start = body.index(self.MARK_OPEN)
        end = body.index(self.MARK_CLOSE, start) + len(self.MARK_CLOSE)
        return body[start:end]

    def test_both_shims_carry_the_byte_identical_checkout_gate(self) -> None:
        self.assertEqual(self._block("vide"), self._block("install.sh"))

    def test_the_block_is_not_an_empty_marker_pair(self) -> None:
        # Two empty blocks are byte-identical too. Name the load-bearing parts,
        # so deleting the gate and keeping the markers cannot pass.
        block = self._block("vide")
        for needle in ("EUID", "_untrusted", "exit 78", "gate_paths",
                       'find -P "$here/src" "$here/units"'):
            self.assertIn(needle, block, f"the checkout gate lost {needle}")

    def test_both_shims_refuse_to_write_bytecode(self) -> None:
        # -B, because a poisoned __pycache__ is loaded in preference to the .py
        # that was reviewed, and PEP 552's default invalidation validates against
        # the source's mtime and size — both forgeable by whoever could write the
        # tree. It shrinks the window; only removing the directory closes it,
        # which is why the refusal's remedy names it.
        for shim in ("vide", "install.sh"):
            self.assertIn("exec python3 -B ", (REPO / shim).read_text(),
                          f"{shim} exec's python3 without -B")


class TestVideShimPyGate(unittest.TestCase):
    def test_ancient_python3_refuses_with_config_78_and_the_real_story(self) -> None:
        """An old system python3 must be refused BY THE SHIM with the version
        in the message — not lines later as a SyntaxError inside the package."""
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            shim = td / "vide"
            shim.write_text((REPO / "vide").read_text())
            shim.chmod(0o755)
            fake = _fake_bin(td, ("readlink", "dirname"))
            old_py = fake / "python3"
            # -V answers with an ancient version; any -c program "fails to run"
            old_py.write_text('#!/bin/sh\n'
                              'if [ "$1" = "-V" ]; then echo "Python 3.6.9"; exit 0; fi\n'
                              'exit 1\n')
            old_py.chmod(0o755)
            p = subprocess.run([_bash(), str(shim), "ls"], env={"PATH": str(fake)},
                               capture_output=True, text=True)
        self.assertEqual(p.returncode, 78, p.stderr)
        self.assertIn("needs Python >= 3.10", p.stderr)
        self.assertIn("3.6.9", p.stderr, "the message must name what was found")

    def test_missing_python3_still_names_the_installer(self) -> None:
        """The pre-existing guard stays ahead of the new gate: no python3 at
        all is 'run install.sh', exit 69 — not a version complaint."""
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            shim = td / "vide"
            shim.write_text((REPO / "vide").read_text())
            shim.chmod(0o755)
            fake = _fake_bin(td, ("readlink", "dirname"))
            p = subprocess.run([_bash(), str(shim), "ls"], env={"PATH": str(fake)},
                               capture_output=True, text=True)
        self.assertEqual(p.returncode, 69, p.stderr)
        self.assertIn("install.sh", p.stderr)


class TestInstallShimDryRunSources(unittest.TestCase):
    """The shim's dry decision on a python3-less box, per source. Dry runs
    stop cleanly at 'cannot preview the Python steps' (rc 0); non-dry runs on
    this stripped box die at the root gate (77, non-root) or the no-apt-get
    gate (78, root) — either way, NOT the dry-run narration."""

    def _run(self, *, argv: tuple = (), env_extra: dict | None = None,
             dotenv: str | None = None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            script = td / "install.sh"
            script.write_text((REPO / "install.sh").read_text())
            script.chmod(0o755)
            if dotenv is not None:
                (td / ".env").write_text(dotenv)
            fake = _fake_bin(td, ("readlink", "dirname", "grep", "tail"))
            env = {"PATH": str(fake)}
            env.update(env_extra or {})
            return subprocess.run([_bash(), str(script), *argv], env=env,
                                  capture_output=True, text=True)

    def _assert_dry(self, p: subprocess.CompletedProcess) -> None:
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("DRY-RUN MODE ACTIVE", p.stderr)
        self.assertIn("cannot preview the Python steps", p.stderr)

    def _assert_not_dry(self, p: subprocess.CompletedProcess) -> None:
        self.assertIn(p.returncode, (77, 78), p.stderr)
        self.assertNotIn("DRY-RUN", p.stderr)

    def test_dotenv_row_makes_the_bootstrap_preview_only(self) -> None:
        self._assert_dry(self._run(dotenv="VIDE_DRY_RUN=1\n"))

    def test_process_env_beats_the_dotenv_row(self) -> None:
        # Python's precedence: a NON-EMPTY env value stops the fallthrough.
        self._assert_not_dry(self._run(dotenv="VIDE_DRY_RUN=1\n",
                                       env_extra={"VIDE_DRY_RUN": "0"}))

    def test_empty_env_falls_through_to_the_dotenv_row(self) -> None:
        self._assert_dry(self._run(dotenv="VIDE_DRY_RUN=1\n",
                                   env_extra={"VIDE_DRY_RUN": ""}))

    def test_export_prefix_spaces_and_quotes_are_tolerated(self) -> None:
        # the same row shapes parse_env_text accepts for this key
        self._assert_dry(self._run(dotenv='export VIDE_DRY_RUN = "1"\n'))

    def test_last_row_wins_like_the_python_parser(self) -> None:
        self._assert_not_dry(self._run(dotenv="VIDE_DRY_RUN=1\nVIDE_DRY_RUN=0\n"))

    def test_export_tab_row_is_ignored_like_the_python_parser(self) -> None:
        """parse_env_text strips the literal prefix 'export ' (space, never a
        tab) — an export<TAB> row lands under a junk key and Python does not
        see it. A shim that DID match it would take its value as the last row
        and diverge: here Python previews (row 1) while a divergent shim would
        read row 2's 0 and apt-get for real — the exact bug class this gate
        exists to close."""
        self._assert_dry(self._run(dotenv="VIDE_DRY_RUN=1\nexport\tVIDE_DRY_RUN=0\n"))

    def test_only_the_exact_value_1_enables(self) -> None:
        self._assert_not_dry(self._run(dotenv="VIDE_DRY_RUN=yes\n"))

    def test_plain_process_env_still_works(self) -> None:
        self._assert_dry(self._run(env_extra={"VIDE_DRY_RUN": "1"}))

    def test_argv_flag_still_works_without_any_env(self) -> None:
        self._assert_dry(self._run(argv=("--dry-run",)))


if __name__ == "__main__":
    unittest.main()
