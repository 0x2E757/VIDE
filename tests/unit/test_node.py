"""node.py's pure half: resolvers, emitters, health — where all three
historical shipped bugs lived. The launcher test EXECUTES the wrapper through
a symlink, because the $0-anchoring is the bug, not the file contents."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import make_config  # noqa: E402
from vide import node  # noqa: E402


class TestNodeMajor(unittest.TestCase):
    def test_parses(self) -> None:
        self.assertEqual(node.node_major("v26.5.0"), 26)
        self.assertEqual(node.node_major("26.5.0"), 26)
        self.assertEqual(node.node_major("v9"), 9)

    def test_junk_is_none(self) -> None:
        self.assertIsNone(node.node_major("garbage"))
        self.assertIsNone(node.node_major(""))


class TestNvmResolver(unittest.TestCase):
    def _tree(self, tmp: Path, versions: list[str], executable: bool = True) -> Path:
        nvm = tmp / "nvm"
        for v in versions:
            b = nvm / f"versions/node/{v}/bin"
            b.mkdir(parents=True)
            n = b / "node"
            n.write_text("#!/bin/sh\n")
            if executable:
                n.chmod(0o755)
        return nvm

    def test_highest_wins_with_tuple_compare_not_string(self) -> None:
        # sort -V parity: v26.10.0 > v26.9.0 (a naive string compare regresses).
        with tempfile.TemporaryDirectory() as td:
            nvm = self._tree(Path(td), ["v26.9.0", "v26.10.0"])
            got = node.nvm_resolve_bindir(nvm, 26)
            self.assertIsNotNone(got)
            self.assertIn("v26.10.0", str(got))

    def test_below_floor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            nvm = self._tree(Path(td), ["v24.9.0"])
            self.assertIsNone(node.nvm_resolve_bindir(nvm, 26))

    def test_non_executable_node_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            nvm = self._tree(Path(td), ["v26.5.0"], executable=False)
            self.assertIsNone(node.nvm_resolve_bindir(nvm, 26))

    def test_empty_tree_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(node.nvm_resolve_bindir(Path(td), 26))


class TestPnpmResolver(unittest.TestCase):
    def _put(self, home: Path, rel: str, executable: bool = True) -> Path:
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("#!/bin/sh\n")
        if executable:
            p.chmod(0o755)
        return p

    def test_v11_bin_layout_wins_over_legacy_flat(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            self._put(home, "pnpm")
            canonical = self._put(home, "bin/pnpm")
            self.assertEqual(node.pnpm_resolve_bin(home), canonical)

    def test_legacy_flat_found(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            flat = self._put(home, "pnpm")
            self.assertEqual(node.pnpm_resolve_bin(home), flat)

    def test_non_executable_falls_through(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            self._put(home, "bin/pnpm", executable=False)
            flat = self._put(home, "pnpm")
            self.assertEqual(node.pnpm_resolve_bin(home), flat)

    def test_glob_backstop_catches_future_relocation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            moved = self._put(home, "libexec/pnpm")
            self.assertEqual(node.pnpm_resolve_bin(home), moved)

    def test_none_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(node.pnpm_resolve_bin(Path(td)))


class TestPnpmLauncher(unittest.TestCase):
    def test_wrapper_anchors_argv0_through_a_symlink(self) -> None:
        """THE shipped bug: pnpm's cmd-shim resolves its payload relative to
        $0 without canonicalising symlinks. The wrapper must pass the ABSOLUTE
        target, so even invoked via a symlink from a different directory the
        payload sees the real path. Executed for real, not inspected."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            payload = tmp / "opt/pnpm/bin/pnpm"
            payload.parent.mkdir(parents=True)
            payload.write_text('#!/bin/sh\nprintf "ARGV0=%s" "$0"\n')
            payload.chmod(0o755)
            wrapper = tmp / "usr-bin/pnpm"
            wrapper.parent.mkdir()
            wrapper.write_text(node.emit_pnpm_launcher(payload))
            wrapper.chmod(0o755)
            link = tmp / "elsewhere/pnpm"
            link.parent.mkdir()
            link.symlink_to(wrapper)
            out = subprocess.run([str(link)], capture_output=True, text=True)
            self.assertEqual(out.stdout, f"ARGV0={payload}",
                             "the wrapper lost the absolute anchor — pnpm's "
                             "$0-relative payload lookup would now miss")


class TestPnpmProfile(unittest.TestCase):
    def test_snippet_exports_pnpm_home_and_path(self) -> None:
        s = node.emit_pnpm_profile_snippet(".local/share/pnpm", "bin")
        self.assertIn('PNPM_HOME="$HOME/.local/share/pnpm"', s)
        self.assertIn("export PNPM_HOME", s)
        self.assertIn('PATH="$PNPM_HOME/bin:${PATH:-}"', s)

    def test_snippet_is_posix_sh(self) -> None:
        s = node.emit_pnpm_profile_snippet(".local/share/pnpm")
        self.assertNotIn("[[", s)  # no bashisms — dash sources this
        if shutil.which("dash"):
            with tempfile.NamedTemporaryFile("w", suffix=".sh") as f:
                f.write(s)
                f.flush()
                rc = subprocess.run(["dash", "-n", f.name]).returncode
                self.assertEqual(rc, 0)

    def test_learned_subdir_lands_on_path(self) -> None:
        s = node.emit_pnpm_profile_snippet(".local/share/pnpm", "shims")
        self.assertIn("$PNPM_HOME/shims:", s)


class TestGlobalBinSubdir(unittest.TestCase):
    def test_result_inside_home_is_stripped(self) -> None:
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            (cfg.pnpm_home / "bin").mkdir(parents=True)
            p = cfg.pnpm_home / "bin/pnpm"
            p.write_text("#!/bin/sh\n")
            p.chmod(0o755)
            with mock.patch.object(node.system, "pnpm_global_bin_dir",
                                   return_value=f"{cfg.pnpm_home}/shims"):
                self.assertEqual(node.pnpm_global_bin_subdir(cfg), "shims")

    def test_result_outside_home_degrades_to_bin(self) -> None:
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            (cfg.pnpm_home / "bin").mkdir(parents=True)
            p = cfg.pnpm_home / "bin/pnpm"
            p.write_text("#!/bin/sh\n")
            p.chmod(0o755)
            # A host-local global-bin-dir override must never be baked into
            # every user's profile.
            with mock.patch.object(node.system, "pnpm_global_bin_dir",
                                   return_value="/root/.local/share/pnpm"):
                self.assertEqual(node.pnpm_global_bin_subdir(cfg), "bin")

    def test_no_pnpm_degrades_to_bin(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(node.pnpm_global_bin_subdir(make_config(Path(td))), "bin")


class TestBinStatus(unittest.TestCase):
    def test_dangling_symlink_is_broken(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            cfg.bin_dir.mkdir(parents=True)
            (cfg.bin_dir / "node").symlink_to(Path(td) / "gone")
            s, ok = node.bin_status(cfg, "node")
            self.assertFalse(ok)
            self.assertIn("BROKEN dangling", s)

    def test_missing_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            cfg.bin_dir.mkdir(parents=True)
            s, ok = node.bin_status(cfg, "node")
            self.assertEqual((s, ok), ("MISSING", False))

    def test_ok_and_stale(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            cfg.bin_dir.mkdir(parents=True)
            n = cfg.bin_dir / "node"
            n.write_text('#!/bin/sh\necho v24.0.0\n')
            n.chmod(0o755)
            s, ok = node.bin_status(cfg, "node")
            self.assertFalse(ok)
            self.assertIn("STALE", s)
            n.write_text('#!/bin/sh\necho v26.5.0\n')
            s, ok = node.bin_status(cfg, "node")
            self.assertTrue(ok)
            self.assertEqual(s, "OK v26.5.0")


if __name__ == "__main__":
    unittest.main()
