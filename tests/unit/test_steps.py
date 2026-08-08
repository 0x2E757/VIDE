"""Exact-sequence step tests — the typed successor of the expect-files: the
converge issues exactly these external actions in this order. A step silently
dropped from the sequence goes red here, which is what the old parity diff
could NOT see (both passes dropped it together)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import RecordingExecutor, make_config, quiet_reporter  # noqa: E402
from vide import codeserver, node, sysd  # noqa: E402


def _seeded_node_tree(tmp: Path, cfg) -> None:
    b = cfg.nvm_dir / "versions/node/v26.5.0/bin"
    b.mkdir(parents=True)
    for n in ("node", "npm", "npx"):
        p = b / n
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)


def _seeded_pnpm(cfg) -> None:
    p = cfg.pnpm_home / "bin/pnpm"
    p.parent.mkdir(parents=True)
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    # bin_dir is /usr/local/bin on a real box — part of the FHS, always there,
    # so the product does not create it. The fixture has to, now that the fake
    # executor refuses a missing parent the way the real one does. Papering over
    # that in the fake instead is what let a first-install crash ship green.
    cfg.bin_dir.mkdir(parents=True, exist_ok=True)


class TestEnsureNodeSequence(unittest.TestCase):
    def test_converged_repoint_sequence_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            _seeded_node_tree(Path(td), cfg)
            ex = RecordingExecutor()
            node._ensure_node(cfg, ex, quiet_reporter(), cfg.toolchain_force)
            bindir = cfg.nvm_dir / "versions/node/v26.5.0/bin"
            self.assertEqual(ex.actions, [
                ("run", ("ln", "-sfn", str(bindir / "node"), str(cfg.bin_dir / "node"))),
                ("run", ("ln", "-sfn", str(bindir / "npm"), str(cfg.bin_dir / "npm"))),
                ("run", ("ln", "-sfn", str(bindir / "npx"), str(cfg.bin_dir / "npx"))),
                ("run", ("chmod", "-R", "a+rX", str(cfg.nvm_dir))),
            ])
            self.assertEqual(len(ex.verified), 1)

    def test_force_wipes_before_reinstalling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td), toolchain_force=True)
            _seeded_node_tree(Path(td), cfg)
            ex = RecordingExecutor()
            node._ensure_node(cfg, ex, quiet_reporter(), cfg.toolchain_force)
            self.assertEqual(ex.actions[0],
                             ("run", ("rm", "-rf", str(cfg.nvm_dir / "versions/node"))),
                             "--force must wipe FIRST: nvm install is idempotent and "
                             "will not repair a corrupted tree")
            self.assertEqual(ex.verbs[1], "run")           # install -d (ensure_dir)
            self.assertEqual(ex.verbs[2], "run_setup_script")


class TestEnsurePnpmSequence(unittest.TestCase):
    def test_converged_reheal_sequence_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            _seeded_pnpm(cfg)
            ex = RecordingExecutor()
            with mock.patch.object(node, "pnpm_global_bin_subdir", return_value="bin"):
                node._ensure_pnpm(cfg, ex, quiet_reporter(), cfg.toolchain_force)
            self.assertEqual(
                [(a[0],) + (a[1],) for a in ex.actions],
                [("atomic_write", str(cfg.bin_dir / "pnpm")),
                 ("run", ("chmod", "-R", "a+rX", str(cfg.pnpm_home))),
                 ("run", ("install", "-d", "-m", "0755", "-o", "root", "-g", "root",
                          str(Path(cfg.pnpm_profile).parent))),
                 ("atomic_write", str(cfg.pnpm_profile))])
            # The wrapper is a WRAPPER, not a symlink — the $0 anchor.
            self.assertIn("exec ", ex.contents[str(cfg.bin_dir / "pnpm")])

    def test_force_wipes_whole_home_first(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td), toolchain_force=True)
            _seeded_pnpm(cfg)
            ex = RecordingExecutor()
            with mock.patch.object(node, "pnpm_global_bin_subdir", return_value="bin"):
                node._ensure_pnpm(cfg, ex, quiet_reporter(), cfg.toolchain_force)
            self.assertEqual(ex.actions[0],
                             ("run", ("rm", "-rf", str(cfg.pnpm_home))))


class TestInstallUnitSequence(unittest.TestCase):
    def _unit_src(self, cfg) -> Path:
        src = cfg.repo_dir / "units/code-server@.service"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text("[Unit]\nDescription=x\n")
        launcher = cfg.repo_dir / "units/code-server-launch"
        launcher.write_text("#!/bin/sh\n")
        return src

    def test_fresh_install_writes_unit_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            src = self._unit_src(cfg)
            ex = RecordingExecutor()
            sysd.install_unit(cfg, ex, quiet_reporter())
            self.assertEqual(ex.actions, [
                ("run", ("install", "-d", "-m", "0755", "-o", "root", "-g", "root",
                         str(Path(cfg.launcher).parent))),
                ("run", ("install", "-m", "0755", "-o", "root", "-g", "root",
                         str(cfg.repo_dir / "units/code-server-launch"), str(cfg.launcher))),
                ("run", ("install", "-m", "0644", "-o", "root", "-g", "root",
                         str(src), str(cfg.unit_path))),
                ("run", ("systemctl", "daemon-reload")),
            ])

    def test_unchanged_unit_skips_daemon_reload_but_installs_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            src = self._unit_src(cfg)
            Path(cfg.unit_path).parent.mkdir(parents=True)
            Path(cfg.unit_path).write_text(src.read_text())  # identical
            ex = RecordingExecutor()
            sysd.install_unit(cfg, ex, quiet_reporter())
            verbs = [a[1][0] for a in ex.actions if a[0] == "run"]
            self.assertNotIn("systemctl", verbs,
                             "converging an unrelated user must not churn the "
                             "shared template unit")
            # ...but the launcher is still (re-)installed on the skip path.
            self.assertEqual(len([a for a in ex.actions
                                  if a[0] == "run" and "install" == a[1][0]]), 2)


class TestCodeServerInstall(unittest.TestCase):
    def test_installer_runs_as_user_with_standalone_method(self) -> None:
        # Branding is stubbed out: this row is about the INSTALLER, and letting
        # a cosmetic step widen the recorded sequence would make the assertion
        # drift every time branding grows. That branding is CALLED at all is
        # pinned separately, in TestBrandingHangsOffTheChokePoint.
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = RecordingExecutor()
            with mock.patch.object(codeserver.system, "probe_as", return_value=False), \
                 mock.patch.object(codeserver.branding, "apply"), \
                 mock.patch.object(codeserver.branding, "seed_user_settings"), \
                 mock.patch.object(codeserver.system, "user_home",
                                   return_value=Path(td) / "home/alice"):
                codeserver.ensure_code_server(cfg, ex, quiet_reporter(), "alice")
            self.assertEqual(len(ex.actions), 1)
            verb, url, runner, args, as_user = ex.actions[0]
            self.assertEqual(verb, "run_setup_script")
            self.assertEqual(runner, ("sh",))
            self.assertEqual(args, ("--method", "standalone"))
            self.assertEqual(as_user, "alice")

    def test_already_installed_is_left_alone(self) -> None:
        # Install/upgrade decoupling: adding user B never restarts user A —
        # MainPID stability across converges depends on this short-circuit.
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = RecordingExecutor()
            with mock.patch.object(codeserver.system, "probe_as", return_value=True), \
                 mock.patch.object(codeserver.system, "user_home",
                                   return_value=Path(td) / "home/alice"):
                codeserver.ensure_code_server(cfg, ex, quiet_reporter(), "alice")
            self.assertEqual(ex.actions, [])

    def test_version_pin_reaches_the_installer_argv(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td), code_server_version="4.99.1")
            ex = RecordingExecutor()
            with mock.patch.object(codeserver.system, "probe_as", return_value=False), \
                 mock.patch.object(codeserver.branding, "apply"), \
                 mock.patch.object(codeserver.branding, "seed_user_settings"), \
                 mock.patch.object(codeserver.system, "user_home",
                                   return_value=Path(td) / "h"):
                codeserver.ensure_code_server(cfg, ex, quiet_reporter(), "alice")
            self.assertEqual(ex.actions[0][3],
                             ("--method", "standalone", "--version", "4.99.1"))


class TestBrandingHangsOffTheChokePoint(unittest.TestCase):
    """Branding patches a VENDORED tree that `vide upgrade` replaces wholesale.
    If it ever stops hanging off _install_code_server, the favicon and the
    webfont come back for a fresh install and silently vanish on the next
    upgrade — the exact failure this placement exists to prevent."""

    def _run(self, verb, already_installed: bool):
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = RecordingExecutor()
            # The branding mock records its position in the SAME action list the
            # executor keeps, which is what makes order assertable at all.
            def mark(*a, **k):
                ex.actions.append(("branding.apply",))
            with mock.patch.object(codeserver.system, "probe_as",
                                   return_value=already_installed), \
                 mock.patch.object(codeserver.branding, "apply",
                                   side_effect=mark) as brand, \
                 mock.patch.object(codeserver.branding, "seed_user_settings") as seed, \
                 mock.patch.object(codeserver.system, "user_home",
                                   return_value=Path(td) / "home/alice"):
                verb(cfg, ex, quiet_reporter(), "alice")
            self.last_actions = [a[0] for a in ex.actions]
            return brand, seed

    def test_a_fresh_install_brands(self) -> None:
        brand, seed = self._run(codeserver.ensure_code_server, already_installed=False)
        self.assertEqual(1, brand.call_count)
        self.assertEqual(1, seed.call_count)

    def test_branding_runs_after_the_installer_not_before_it(self) -> None:
        """Call COUNT was pinned and ORDER was not. Move branding above
        run_setup_script and all three placement rows stay green — while
        code_server_root resolves nothing on a fresh box, branding warns, and
        silently no-ops. Its documented failure mode is precisely a warning
        nobody reads."""
        self._run(codeserver.ensure_code_server, already_installed=False)
        kinds = self.last_actions
        self.assertIn("run_setup_script", kinds,
                      "the installer step disappeared — this pin is now vacuous")
        self.assertLess(kinds.index("run_setup_script"), kinds.index("branding.apply"),
                        "branding must patch a tree that already exists")

    def test_an_upgrade_re_brands(self) -> None:
        # The load-bearing half: an upgrade lays down a NEW versioned tree, so
        # branding that ran only at install time would be gone.
        brand, seed = self._run(codeserver.upgrade_code_server, already_installed=True)
        self.assertEqual(1, brand.call_count)
        self.assertEqual(1, seed.call_count)

    def test_a_converge_on_an_installed_user_brands_nothing(self) -> None:
        # The tree is untouched, so re-branding would be pure churn — and this
        # short-circuit is what keeps adding user B from disturbing user A.
        brand, seed = self._run(codeserver.ensure_code_server, already_installed=True)
        self.assertEqual(0, brand.call_count)
        self.assertEqual(0, seed.call_count)


class TestCodeServerVersionPrecedence(unittest.TestCase):
    def test_explicit_pin_wins(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td), code_server_version="1.2.3",
                              code_server_pin_latest=True)
            ex = RecordingExecutor()
            self.assertEqual(codeserver.code_server_version(cfg, ex), "1.2.3")

    def test_pin_off_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            self.assertEqual(codeserver.code_server_version(cfg, RecordingExecutor()), "")

    def test_dry_run_never_touches_the_network(self) -> None:
        from vide.executor import Executor
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td), code_server_pin_latest=True)
            ex = Executor(dry_run=True, reporter=quiet_reporter(), cfg=cfg)
            with mock.patch.object(codeserver.net, "resolve_latest_version") as r:
                self.assertEqual(codeserver.code_server_version(cfg, ex), "")
                r.assert_not_called()


if __name__ == "__main__":
    unittest.main()
