"""Reporter format, executor semantics, caddy snippet, prereqs probe, CLI
surface, install-sequence ordering."""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import RecordingExecutor, make_config, quiet_reporter  # noqa: E402
from vide import caddy, install_flow  # noqa: E402
from vide.executor import Executor  # noqa: E402
from vide.reporter import Reporter  # noqa: E402


class TestReporter(unittest.TestCase):
    def test_level_prefixes_match_bash_byte_for_byte(self) -> None:
        buf = io.StringIO()  # not a tty → plain format
        rep = Reporter(debug=True, stream=buf)
        rep.info("i")
        rep.warn("w")
        rep.err("e")
        rep.debug("d")
        self.assertEqual(buf.getvalue().splitlines(),
                         ["INFO  i", "WARN  w", "ERROR e", "DEBUG d"])

    def test_debug_gated(self) -> None:
        buf = io.StringIO()
        Reporter(debug=False, stream=buf).debug("hidden")
        self.assertEqual(buf.getvalue(), "")


class TestExecutorSemantics(unittest.TestCase):
    def test_env_merges_and_clear_env_removes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            os.environ["VIDE_TEST_CLEARME"] = "leaky"
            try:
                ex = Executor(dry_run=False, reporter=quiet_reporter())
                ex.run(["sh", "-c",
                        f'printf "%s|%s" "$VIDE_TEST_SET" "${{VIDE_TEST_CLEARME:-gone}}" > {out}'],
                       env={"VIDE_TEST_SET": "yes"},
                       clear_env=("VIDE_TEST_CLEARME",))
            finally:
                os.environ.pop("VIDE_TEST_CLEARME", None)
            # merge (parent env survives + overlay applied), clear = REMOVED
            self.assertEqual(out.read_text(), "yes|gone")

    def test_umask_applies_to_child_and_restores(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            before = os.umask(0o077)
            os.umask(before)
            ex = Executor(dry_run=False, reporter=quiet_reporter())
            ex.run(["sh", "-c", f"umask > {out}"], umask=0o022)
            self.assertEqual(out.read_text().strip().lstrip("0") or "0", "22")
            after = os.umask(0)
            os.umask(after)
            self.assertEqual(before, after, "umask leaked past the spawn")

    def test_dry_run_renders_argv_never_stdin(self) -> None:
        buf = io.StringIO()
        rep = Reporter(stream=buf)
        ex = Executor(dry_run=True, reporter=rep)
        ex.run(["chpasswd"], input_text="alice:S3CRET\n")
        log = buf.getvalue()
        self.assertIn("chpasswd", log)
        self.assertNotIn("S3CRET", log, "the preview leaked a stdin-fed secret")

    def test_atomic_write_mode_and_content_no_temp_litter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "f"
            ex = Executor(dry_run=False, reporter=quiet_reporter())
            ex.atomic_write(dest, "one", mode=0o644)
            ex.atomic_write(dest, "two", mode=0o600)  # clobbers, like mv -f
            self.assertEqual(dest.read_text(), "two")
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
            self.assertEqual([p.name for p in Path(td).iterdir()], ["f"])

    def test_run_setup_script_chmods_0644_for_as_user(self) -> None:
        """The shipped EACCES bug: root's 0600 temp is unreadable by the target
        user the installer runs as. Capture the script's mode at spawn time."""
        seen = {}

        class Probe(Executor):
            def _spawn(self, argv, **kw):  # type: ignore[override]
                script = next(a for a in argv if "/vide-installer." in a)
                seen["mode"] = os.stat(script).st_mode & 0o777

        from fakes import FakeDlConfig
        ex = Probe(dry_run=False, reporter=quiet_reporter(), cfg=FakeDlConfig())
        with mock.patch("vide.net.download",
                        side_effect=lambda url, dest, *a, **k: Path(dest).write_text("#!/bin/sh\n")):
            ex.run_setup_script("https://x.test/i.sh", "VAR", ["sh"], as_user="alice",
                                home="/home/alice")
        self.assertEqual(seen["mode"], 0o644)


class TestTickingSpawn(unittest.TestCase):
    """The ticking (wizard) spawn path: a child must never hold the
    operator's terminal. The first live smoke §1 walk found apt COMPLETING
    its package work then stopping in state T: a background-pgrp child that
    tcsetattr's its inherited tty stdin draws an unconditional SIGTTOU
    (apt's StopPtyMagic, Debian #555632) and the poll loop waits forever."""

    def test_tcsetattr_child_cannot_stop_the_ticking_loop(self) -> None:
        """The fix-agnostic kernel-fact reproduction, watchdogged from
        OUTSIDE: a regression here HANGS the harness, so the kill switch
        must not live inside the hung process. On the kill path the stopped
        grandchild's group becomes an orphaned pgrp with a stopped member —
        POSIX mandates kernel HUP+CONT, so nothing leaks."""
        harness = Path(__file__).resolve().parent / "tty_repro_harness.py"
        try:
            proc = subprocess.run([sys.executable, str(harness)],
                                  timeout=10, start_new_session=True,
                                  capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            self.fail("ticking loop hung on a tty-touching child — the "
                      "SIGTTOU stop (smoke §1 apt hang) has regressed")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_ticking_child_without_input_gets_devnull_stdin_and_detaches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "probe"
            ex = Executor(dry_run=False, reporter=quiet_reporter(),
                          tick=lambda: time.sleep(0.005))
            # Park a PIPE on our own fd 0 for the spawn: the runner's stdin
            # may itself be /dev/null (prove-teeth runs the suite that way),
            # which would make an INHERITED stdin indistinguishable from the
            # deliberate DEVNULL — exactly the vacuous-green this probe must
            # not have. With a pipe there, inheritance reads "pipe:[...]".
            r, w = os.pipe()
            saved0 = os.dup(0)
            os.dup2(r, 0)
            try:
                ex.run([sys.executable, "-c",
                        "import os, pathlib\n"
                        f"pathlib.Path({str(out)!r}).write_text(' '.join(\n"
                        "    [os.readlink('/proc/self/fd/0'),\n"
                        "     str(os.getsid(0)), str(os.getpid())]))\n"])
            finally:
                os.dup2(saved0, 0)
                os.close(saved0)
                os.close(r)
                os.close(w)
            fd0, sid, pid = out.read_text().split()
            self.assertEqual(fd0, "/dev/null")
            self.assertEqual(sid, pid,
                             "child must lead its OWN session — no controlling "
                             "tty, no /dev/tty re-acquisition, no SIGTTOU")
            self.assertNotEqual(int(sid), os.getsid(0),
                                "child landed in the test runner's session")

    def test_ticking_input_text_still_arrives_on_a_pipe(self) -> None:
        """Guards the DEVNULL change from over-rotating: chpasswd/tee children
        are fed one-liners on a PIPE (secrets never on argv) — that channel
        must survive."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            ex = Executor(dry_run=False, reporter=quiet_reporter(),
                          tick=lambda: time.sleep(0.005))
            ex.run(["sh", "-c", f"cat > {out}"], input_text="piped-line\n")
            self.assertEqual(out.read_text(), "piped-line\n")

    def test_child_exiting_without_draining_stdin_is_not_a_crash(self) -> None:
        """A child that dies (or closes stdin) before reading its one-liner
        yields EPIPE on the parent's write/close. That is the CHILD's failure —
        its exit code is the story — and it must not surface as an unhandled
        BrokenPipeError. Driven through a fake Popen: a real child racing its
        own exit against our write is nondeterministic by nature.

        The disposition HALF is the load-bearing part: __main__ restores
        SIGPIPE to SIG_DFL (shell parity), and under SIG_DFL the kernel KILLS
        the process with signal 13 before any except clause runs — an EPIPE
        guard alone is dead code. The feed must run with SIGPIPE ignored and
        the entry disposition restored afterwards."""
        import signal

        seen = {}

        class _DeadStdin:
            def write(self, s):
                seen["disposition"] = signal.getsignal(signal.SIGPIPE)
                raise BrokenPipeError(32, "Broken pipe")

            def close(self):
                raise BrokenPipeError(32, "Broken pipe")

        class _DeadChild:
            pid = 424242
            stdin = _DeadStdin()

            def poll(self):
                return 0  # exited cleanly from the loop's point of view

        ex = Executor(dry_run=False, reporter=quiet_reporter(),
                      tick=lambda: None)
        entry = signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # the __main__ reality
        try:
            with mock.patch("vide.executor.subprocess.Popen",
                            return_value=_DeadChild()) as popen:
                ex.run(["chpasswd"], input_text="alice:pw\n")  # must not raise
            self.assertEqual(popen.call_count, 1)
            self.assertEqual(seen["disposition"], signal.SIG_IGN,
                             "the feed ran under SIG_DFL — EPIPE would be a "
                             "signal-13 death, not a catchable exception")
            self.assertEqual(signal.getsignal(signal.SIGPIPE), signal.SIG_DFL,
                             "the entry disposition was not restored")
        finally:
            signal.signal(signal.SIGPIPE, entry)

    def test_child_that_dies_without_draining_still_reports_its_rc(self) -> None:
        """Swallowing EPIPE must not swallow the FAILURE: the child's nonzero
        exit code still surfaces as CommandFailed."""
        from vide.errors import CommandFailed

        class _DeadStdin:
            def write(self, s):
                raise BrokenPipeError(32, "Broken pipe")

            def close(self):
                raise BrokenPipeError(32, "Broken pipe")

        class _DeadChild:
            pid = 424243
            stdin = _DeadStdin()

            def poll(self):
                return 3

        ex = Executor(dry_run=False, reporter=quiet_reporter(),
                      tick=lambda: None)
        with mock.patch("vide.executor.subprocess.Popen",
                        return_value=_DeadChild()):
            with self.assertRaises(CommandFailed) as cm:
                ex.run(["chpasswd"], input_text="alice:pw\n")
        self.assertEqual(cm.exception.returncode, 3)


class TestStoppedHelper(unittest.TestCase):
    def test_stopped_reads_the_real_process_state(self) -> None:
        """The tripwire's eyes: /proc/<pid>/stat state after the LAST ')'
        (comm may hold spaces/parens), T/t only, OSError → False."""
        import signal
        from vide.executor import _stopped
        child = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            self.assertFalse(_stopped(child.pid), "a running child is not T")
            os.kill(child.pid, signal.SIGSTOP)
            deadline = time.monotonic() + 2
            while not _stopped(child.pid):
                self.assertLess(time.monotonic(), deadline,
                                "SIGSTOPped child never read as state T")
                time.sleep(0.01)
        finally:
            os.kill(child.pid, signal.SIGKILL)
            child.wait()
        self.assertFalse(_stopped(child.pid), "a reaped pid must read False")


class TestTickingAbortGrace(unittest.TestCase):
    def test_stopped_child_dies_by_delivered_term_within_the_grace(self) -> None:
        """SIGTERM stays PENDING on a stopped group until SIGCONT: without
        the chaser the 'graceful' abort silently burns the whole 5s grace and
        SIGKILLs (dpkg would die -9 mid-transaction — the exact outcome the
        grace exists to prevent). Broken shape: no marker file, ~5.3s."""
        with tempfile.TemporaryDirectory() as td:
            mark = Path(td) / "mark"
            ex = Executor(dry_run=False, reporter=quiet_reporter(),
                          tick=lambda: time.sleep(0.005))
            t0 = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                # timeout 0.5s, not 0.2: sh must have STOPPED ITSELF before
                # the deadline fires, or the test degrades into a plain
                # TERM-of-a-running-child and never exercises the CONT chaser
                ex.run(["sh", "-c",
                        f'trap "echo term > {mark}; exit 0" TERM; '
                        "kill -STOP $$; exit 1"],
                       timeout=0.5)
            elapsed = time.monotonic() - t0
            self.assertTrue(mark.exists(),
                            "child died ungraceful (-9): TERM was never "
                            "delivered to the stopped group")
            self.assertLess(elapsed, 4.0,
                            "grace degenerated to the 5s KILL fallback")


class TestCaddySnippet(unittest.TestCase):
    def test_contract_lines(self) -> None:
        s = caddy.emit_snippet("bob", 9797, "vide.example.com")
        self.assertIn("reverse_proxy 127.0.0.1:9797", s)
        self.assertIn("stream_close_delay 30m", s)
        self.assertIn("flush_interval -1", s)
        self.assertIn("vide.example.com {", s)

    def test_placeholder_without_fqdn(self) -> None:
        s = caddy.emit_snippet("bob", 9797)
        self.assertIn("<SUBDOMAIN> {", s)

    def test_does_not_rewrite_host(self) -> None:
        # header_up Host makes the editor render but never connect ("Invalid
        # Host/Origin"). The string may appear only in the warning COMMENT.
        for line in caddy.emit_snippet("bob", 9797).splitlines():
            if "header_up" in line:
                self.assertTrue(line.lstrip().startswith("#"),
                                f"live header_up directive in the snippet: {line!r}")


class TestEnsurePrereqs(unittest.TestCase):
    def _run(self, *, ldconfig: bool, have=lambda c: True) -> RecordingExecutor:
        ex = RecordingExecutor()
        with mock.patch.object(install_flow.system, "have_cmd", side_effect=have), \
             mock.patch.object(install_flow.system, "ldconfig_has",
                               return_value=ldconfig), \
             mock.patch.object(install_flow.Path, "exists", return_value=True):
            install_flow.ensure_prereqs(ex, quiet_reporter())
        return ex

    def test_missing_libatomic_adds_the_package(self) -> None:
        # pnpm's standalone binary links against libatomic.so.1; Node does not.
        # Found by the integration tier on its very first real run.
        ex = self._run(ldconfig=False)
        installs = [a for a in ex.actions if a[1][:3] == ("apt-get", "install", "-y")]
        self.assertEqual(len(installs), 1)
        self.assertIn("libatomic1", installs[0][1])

    def test_present_libatomic_installs_nothing(self) -> None:
        ex = self._run(ldconfig=True)
        self.assertEqual(ex.actions, [], "nothing missing → apt must not run")

    def test_missing_curl_still_installed_for_the_upstream_installers(self) -> None:
        # urllib replaced curl for VIDE's OWN fetches; the nvm/pnpm/code-server
        # installers still fetch with curl themselves. Do not "trim" it.
        ex = self._run(ldconfig=True, have=lambda c: c != "curl")
        installs = [a for a in ex.actions if a[1][:3] == ("apt-get", "install", "-y")]
        self.assertIn("curl", installs[0][1])


class TestEnsureSudo(unittest.TestCase):
    """The smoke §1 finding: minimal images ship the sudo GROUP (gid 27,
    base-passwd) without the sudo PACKAGE — useradd -G sudo succeeds while
    sudo/visudo do not exist. The vide branch must ensure the package."""

    def _run(self, *, present: bool) -> RecordingExecutor:
        ex = RecordingExecutor()
        # keyed stub, not a blanket bool: an unexpected probe fails loudly
        with mock.patch.object(install_flow.system, "have_cmd",
                               side_effect=lambda c: {"sudo": present}[c]), \
             mock.patch.object(install_flow.system, "visudo_cmd",
                               return_value="/usr/sbin/visudo" if present else None):
            install_flow.ensure_sudo(ex, quiet_reporter())
        return ex

    def test_missing_sudo_adds_the_package(self) -> None:
        ex = self._run(present=False)
        argvs = [a[1] for a in ex.actions if a[0] == "run"]
        self.assertEqual(argvs, [("apt-get", "update", "-qq"),
                                 ("apt-get", "install", "-y", "sudo")],
                         "own update first: ensure_prereqs may have left the "
                         "lists untouched on an all-prereqs-present box")

    def test_present_sudo_installs_nothing(self) -> None:
        self.assertEqual(self._run(present=True).actions, [])


class TestInstallSequenceOrdering(unittest.TestCase):
    def test_platform_then_prereqs_then_tools(self) -> None:
        """The gate straddle: distro/arch refuse BEFORE apt ever runs; the
        tool floor is checked AFTER apt installed curl. The honest Python form
        of the old line-number grep."""
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            osr = tmp / "osr"
            osr.write_text("ID=debian\n")
            cfg = make_config(tmp, dry_run=True, os_release_file=osr,
                              uname_m="x86_64", vide_user="nosuchuser-xyz")
            rep = quiet_reporter()
            ex = Executor(dry_run=True, reporter=rep, cfg=cfg)
            from vide.confirm import Confirmer
            conf = Confirmer(yes_argv=False, environ={}, reporter=rep)
            with mock.patch.object(install_flow.preflight, "platform_gate",
                                   side_effect=lambda *a: calls.append("platform")), \
                 mock.patch.object(install_flow, "ensure_prereqs",
                                   side_effect=lambda *a: calls.append("prereqs")), \
                 mock.patch.object(install_flow.preflight, "tools_gate",
                                   side_effect=lambda *a: calls.append("tools")), \
                 contextlib.redirect_stdout(io.StringIO()):
                install_flow.run_install(cfg, ex, rep, conf)
        self.assertEqual(calls[:3], ["platform", "prereqs", "tools"])


class TestGlobalFlagsReachInstall(unittest.TestCase):
    def test_vide_dry_run_install_stays_a_preview(self) -> None:
        """REGRESSION (review r1, two independent finders): main() once
        dropped the global argv_env in the install handoff, so
        `vide --dry-run install` printed the banner and then ran a REAL
        install — the exact betrayal --dry-run exists to prevent."""
        from unittest import mock as m
        from vide import cli
        captured = {}

        def fake_run_install(cfg, ex, rep, conf, prompter=None):
            captured["dry_run"] = cfg.dry_run
            captured["ex_dry"] = ex.dry_run
            return 0

        with tempfile.TemporaryDirectory() as td, \
             m.patch.object(cli, "run_install", side_effect=fake_run_install), \
             m.patch.object(cli.os, "isatty", return_value=False), \
             contextlib.redirect_stderr(io.StringIO()):
            # isatty mocked False: on an interactive terminal the REAL gate
            # would otherwise open a live curses screen inside the unit tier.
            rc = cli.main(["--dry-run", "install", "--user", "x"], Path(td))
        self.assertEqual(rc, 0)
        self.assertTrue(captured["dry_run"], "global --dry-run was dropped "
                        "on the way into the install sequencer")
        self.assertTrue(captured["ex_dry"])

    def test_debug_travels_too(self) -> None:
        from unittest import mock as m
        from vide import cli
        captured = {}
        with tempfile.TemporaryDirectory() as td, \
             m.patch.object(cli, "run_install",
                            side_effect=lambda cfg, ex, rep, conf, prompter=None:
                            captured.update(debug=cfg.debug) or 0), \
             m.patch.object(cli.os, "isatty", return_value=False), \
             contextlib.redirect_stderr(io.StringIO()):
            cli.main(["--debug", "install"], Path(td))
        self.assertTrue(captured["debug"])


class TestDoctorUserViewGate(unittest.TestCase):
    def test_non_root_doctor_never_false_perms(self) -> None:
        """REGRESSION (review r1, two independent finders): the port dropped
        bash's EUID==0 gate on the user-view probe; runuser then fails for a
        plain user and doctor lied PERM/69 about a healthy box."""
        from unittest import mock as m
        from vide import node as vnode
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            cfg.bin_dir.mkdir(parents=True)
            for b in ("node", "npm", "npx", "pnpm"):
                p = cfg.bin_dir / b
                p.write_text('#!/bin/sh\necho v26.5.0\n')
                p.chmod(0o755)
            with m.patch.object(vnode.system, "euid", return_value=1000), \
                 m.patch.object(vnode.system, "probe_as",
                                side_effect=AssertionError("runuser must not run non-root")):
                report, healthy = vnode.toolchain_report(cfg, "somebody")
        self.assertTrue(healthy)
        self.assertNotIn("PERM", report)

    def test_root_doctor_still_catches_traversal(self) -> None:
        from unittest import mock as m
        from vide import node as vnode
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            cfg.bin_dir.mkdir(parents=True)
            for b in ("node", "npm", "npx", "pnpm"):
                p = cfg.bin_dir / b
                p.write_text('#!/bin/sh\necho v26.5.0\n')
                p.chmod(0o755)
            with m.patch.object(vnode.system, "euid", return_value=0), \
                 m.patch.object(vnode.system, "probe_as", return_value=False):
                report, healthy = vnode.toolchain_report(cfg, "ittest")
        self.assertFalse(healthy)
        self.assertIn("PERM", report)


class TestCliSurface(unittest.TestCase):
    def test_usage_lists_every_registered_verb_plus_install(self) -> None:
        from vide.cli import COMMANDS, USAGE
        for cmd in COMMANDS:
            self.assertIn(f"\n  {cmd.name}", USAGE, f"{cmd.name} missing from usage")
        self.assertIn("\n  install", USAGE)

    def test_only_destroy_and_rotate_are_destructive(self) -> None:
        from vide.cli import COMMANDS
        destructive = {c.name for c in COMMANDS if c.destructive}
        # rotate-sso is the fleet-wide kill switch (signs out ALL users on ALL
        # instances) — a strictly larger blast radius than `rotate <user>`, so
        # it carries the same argv-only gate. allow/revoke do NOT: the last-email
        # revoke is gated in-handler on state the static table cannot see.
        self.assertEqual(destructive, {"destroy", "rotate", "rotate-sso"},
                         "down/allow/revoke stay off the static gate — see the handler note")

    def test_a_flag_after_the_verb_is_refused_not_ignored(self) -> None:
        """`vide toolchain --dry-run` used to converge FOR REAL: main() parses
        global flags before the verb, and handlers read args positionally and
        dropped the rest. --yes failed safe (an extra prompt); --dry-run failed
        unsafe, on the one promise a provisioner cannot break twice."""
        from vide.cli import COMMANDS, main
        from vide.errors import UsageError
        with tempfile.TemporaryDirectory() as td:
            for argv in (["toolchain", "--dry-run"], ["upgrade", "u", "--dry-run"],
                         ["upgrade-sso", "--dry-run"], ["down", "u", "--yes"],
                         ["doctor", "--force"], ["ls", "--nonsense"]):
                with self.assertRaises(UsageError, msg=f"{argv} was not refused"):
                    main(argv, Path(td))
        # and the flags each verb DOES declare must still be reachable
        declared = {c.name: c.flags for c in COMMANDS}
        self.assertEqual(declared["doctor"], ("--quiet",))
        self.assertEqual(declared["toolchain"], ("--force",))
        self.assertEqual(declared["allow"], ("--force-restart",))

    def test_a_misplaced_global_flag_says_where_it_belongs(self) -> None:
        # The likely operator error is position, not spelling — the message has
        # to name the fix or it reads as "that flag does not exist".
        from vide.cli import main
        from vide.errors import UsageError
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(UsageError) as cm:
                main(["toolchain", "--dry-run"], Path(td))
        self.assertIn("PRECEDE", str(cm.exception))

    def test_version_answers_without_a_repo_a_config_or_root(self) -> None:
        """The repo_dir passed here does NOT exist: load_config would raise on
        it, so a pass proves --version is answered before any of the machinery
        a broken box breaks. That is the whole point — the flag exists to make
        a bug report from such a box name its revision."""
        from vide import __version__, cli
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["--version"], Path("/vide-no-such-repo"))
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue(), f"vide {__version__}\n")
        self.assertTrue(__version__.strip(), "an empty version identifies nothing")

    def test_usage_names_the_version_flag(self) -> None:
        # Undiscoverable is the same as absent for a flag whose only user is
        # someone writing a bug report.
        from vide.cli import USAGE
        self.assertIn("--version", USAGE)

    def test_root_requirements_match_bash(self) -> None:
        from vide.cli import COMMANDS
        needs_root = {c.name for c in COMMANDS if c.needs_root}
        self.assertEqual(needs_root, {"down", "destroy", "upgrade", "rotate", "toolchain",
                                      "allow", "revoke", "rotate-sso", "upgrade-sso"})


if __name__ == "__main__":
    unittest.main()
