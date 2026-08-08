"""The execution choke point — every durable mutation flows through here.

The boundary rule, made a type:
one class, parameterized by dry_run; the mutate-family methods branch on it
and log the preview DERIVED FROM THE REAL OPERATION, so dry-run parity is
definitional — there is no second, hand-maintained description to rot.

Domain modules receive an Executor and import neither subprocess nor os
(pinned by tests/unit/test_invariants.py). The two typed escape hatches are
`narrate()` (the secret-path / value-producer skip: a preview must not mint a
real credential) and `verify()` (post-mutation assertions a preview cannot
make). Everything the bash carved out with `# DRY-RUN ALLOWLIST:` tags is
either dissolved by the mutate/observe split (reads live in system.py and
always run) or routed through those two names.

Style rule: mutations bash performed via coreutils argv STAY coreutils argv
(`ln -sfn`, `chmod -R a+rX`, `install -d/-m`, `useradd`, `systemctl`, `rm`) —
zero semantic-porting risk and the preview line falls out of the argv. Only
atomic_write (root-owned destinations) and download are native.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .errors import CommandFailed, Ex, SoftwareError, VideError
from .reporter import Reporter
from . import net
from . import system


def _stopped(pid: int) -> bool:
    """True when /proc/<pid>/stat shows state T/t. The state is the field
    after the LAST ')' — comm may contain spaces and parens. Read-only on
    purpose: waitpid(WUNTRACED) would consume the status Popen.poll() relies
    on. Linux-only, like the platform gate that admits this box at all."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            stat = f.read()
    except OSError:
        return False
    tail = stat.rpartition(b")")[2].split()
    return bool(tail) and tail[0] in (b"T", b"t")


class Executor:
    def __init__(self, *, dry_run: bool, reporter: Reporter,
                 cfg: "net.DlSettings | None" = None,
                 tick: Callable[[], None] | None = None) -> None:
        self.dry_run = dry_run
        self._rep = reporter
        self._cfg = cfg  # only download() needs the DL_* tunables
        # `tick` is the TUI heartbeat: when set, _spawn waits on children in a
        # poll loop that calls it (so the wizard can repaint, tail the log
        # capture and service Ctrl-C while apt runs), and children get their
        # own process group (a terminal ^C must reach the WIZARD, never dpkg
        # mid-transaction). None = plain mode, byte-for-byte today's path.
        # The tick contract: it must BLOCK briefly (the session's getch
        # timeout is the loop's pacing); a non-blocking tick would busy-spin.
        self._tick = tick
        self._current: "subprocess.Popen[str] | None" = None

    # ---- the typed escape hatches ------------------------------------------

    def narrate(self, msg: str) -> bool:
        """DryRun: log '[dry-run] msg' and return True (caller early-returns —
        the secret paths and value-producers). Real: False."""
        if self.dry_run:
            self._rep.info(f"[dry-run] {msg}")
            return True
        return False

    def verify(self, ok: Callable[[], bool], msg: str, code: Ex = Ex.SOFTWARE) -> None:
        """Post-mutation assertion. A preview mutated nothing, so it asserts
        nothing (the bash allowlisted exactly this shape)."""
        if self.dry_run:
            return
        if not ok():
            err = SoftwareError(msg)
            err.code = code
            raise err

    # ---- leaf mutations ------------------------------------------------------

    def run(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None,
            clear_env: Sequence[str] = (), input_text: str | None = None,
            umask: int | None = None, timeout: float | None = None) -> None:
        """Execute a mutating command, or in dry-run log the intended action.
        The debug/dry-run rendering prints ARGV ONLY, never input_text — that
        is what keeps stdin-fed secrets (chpasswd) out of every log."""
        if self.dry_run:
            self._rep.info(f"[dry-run] {shlex.join(argv)}")
            return
        self._rep.debug(f"+ {shlex.join(argv)}")
        self._spawn(argv, env=env, clear_env=clear_env, input_text=input_text,
                    umask=umask, timeout=timeout)

    def run_as(self, user: str, argv: Sequence[str], *,
               env: Mapping[str, str] | None = None,
               input_text: str | None = None, timeout: float | None = None) -> None:
        if self.dry_run:
            self._rep.info(f"[dry-run] (as {user}) {shlex.join(argv)}")
            return
        self._rep.debug(f"+ (as {user}) {shlex.join(argv)}")
        full = [*system._AS_USER, user, "--", *argv]
        self._spawn(full, env=env, input_text=input_text, timeout=timeout)

    def atomic_write(self, dest: Path, content: str, *, mode: int,
                     owner: tuple[str, str] | None = None) -> None:
        """Same-directory temp + rename, so readers never see a torn or
        wrong-perm file. ROOT-OWNED DESTINATIONS ONLY: for anything inside a
        user's tree use write_as_user — a root open() traversing a
        user-controlled directory is a symlink attack (see write_as_user)."""
        if self.dry_run:
            self._rep.info(f"[dry-run] atomic_write {dest} (mode {mode:04o}"
                           + (f" owner {owner[0]}:{owner[1]}" if owner else "") + ")")
            return
        self._rep.debug(f"+ atomic_write {dest} (mode {mode:04o})")
        fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=f".{dest.name}.")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, mode)
            if owner is not None:
                self._chown(tmp, owner)
            # os.replace is rename(2): atomic, clobbers dest, replaces a dest
            # symlink ITSELF (not its target) — the mv -f port. Same-dir temp
            # guarantees same filesystem, so EXDEV is impossible.
            os.replace(tmp, dest)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _chown(self, path: str, owner: tuple[str, str]) -> None:
        """The identity seam, split out of atomic_write for ONE reason: it is the
        single operation in that method a test double cannot perform, and every
        fake that re-implemented the whole method to get around it also silently
        re-implemented the parts it had no business changing — the missing-parent
        refusal, os.replace's symlink semantics, the mode. Two first-SSO-install
        crashes shipped behind exactly that (the missing parent, then the missing
        group), both green across 500+ rows. With the seam here the doubles
        inherit this method verbatim and override four lines instead of thirty.

        Resolution order is load-bearing and mirrored by the doubles: pwd first,
        then grp, both raising BEFORE any chown is attempted — so a group VIDE
        has not created yet fails here, not halfway through a write. Mapped to a
        typed error because the `install -d -o/-g` half of this same class fails
        loudly with `invalid group`, while this half raised a bare KeyError from
        deep inside a write and printed a traceback instead of the fact."""
        import grp as _grp
        import pwd as _pwd
        try:
            uid, gid = _pwd.getpwnam(owner[0]).pw_uid, _grp.getgrnam(owner[1]).gr_gid
        except KeyError as e:
            # SoftwareError, not StateError: every reachable instance of this is
            # VIDE writing an artifact before the step that creates the identity
            # owning it — an ordering bug in this tree, not a state the operator
            # put the box in. Both crashes it names were exactly that.
            raise SoftwareError(
                f"cannot write {path} owned by {owner[0]}:{owner[1]} — that "
                f"identity does not exist yet ({e})") from None
        os.chown(path, uid, gid)

    def write_as_user(self, user: str, dest: Path, content: str, *, mode: int) -> None:
        """Content into a target user's tree, written AS THAT USER, atomically.

        Deliberately the four-subprocess runuser pipeline, not a native root
        write: a hostile/compromised user can make any path component of their
        own tree a symlink (~/.config -> /etc), and a root-privileged
        mkstemp/rename traversing it lands wherever they pointed. Running as
        the user caps the damage at the user's own privileges — the same
        reasoning that governs every write into a user-owned tree. Do not
        "simplify" this."""
        if self.dry_run:
            self._rep.info(f"[dry-run] write_as_user {user} {dest} (mode {mode:04o})")
            return
        self._rep.debug(f"+ write_as_user {user} {dest} (mode {mode:04o})")
        mk = system.query_as(user, ["mktemp", f"{dest.parent}/.{dest.name}.XXXXXX"])
        if mk.returncode != 0 or not mk.stdout.strip():
            raise CommandFailed(("mktemp",), mk.returncode or 1)
        tmp = mk.stdout.strip()
        try:
            self._spawn([*system._AS_USER, user, "--", "tee", tmp],
                        input_text=content, quiet_stdout=True)
            self._spawn([*system._AS_USER, user, "--", "chmod", f"{mode:o}", tmp])
            self._spawn([*system._AS_USER, user, "--", "mv", "-f", tmp, str(dest)])
        except BaseException:
            system.query_as(user, ["rm", "-f", tmp])
            raise

    def ensure_dir(self, path: Path, *, mode: int,
                   owner: tuple[str, str] | None = None) -> None:
        """install -d: creates AND re-asserts mode/owner on an existing dir
        (converge semantics — drift-heal on every run)."""
        argv = ["install", "-d", "-m", f"{mode:04o}"]
        if owner is not None:
            argv += ["-o", owner[0], "-g", owner[1]]
        self.run([*argv, str(path)])

    def ensure_dir_as_user(self, user: str, path: Path, *, mode: int) -> None:
        self.run_as(user, ["install", "-d", "-m", f"{mode:04o}", str(path)])

    def _dl_cfg(self) -> net.DlSettings:
        if self._cfg is None:
            raise SoftwareError("executor constructed without download settings")
        return self._cfg

    def download(self, url: str, dest: Path, override_var: str | None = None) -> None:
        if self.dry_run:
            self._rep.info(f"[dry-run] download {url} -> {dest}")
            return
        net.download(url, dest, override_var, cfg=self._dl_cfg(), rep=self._rep,
                     tick=self._tick)

    def run_setup_script(self, url: str, override_var: str, runner: Sequence[str], *,
                         args: Sequence[str] = (), env: Mapping[str, str] | None = None,
                         clear_env: Sequence[str] = (), as_user: str | None = None,
                         home: str | None = None, throwaway_home: bool = False,
                         umask: int = 0o022) -> None:
        """The sanctioned composite for the three `curl | sh`-class installers
        (nvm, get.pnpm.io, code-server.dev). One honest narrated line under
        dry-run — their bootstrap cannot be expressed as a single argv."""
        if self.dry_run:
            detail = " ".join(f"{k}={v}" for k, v in (env or {}).items())
            who = f" (as {as_user})" if as_user else ""
            self._rep.info(f"[dry-run] fetch {url}, run it with "
                           f"{detail or 'a clean env'}{who}")
            return
        # A PRIVATE 0700 directory, not a bare mkstemp in world-writable /tmp —
        # same pattern as oauth2proxy.install_version. mkstemp's own file is
        # fine, but download() writes to a SIBLING it creates itself
        # ("<name>.part", no O_EXCL/O_NOFOLLOW), and mkstemp's name is
        # world-readable the instant it exists: a local user watching /tmp could
        # pre-create that sibling as a symlink or as a file they keep owning,
        # and root then writes through it — for nvm and pnpm, as root. Debian
        # and Ubuntu ship fs.protected_symlinks/protected_regular, which
        # downgrade that to a retry-loop DoS rather than RCE, but the whole
        # exposure comes from the directory, so the directory is what changes.
        # Honours TMPDIR too, unlike the hardcoded /tmp it replaces.
        tmp_dir = tempfile.mkdtemp(prefix="vide-installer.")  # 0700 by contract
        tmp = Path(tmp_dir) / "installer"
        tmp_home: str | None = None
        try:
            # tick-threaded: these installer fetches are the only downloads
            # the wizard actually performs — a flaky network must not freeze
            # the screen for the connect+backoff worst case (~40s).
            net.download(url, tmp, override_var, cfg=self._dl_cfg(), rep=self._rep,
                         tick=self._tick)
            run_env = dict(env or {})
            if as_user is not None:
                # The installer runs AS the target user, who must be able to
                # traverse the directory and READ the file; both are root-owned
                # and it is a public script, so this leaks nothing. (The shipped
                # EACCES bug, guarded by a test.) Opened only AFTER the download
                # finished: the race the private directory closes is against the
                # ".part" sibling, which exists only during the download. World-
                # READABLE is not the hazard — world-WRITABLE was.
                os.chmod(tmp_dir, 0o755)
                os.chmod(tmp, 0o644)
                if home is not None:
                    run_env["HOME"] = home
                argv = [*system._AS_USER, as_user, "--", "env",
                        *[f"{k}={v}" for k, v in run_env.items()],
                        *runner, str(tmp), *args]
                self._rep.debug(f"+ {shlex.join(argv)}")
                self._spawn(argv, umask=umask)
            else:
                if throwaway_home:
                    tmp_home = tempfile.mkdtemp(prefix="vide-home.")
                    run_env["HOME"] = tmp_home
                argv = [*runner, str(tmp), *args]
                self._rep.debug(f"+ {shlex.join(argv)} [{' '.join(f'{k}={v}' for k, v in run_env.items())}]")
                self._spawn(argv, env=run_env, clear_env=clear_env, umask=umask)
        finally:
            import shutil as _shutil
            _shutil.rmtree(tmp_dir, ignore_errors=True)
            if tmp_home is not None:
                _shutil.rmtree(tmp_home, ignore_errors=True)

    def idle(self, seconds: float) -> None:
        """A domain-visible pause that keeps the TUI alive: plain mode is
        time.sleep; under a session the tick paces the wait (repaint, log
        pump, Ctrl-C service). Real waits only — a dry-run polls nothing."""
        if self.dry_run:
            return
        import time as _time
        if self._tick is None:
            _time.sleep(seconds)
            return
        end = _time.monotonic() + seconds
        while _time.monotonic() < end:
            self._tick()  # blocks ~100 ms per call (the getch heartbeat)

    def kill_current_child(self) -> None:
        """TUI abort hook: SIGTERM the child's whole process group (installers
        background grandchildren). The caller then unwinds (KeyboardInterrupt),
        and _spawn_ticking's finally grants a bounded TERM->KILL grace so dpkg
        can close its transaction instead of dying -9 mid-write. No-op when
        nothing runs."""
        proc = self._current
        if proc is None or proc.poll() is not None:
            return
        import signal as _signal
        try:
            os.killpg(proc.pid, _signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        # A stopped group holds SIGTERM as pending until continued — chase
        # with CONT so the graceful path works on it too (mirrors the
        # _spawn_ticking finally; SIGKILL there needs no chaser).
        try:
            os.killpg(proc.pid, _signal.SIGCONT)
        except (ProcessLookupError, PermissionError):
            pass

    # ---- internals -----------------------------------------------------------

    def _spawn(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None,
               clear_env: Sequence[str] = (), input_text: str | None = None,
               umask: int | None = None, timeout: float | None = None,
               quiet_stdout: bool = False) -> None:
        # env MERGE, not replace: subprocess.run(env=) replaces the whole
        # environment, but bash `env VAR=... cmd` overlays. clear_env carries
        # the `env -u` semantics (pnpm's XDG_* isolation depends on it —
        # REMOVED, not set empty).
        child_env = {k: v for k, v in os.environ.items() if k not in clear_env}
        child_env.update(env or {})
        # Mutations route child stdout to OUR stderr: installer chatter must
        # never leak into the machine channel (stdout is contract). Under a
        # TUI session fd 2 is dup2-captured, so the same routing lands the
        # chatter in the log capture with zero change here.
        sys.stderr.flush()
        out = subprocess.DEVNULL if quiet_stdout else sys.stderr.fileno()
        old_umask: int | None = None
        if umask is not None:
            old_umask = os.umask(umask)  # process-wide; converge is single-threaded
        # __main__ restores SIGPIPE to SIG_DFL (shell parity for `vide ls |
        # head`) — but under SIG_DFL a child that exits without draining its
        # stdin KILLS this process with signal 13 mid-converge; no except
        # clause ever runs. Ignore SIGPIPE around the feed so EPIPE surfaces
        # as the catchable BrokenPipeError (communicate() and the ticking
        # feed both swallow it; the child's exit code is the real story).
        import signal as _signal
        old_sigpipe = (_signal.signal(_signal.SIGPIPE, _signal.SIG_IGN)
                       if input_text is not None else None)
        try:
            if self._tick is None:
                proc = subprocess.run(list(argv), env=child_env,
                                      input=input_text, text=True,
                                      stdout=out, timeout=timeout, check=False)
                rc = proc.returncode
            else:
                rc = self._spawn_ticking(argv, child_env, out, input_text, timeout)
        finally:
            if old_sigpipe is not None:
                _signal.signal(_signal.SIGPIPE, old_sigpipe)
            if old_umask is not None:
                os.umask(old_umask)
        if rc != 0:
            raise CommandFailed(tuple(argv), rc)

    def _spawn_ticking(self, argv: Sequence[str], child_env: Mapping[str, str],
                       out: int, input_text: str | None,
                       timeout: float | None) -> int:
        """Popen + poll loop instead of subprocess.run, so the screen stays
        alive during long children. No output pipes AT ALL — children write
        straight to the (captured) fds, which is what makes this immune to the
        pipe-buffer deadlock and the grandchild-holds-the-write-end EOF trap
        that killed the drain-thread designs."""
        import signal as _signal
        import time as _time
        child = subprocess.Popen(
            list(argv), env=dict(child_env), text=True, stdout=out,
            # DEVNULL, never the inherited tty: apt restores termios on its
            # stdin when that is a tty (StopPtyMagic, Debian #555632), and
            # tcsetattr from a background group is an unconditional SIGTTOU
            # stop — the poll loop below would wait forever (the first live
            # smoke walk's hang). Children that must read are fed one-liners
            # via input_text → PIPE; the operator's keyboard belongs to
            # curses, so "no stdin" IS the ticking contract.
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            # Own SESSION (setsid), not merely own pgrp: a terminal ^C
            # (SIGINT to the fg group) must hit the wizard, which decides —
            # never dpkg mid-transaction. And the child must have NO
            # controlling tty at all: same-session children could re-acquire
            # it via open("/dev/tty") (ENXIO now — fail-loud, not
            # stop-silent), while a foreign-session child with an inherited
            # tty fd would SUCCEED in raw-moding the wizard's terminal with
            # ISIG off. killpg(child.pid) semantics are unchanged: a session
            # leader is its own pgrp leader.
            start_new_session=True)
        deadline = _time.monotonic() + timeout if timeout is not None else None
        self._current = child
        try:
            if input_text is not None:
                assert len(input_text) < 4096, "ticking stdin is for one-liners"
                assert child.stdin is not None
                # Written and CLOSED before the wait loop: a one-liner fits the
                # pipe buffer, so this cannot deadlock against child output
                # (which has no pipe to fill in the first place). A child that
                # exits without draining its stdin yields EPIPE here — that is
                # the child's failure, and its exit code (returned by the wait
                # loop below) is the story; the pipe error must not upstage it.
                try:
                    child.stdin.write(input_text)
                except BrokenPipeError:
                    pass
                finally:
                    try:
                        child.stdin.close()
                    except BrokenPipeError:
                        pass
            ticks = 0
            warned_stopped = False
            while True:
                rc = child.poll()
                if rc is not None:
                    return rc
                if deadline is not None and _time.monotonic() > deadline:
                    raise subprocess.TimeoutExpired(list(argv), timeout or 0)
                ticks += 1
                # Tripwire (~every 5s at the 100ms getch pacing): a stopped
                # child would otherwise be an invisible infinite spinner.
                # WARN-only — no auto-CONT (would fight an operator's
                # debugging SIGSTOP), no waitpid(WUNTRACED) (it would consume
                # the status Popen.poll() relies on).
                if ticks % 50 == 0 and not warned_stopped and _stopped(child.pid):
                    self._rep.warn(f"child pid {child.pid} is stopped (state T);"
                                   f" waiting — resume with: kill -CONT -{child.pid}")
                    warned_stopped = True
                self._tick()  # type: ignore[misc]  # non-None on this path
        finally:
            self._current = None
            if child.poll() is None:
                # tick raised (abort/Ctrl-C/SIGHUP) or timeout: never orphan
                # the group — but TERM first with a bounded grace, so dpkg
                # mid-transaction gets to close instead of dying -9.
                try:
                    os.killpg(child.pid, _signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                # TERM stays PENDING on a stopped group until it is continued;
                # without the CONT chaser the graceful path silently burns the
                # whole grace and falls to SIGKILL — dpkg dies -9 mid-write,
                # the exact outcome the grace exists to prevent.
                try:
                    os.killpg(child.pid, _signal.SIGCONT)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, _signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    child.wait()
