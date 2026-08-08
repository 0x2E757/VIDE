"""Fast tripwires on the unit/launcher socket literals and the SSO state
layout — a drift here is caught in <1s instead of a ~6-minute parity run, and
the phantom-instance trap (any /etc/vide/<x>.env is read back as an instance)
is pinned so no SSO path can plant one."""
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# `vide`, `fakes` and `test_sso_verbs` are imported at FUNCTION level below, so
# the paths they need must be set unconditionally at module level. They used to
# sit under `if __name__ == "__main__"`, which never executes under
# `python3 -m unittest <id>` — the form prove-teeth.sh uses. See
# TestUnitModulesAreStandalone.
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))


def _unit_text() -> str:
    return (REPO / "units" / "code-server@.service").read_text()


def _exec_start_post() -> str:
    """Every ExecStartPost= line of the instance unit, joined.

    SCOPED, and that is the whole point. The freeze this file pins is REQUIRED to
    carry its own rationale comment, and that comment necessarily contains the
    literals `chown root`, `2750` and `vide-proxy` — so an assertion over the
    whole file is satisfied by the paragraph explaining the fix and stays green
    with the ExecStartPost line deleted outright. Every assertion below runs
    against this text and never against the file."""
    lines = [ln for ln in _unit_text().splitlines() if ln.startswith("ExecStartPost=")]
    assert lines, "the instance unit has no ExecStartPost= line at all"
    return "\n".join(lines)


class TestUnitLauncherLiterals(unittest.TestCase):
    def _unit(self) -> str:
        return _unit_text()

    def _launch(self) -> str:
        return (REPO / "units" / "code-server-launch").read_text()

    def test_runtime_dir_is_private_until_root_takes_it(self) -> None:
        u = self._unit()
        self.assertIn("RuntimeDirectory=vide/%i", u)
        # 0700, not 0750. While the directory is the instance user's, its GROUP is
        # her primary group — a user-private group on a stock box, but a shared one
        # wherever USERGROUPS_ENAB is off or accounts come from a directory, where
        # 0750 would hand every member of it a shell as this instance for the
        # length of the start. Nothing needs those bits: the only principals that
        # traverse here are root, and caddy after the freeze grants it explicitly.
        self.assertIn("RuntimeDirectoryMode=0700", u)
        # ExecStartPOST, not Pre: systemd re-asserts RuntimeDirectory owner/mode
        # for the main ExecStart, which would undo a Pre chgrp.
        self.assertIn('ExecStartPost=+/bin/sh -c \'test -z "$${VIDE_SOCKET}"', u)
        self.assertNotIn("ExecStartPre=+/bin/sh -c 'test -z", u)

    def test_never_group_vide_proxy_on_instance_unit(self) -> None:
        # Group=vide-proxy would group-own every workspace file the user writes.
        for line in self._unit().splitlines():
            self.assertNotEqual(line.strip(), "Group=vide-proxy")

    def test_launcher_socket_branch(self) -> None:
        lz = self._launch()
        self.assertIn('--socket "$VIDE_SOCKET"', lz)
        self.assertIn("--socket-mode 0660", lz)
        self.assertIn('rm -f -- "$VIDE_SOCKET"', lz)
        # the VIDE_PORT guard must sit AFTER the socket branch so a socket
        # instance never trips it
        self.assertLess(lz.index("VIDE_SOCKET"), lz.index("VIDE_PORT:?"))

    def test_common_args_reach_both_bindings(self) -> None:
        # The two exec lines are the drift hazard: a flag added to one binding
        # and forgotten on the other is invisible until an operator runs the
        # mode nobody tested. Pin that BOTH expand the shared array.
        lz = self._launch()
        self.assertEqual(2, lz.count('"${common_args[@]}"'))
        self.assertIn("common_args=(--app-name VIDE)", lz)

    def test_workspace_trust_defaults_off_but_is_recoverable(self) -> None:
        # Disabling Workspace Trust is a security-control weakening, so it is
        # pinned in BOTH directions: off by default (what the operator asked
        # for), and restorable without editing VIDE (the knob). If either half
        # is dropped the row goes red — the default silently hardening is as
        # much a regression as the knob silently disappearing.
        lz = self._launch()
        self.assertIn("--disable-workspace-trust", lz)
        self.assertIn('"${VIDE_WORKSPACE_TRUST:-0}" != "1"', lz)
        # ...and the flag must be INSIDE the conditional, never unconditional.
        guard = lz.index('"${VIDE_WORKSPACE_TRUST:-0}" != "1"')
        self.assertLess(guard, lz.index("--disable-workspace-trust"))

    def test_vide_never_writes_the_trust_key_into_a_record(self) -> None:
        # The knob is environment-only BY DESIGN: writing it would change the
        # per-instance record's shape, which the parity tier byte-compares.
        from vide import contract
        for record in (contract.PORT_RECORD, contract.SOCKET_RECORD):
            self.assertNotIn("VIDE_WORKSPACE_TRUST", record)


class TestTheSocketDirectoryIsFrozen(unittest.TestCase):
    """/run/vide/<user> is created for the instance user (RuntimeDirectory +
    User=%i), so until root takes it away that user may unlink and rename every
    entry in it — the launcher's own `rm -f` proves VIDE relies on exactly that.
    Caddy re-resolves `reverse_proxy unix/<socket>` on every connection, so a
    symlink planted at that name points the operator's internet-facing Caddy at
    any socket on the box: another instance's `auth: none` IDE, or
    /run/caddy/admin.sock. These rows pin the ORDER that closes it."""

    def setUp(self) -> None:
        self.p = _exec_start_post()

    def test_the_directory_is_frozen_to_root(self) -> None:
        self.assertIn('chown root:vide-proxy "$$D"', self.p)
        self.assertIn("D=/run/vide/%i", self.p)

    def test_the_freeze_follows_the_socket_appearing(self) -> None:
        # Freezing before the bind would leave code-server unable to create the
        # socket at all: it runs as %i and needs write on that directory.
        self.assertLess(self.p.index('[ -e "$${VIDE_SOCKET}" ]'),
                        self.p.index('chown root:vide-proxy "$$D"'))

    def test_the_mode_is_narrowed_after_the_chown(self) -> None:
        # The pre-freeze OWNER can chmod the directory to 0777 a millisecond
        # before root's chown, and chown does not narrow a mode. chown-then-chmod
        # is the order; the other one leaves a root-owned world-writable dir.
        freeze = self.p.index('chown root:vide-proxy "$$D"')
        self.assertLess(freeze, self.p.rindex('chmod 2750 "$$D"'))

    def test_the_decisive_test_runs_after_the_freeze(self) -> None:
        # This is what converts check-then-act into act-then-check. Before the
        # freeze the path was swappable between the test and the chgrp, and both
        # dereference — /etc/shadow at 0660 root:vide-proxy was one swap away.
        freeze = self.p.index('chown root:vide-proxy "$$D"')
        check = self.p.index('[ -L "$${VIDE_SOCKET}" ]')
        relabel = self.p.index('chgrp vide-proxy "$${VIDE_SOCKET}"')
        self.assertLess(freeze, check)
        self.assertLess(check, relabel)

    def test_the_check_covers_hard_links_and_ownership_not_just_type(self) -> None:
        # `[ -S ] && [ ! -L ]` is TRUE of a hard link, and
        # renameat2(RENAME_EXCHANGE) installs one atomically.
        self.assertIn('stat -c "%%U %%h"', self.p)
        self.assertIn('!= "%i 1"', self.p)

    def test_the_stat_format_is_escaped_from_systemd(self) -> None:
        # %U is a systemd specifier (the unit user's numeric uid). Written `%U`,
        # `stat -c %U` silently becomes `stat -c <uid>` and the whole ownership
        # comparison collapses to a constant. This is the single most likely way
        # this fix ships broken, and no test that only reads `stat -c` sees it.
        self.assertNotIn('stat -c "%U', self.p)
        self.assertIn('"%%U %%h"', self.p)

    def test_the_check_compares_no_gettext_translated_field(self) -> None:
        """stat's `%F` is TRANSLATED. On a box whose /etc/default/locale sets a
        German LANG — which systemd exports into every service — `stat -c %F` on
        a socket prints `Socket`, so a comparison against `socket` refuses EVERY
        SSO start and the journal blames an attack that never happened. No tier
        would see it: they all run under C. It is also redundant, because `[ -S ]`
        and `[ ! -L ]` already say the same thing in the shell, in no language.

        `%U` is an NSS name and `%h` a number; neither is translated. This row
        exists because the field was in the shipped line for one commit."""
        for translated in ("%%F", "%%A", "%%C"):
            self.assertNotIn(translated, self.p,
                             f"stat's {translated[1:]} is gettext-translated — comparing it "
                             "makes the unit refuse to start under any non-C locale")

    def test_the_socket_path_is_pinned_to_the_directory_being_frozen(self) -> None:
        # The freeze targets $D; every later check reads $VIDE_SOCKET out of
        # /etc/vide/<user>.env. A record naming anything else would put the
        # relabel back on an unfrozen path — the whole bug, re-armed by a hand
        # edit. Pin them to each other before anything moves.
        guard = self.p.index('[ "$${VIDE_SOCKET}" != "$$D/code-server.sock" ]')
        self.assertLess(guard, self.p.index('chown root:vide-proxy "$$D"'))

    def test_caddy_is_granted_traversal_only_after_the_freeze(self) -> None:
        """VIDE must not hand Caddy the walk into a directory the instance user
        still owns.

        Group-owning the directory vide-proxy BEFORE the wait — which is how the
        socket would inherit the group at bind(2) — left it `2750
        <user>:vide-proxy` for the whole start: Caddy could already walk it and
        the instance user still owned it. She controls the ExecStart binary, so
        she holds that window open for the full budget, plants a symlink, and
        makes one request to her own hostname; Caddy follows it, and Caddy's
        per-address connection pool outlives the refusal that then fails the unit.

        THIS ROW IS A NARROWING, NOT THE CLOSURE, and saying so is the point: she
        owns the directory until the chown and an owner can always chmod, so
        `chmod o+x` still hands caddy the walk as `other`. What this pins is that
        VIDE does not do it FOR her, on every start, whether she asked or not. The
        residual is stated in docs/threat-model.md and SECURITY.md, and closing it
        needs the path Caddy dials to live in a directory she never owns."""
        freeze = self.p.index('chown root:vide-proxy "$$D"')
        for grant in re.finditer(r"vide-proxy", self.p):
            self.assertGreaterEqual(
                grant.start(), freeze,
                "a vide-proxy grant precedes the freeze — Caddy can traverse a "
                "directory the instance user still owns")

    def test_it_cannot_fail_open(self) -> None:
        # The historical shape: the loop fell out with `sleep 0.3` as the last
        # command and `sh` exited 0 — a silent fail-OPEN indistinguishable from
        # success in the journal.
        self.assertTrue(self.p.rstrip().endswith("'"))
        self.assertNotIn("done'", self.p)
        self.assertIn('if [ ! -e "$${VIDE_SOCKET}" ]; then', self.p)
        # exactly two clean exits: password mode, and the end of the happy path.
        self.assertEqual(1, self.p.count("exit 0"))

    def test_every_mutating_command_is_checked(self) -> None:
        # The count is asserted first, and that is not decoration: written as a
        # bare `for occurrence in finditer(...)` this row passes with ZERO
        # iterations, i.e. it goes green precisely when the command it guards has
        # been deleted. It shipped in that shape once.
        want = {'chmod 2750 "$$D"': 1,
                'chown root:vide-proxy "$$D"': 1,
                'chgrp vide-proxy "$${VIDE_SOCKET}"': 1,
                'chmod 0660 "$${VIDE_SOCKET}"': 1}
        for cmd, n in want.items():
            hits = list(re.finditer(re.escape(cmd), self.p))
            self.assertEqual(n, len(hits), f"{cmd} appears {len(hits)}x, expected {n}x")
            for occurrence in hits:
                tail = self.p[occurrence.end():occurrence.end() + 10]
                self.assertTrue(tail.startswith(" || exit 1"),
                                f"{cmd} is not followed by `|| exit 1` (found {tail!r})")

    def test_the_freeze_is_the_last_exec_command_of_the_start_job(self) -> None:
        # systemd re-runs its exec-directory setup before EVERY Exec* command and
        # chowns RuntimeDirectory back to User= — recursively, socket included
        # (systemd#12713). One more ExecStartPost= after this one silently undoes
        # the whole freeze and fails GREEN. There is no systemd directive that
        # enforces this; this row is the only thing standing between the control
        # and a one-line deletion nobody would notice.
        u = _unit_text()
        self.assertEqual(1, len([ln for ln in u.splitlines()
                                 if ln.startswith("ExecStartPost=")]))
        self.assertNotIn("\nExecReload=", u)

    def test_the_budget_is_bounded_by_both_ceilings(self) -> None:
        # The row that stops someone "fixing" a slow box by raising the budget
        # into a permanent restart loop. Same shape as the proxy's runway pin.
        u = _unit_text()
        iters = int(re.search(r'"\$\$n" -lt (\d+)', self.p).group(1))
        step = float(re.search(r"sleep ([\d.]+); done", self.p).group(1))
        budget = iters * step
        timeout = int(re.search(r"^TimeoutStartSec=(\d+)$", u, re.M).group(1))
        stop = int(re.search(r"^TimeoutStopSec=(\d+)$", u, re.M).group(1))
        burst = int(re.search(r"^StartLimitBurst=(\d+)$", u, re.M).group(1))
        restart = int(re.search(r"^RestartSec=(\d+)$", u, re.M).group(1))
        interval = int(re.search(r"^StartLimitIntervalSec=(\d+)$", u, re.M).group(1))
        self.assertGreaterEqual(budget, 20, "a cold code-server start needs more than this")
        self.assertLess(budget, timeout,
                        "the start job is killed before our refusal can name itself")
        # A whole cycle is start + STOP + gap. Leaving the stop half out — as the
        # first draft of this row did — models a restart with no shutdown, and one
        # wedged stop at the 90s TimeoutStopSec default is then enough to push the
        # fifth start outside the window and switch the burst limit off silently.
        self.assertLess(burst * (budget + stop + restart), interval,
                        "the burst limit is never reached, so a permanently stuck "
                        "instance restarts forever instead of landing in 'failed'")

    def test_the_payload_expands_nothing_systemd_would_not(self) -> None:
        # These two keep the behavioural driver below honest: they make its
        # substitution provably TOTAL for the text that exists, so it cannot be
        # running a different script than systemd does.
        stripped = self.p.replace("%%", "")
        self.assertEqual(["%i"], sorted(set(re.findall(r"%.", stripped))))
        self.assertIsNone(re.search(r"(?<!\$)\$(?!\$)", self.p))
        self.assertNotIn("'", self.p[self.p.index("'") + 1:-1])


class TestTheFreezeScriptRunsAsWritten(unittest.TestCase):
    """Text pins say the words are in the right order. This runs the actual
    payload under /bin/sh with chgrp/chmod/chown/sleep shimmed onto PATH, so the
    ORDER, the `|| exit 1` on every mutating command and — because sleep is a
    shim — the fail-closed 45s timeout are all exercised hermetically, in
    milliseconds. `stat` is deliberately NOT shimmed: the ownership and
    link-count check is the amendment these rows exist to prove, and a shimmed
    stat would prove nothing about it."""

    def _payload(self, runroot: Path, instance: str | None = None) -> str:
        p = _exec_start_post()
        p = p[p.index("'") + 1:p.rindex("'")]
        # One pass, exactly as systemd resolves specifiers: %% is a literal %,
        # %i is the instance name. Doing it in two passes would mishandle %%i.
        me = instance or __import__("pwd").getpwuid(os.getuid()).pw_name
        p = re.sub(r"%(.)", lambda m: me if m.group(1) == "i" else m.group(1), p)
        p = p.replace("$$", "$")
        # The payload hardcodes the runtime root; point it at a tmp tree. Assert
        # the substitution applied and applied ONCE — a rotted replace would run
        # against the real /run/vide and the arm would pass for a fixture reason.
        self.assertEqual(1, p.count("/run/vide"))
        return p.replace("/run/vide", str(runroot))

    def _shims(self, root: Path) -> Path:
        b = root / "bin"
        b.mkdir()
        for name in ("chgrp", "chmod", "chown", "sleep"):
            s = b / name
            s.write_text('#!/bin/sh\nn=${0##*/}\n'
                         'printf "%s %s\\n" "$n" "$*" >> "$VIDE_SHIM_LOG"\n'
                         'case " $VIDE_SHIM_FAIL " in *" $n "*) exit 1 ;; esac\n'
                         'exit 0\n')
            s.chmod(0o755)
        return b

    def _run(self, socket_value: str, *, fail: str = "", make=None, instance=None):
        import shutil
        import subprocess
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        me = instance or __import__("pwd").getpwuid(os.getuid()).pw_name
        runroot = tmp / "run"
        (runroot / me).mkdir(parents=True)
        payload = self._payload(runroot, instance)
        log = tmp / "log"
        log.write_text("")
        sock = runroot / me / "code-server.sock"
        if make is not None:
            make(sock, runroot / me)
        env = dict(os.environ,
                   PATH=f"{self._shims(tmp)}{os.pathsep}{os.environ['PATH']}",
                   VIDE_SHIM_LOG=str(log), VIDE_SHIM_FAIL=fail,
                   VIDE_SOCKET=(str(sock) if socket_value == "@" else socket_value))
        # VIDE_SOCKET reaches the real unit through EnvironmentFile, not the
        # shell — but the shell reads it from the environment either way, which
        # is exactly what this models.
        proc = subprocess.run(["/bin/sh", "-c", payload], env=env,
                              capture_output=True, text=True, timeout=120)
        return proc, [ln.split() for ln in log.read_text().splitlines()]

    @staticmethod
    def _bind(path: Path) -> None:
        import socket as _s
        s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        s.bind(str(path))
        # keep it open for the life of the test; the inode is what matters
        TestTheFreezeScriptRunsAsWritten._held.append(s)

    _held: list = []

    def tearDown(self) -> None:
        for s in self._held:
            s.close()
        self._held.clear()

    def test_a_real_socket_is_frozen_then_relabelled_in_that_order(self) -> None:
        proc, log = self._run("@", make=lambda sock, d: self._bind(sock))
        self.assertEqual(0, proc.returncode, proc.stderr)
        verbs = [(c[0], c[1]) for c in log if c[0] != "sleep"]
        self.assertEqual(
            [("chown", "root:vide-proxy"), ("chmod", "2750"),
             ("chgrp", "vide-proxy"), ("chmod", "0660")], verbs)
        # and the socket is relabelled strictly AFTER the directory is frozen
        froze = next(i for i, c in enumerate(log) if c[0] == "chown")
        touched = next(i for i, c in enumerate(log)
                       if c[0] == "chgrp" and c[-1].endswith("code-server.sock"))
        self.assertLess(froze, touched)
        # THE SETTLE, behaviourally: the socket exists on the first look, so the
        # only sleep on this path is the settle — and it must fall between the
        # wait and the freeze. code-server chmods its socket to --socket-mode
        # AFTER bind, and once the directory is frozen it can no longer resolve
        # its own socket path, so freezing inside that window hands it EACCES on
        # its own chmod. Without this the settle is a line no test would miss.
        sleeps = [i for i, c in enumerate(log) if c[0] == "sleep"]
        self.assertEqual(1, len(sleeps), f"expected exactly the settle, got {log}")
        self.assertLess(sleeps[0], froze)

    def test_a_socket_owned_by_someone_else_is_refused(self) -> None:
        # The `%U` half, falsified. The instance name the unit was templated for
        # is not the owner of the inode at the path, which is what a socket moved
        # or linked in from elsewhere looks like. Nothing else in this class can
        # go red for this reason: every other arm binds as the expected user.
        proc, log = self._run("@", instance="somebodyelse",
                              make=lambda sock, d: self._bind(sock))
        self.assertEqual(1, proc.returncode)
        self.assertIn("not a plain singly-linked socket", proc.stderr)
        self.assertFalse([c for c in log
                          if c[0] == "chgrp" and c[-1].endswith("code-server.sock")])

    def test_a_socket_that_never_appears_fails_the_unit(self) -> None:
        # The historical fail-OPEN: the loop fell out and `sh` exited 0, leaving
        # the directory writable by the instance user with nothing said.
        proc, log = self._run("@")
        self.assertEqual(1, proc.returncode)
        self.assertIn("did not bind", proc.stderr)
        self.assertEqual(150, sum(1 for c in log if c[0] == "sleep"))
        self.assertFalse([c for c in log if c[0] == "chown"])

    def test_a_symlinked_socket_is_refused_after_the_freeze(self) -> None:
        def make(sock, d):
            real = d / "real.sock"
            self._bind(real)
            sock.symlink_to(real)
        proc, log = self._run("@", make=make)
        self.assertEqual(1, proc.returncode)
        self.assertIn("not a plain singly-linked socket", proc.stderr)
        # the freeze still landed — it must, or the refusal leaves the directory
        # in the attacker's hands — but nothing was relabelled
        self.assertTrue([c for c in log if c[0] == "chown"])
        self.assertFalse([c for c in log
                          if c[0] == "chgrp" and c[-1].endswith("code-server.sock")])

    def test_a_hard_linked_socket_is_refused(self) -> None:
        # The row nobody would think to write. `[ -S ] && [ ! -L ]` is TRUE of a
        # hard link and renameat2(RENAME_EXCHANGE) installs one atomically, so
        # type alone was never enough — this is what `%h == 1` buys.
        def make(sock, d):
            real = d / "real.sock"
            self._bind(real)
            os.link(real, sock)
        proc, log = self._run("@", make=make)
        self.assertEqual(1, proc.returncode)
        self.assertIn("not a plain singly-linked socket", proc.stderr)
        self.assertFalse([c for c in log
                          if c[0] == "chgrp" and c[-1].endswith("code-server.sock")])

    def test_a_record_naming_another_path_is_refused_before_anything_moves(self) -> None:
        proc, log = self._run("/tmp/elsewhere.sock")
        self.assertEqual(1, proc.returncode)
        self.assertIn("not", proc.stderr)
        self.assertEqual([], log)

    def test_a_failed_freeze_never_reaches_the_relabel(self) -> None:
        proc, log = self._run("@", fail="chown", make=lambda sock, d: self._bind(sock))
        self.assertEqual(1, proc.returncode)
        self.assertFalse([c for c in log
                          if c[0] == "chgrp" and c[-1].endswith("code-server.sock")])

    def test_password_mode_is_a_no_op(self) -> None:
        # The short-circuit that keeps password instances — and the byte-frozen
        # integration tier — entirely out of this.
        proc, log = self._run("")
        self.assertEqual(0, proc.returncode)
        self.assertEqual([], log)


class TestProxyUnitLiterals(unittest.TestCase):
    def _u(self) -> str:
        return (REPO / "units" / "oauth2-proxy.service").read_text()

    def test_identity_and_config(self) -> None:
        u = self._u()
        self.assertIn("User=vide-oauth2", u)
        self.assertIn("EnvironmentFile=/etc/vide/sso/proxy.env", u)
        self.assertNotIn("EnvironmentFile=-", u)  # missing env must fail loudly
        self.assertIn("--config /etc/vide/sso/proxy.toml", u)

    def test_hardening_and_least_privilege(self) -> None:
        u = self._u()
        # The full hardening block: rootless podman can't RUN these (the sso gate
        # drops them in a relaxation), so this static pin is the ONLY automated
        # guard that the shipped unit keeps them — pin the whole set, not a
        # sample, or a silent deletion goes unnoticed.
        for directive in (
            "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
            "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
            "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
            "ProtectProc=invisible", "RestrictAddressFamilies=AF_INET AF_INET6",
            "RestrictNamespaces=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes",
            "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
            "CapabilityBoundingSet=", "SystemCallFilter=@system-service",
            "SystemCallArchitectures=native", "SystemCallErrorNumber=EPERM",
            "UMask=0077",
        ):
            self.assertIn(directive, u, f"shipped proxy unit lost hardening: {directive}")
        # the proxy never touches instance sockets -> not in the group
        for line in u.splitlines():
            self.assertNotEqual(line.strip(), "Group=vide-proxy")

    def test_survives_a_boot_where_the_issuer_is_slow(self) -> None:
        # Regression pin for the 2026-07-27 reboot finding: oauth2-proxy resolves
        # its OIDC issuer AT STARTUP and exits 1 when that fails. With no network
        # ordering and a 5x3s budget, a boot that reaches DNS late left the SOLE
        # SSO gate in 'failed' permanently — IDEs healthy, nobody able to log in.
        u = self._u()
        self.assertIn("Wants=network-online.target", u)
        self.assertIn("After=network-online.target", u)
        # THE RUNWAY IS NOW UNBOUNDED, AND THE BOUND IS WHAT HAD TO GO.
        # This used to assert a PRODUCT — StartLimitBurst x RestartSec >= 60 —
        # and then that the product stayed inside StartLimitIntervalSec, so a
        # genuinely bad config would land in 'failed' rather than hammer forever.
        # Landing in 'failed' is exactly what may no longer happen: systemd
        # propagates a service's start_limit_hit to the socket unit that triggers
        # it (SOCKET_FAILURE_SERVICE_START_LIMIT_HIT), a failed socket unit calls
        # socket_close_fds(), and the fleet's authorization port is then free for
        # any local account to bind. The old numbers reached that in ~100s on the
        # very boot this test is named for.
        #
        # So the assertion inverts: there must be NO start limit at all, and the
        # absence is asserted rather than the presence of a bigger number,
        # because "bigger" is still reachable.
        self.assertRegex(u, r"(?m)^StartLimitIntervalSec=0$")
        self.assertIsNone(
            re.search(r"^StartLimitBurst=", u, re.M),
            "a start limit on this unit hands the fleet's authorization port back "
            "to the box when it fires — see the four-link chain in the unit")
        # Restart=always, not on-failure: a clean exit(0) is a resting state
        # on-failure does not cover, and this process is the fleet's sole gate.
        self.assertRegex(u, r"(?m)^Restart=always$")
        sec = int(re.search(r"^RestartSec=(\d+)$", u, re.M).group(1))
        self.assertGreaterEqual(sec, 1)
        self.assertLessEqual(
            sec, 10,
            "RestartSec paces an unbounded retry loop now; a long one turns a "
            "transient resolver failure into a long outage with no limiter to "
            "surface it")
        # The observability the limiter used to provide has to exist somewhere,
        # and NRestarts is where it went. Pin that BOTH halves are present — the
        # reader in the host-read seam and a consumer in doctor — because either
        # alone is dead code: a reader nobody calls, or a call to a reader that
        # does not exist. Without this, a permanently broken proxy sits in
        # `activating (auto-restart)` looking healthier than a failed one, and
        # nothing in the tree says so.
        self.assertIn("def unit_n_restarts",
                      (REPO / "src" / "vide" / "system.py").read_text())
        self.assertIn("system.unit_n_restarts",
                      (REPO / "src" / "vide" / "oauth2proxy.py").read_text())

    def test_instance_unit_keeps_its_no_network_rationale(self) -> None:
        # The proxy's fix must NOT be copy-pasted here: code-server really does
        # bind loopback and needs no upstream to start, so ordering it after
        # network-online would only delay first boot for nothing.
        u = (REPO / "units" / "code-server@.service").read_text()
        self.assertNotIn("After=network-online.target", u)


class TestATemplateChangeIsAnnounced(unittest.TestCase):
    """A converge deliberately restarts no instance — installing user B must not
    drop A, C and D — so a template change is LATENT: each instance picks it up at
    its next restart, which unattended means all of them at the next reboot. Since
    the freeze the template can FAIL a start, so an operator who was not told is an
    operator who finds out from a reboot."""

    def _warnings(self, tmp: Path, pre_existing: str | None, *,
                  dry_run: bool = False) -> list[str]:
        import shutil
        from fakes import RecordingExecutor, make_config, quiet_reporter
        from vide import sysd
        from vide.executor import Executor
        (tmp / "units").mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / "units" / "code-server@.service", tmp / "units")
        cfg = make_config(tmp)
        Path(cfg.unit_path).parent.mkdir(parents=True, exist_ok=True)
        if pre_existing is not None:
            Path(cfg.unit_path).write_text(pre_existing)
        rep = quiet_reporter()
        seen: list[str] = []
        rep.warn = seen.append          # type: ignore[method-assign]
        # The REAL Executor for the dry-run arm: dry_run is its own property, and
        # a double asserting it would be a double asserting itself.
        ex = Executor(dry_run=True, reporter=rep, cfg=cfg) if dry_run else RecordingExecutor()
        sysd.install_unit(cfg, ex, rep)
        return seen

    def test_a_changed_template_says_a_restart_is_owed(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            seen = self._warnings(Path(t), "[Service]\nExecStart=/bin/true\n")
        self.assertTrue(any("no instance was restarted" in w for w in seen), seen)
        self.assertTrue(any("ONE" in w for w in seen), seen)

    def test_a_first_install_says_nothing(self) -> None:
        # There is nothing to restart: enable_start is about to start the only
        # instance there is, on the new template. A warning printed where no
        # action is possible is how a warning gets ignored on the day it matters.
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual([], self._warnings(Path(t), None))

    def test_a_dry_run_says_nothing(self) -> None:
        # Nothing was written, so no restart is owed. The proxy's named twin
        # excludes the preview for the same reason: a dry run that prints an
        # action item the operator cannot act on teaches them that the preview
        # says things which are not true.
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual([], self._warnings(Path(t), "[Service]\nExecStart=/bin/true\n",
                                                dry_run=True))

    def test_an_unchanged_template_says_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            same = (REPO / "units" / "code-server@.service").read_text()
            self.assertEqual([], self._warnings(Path(t), same))


class TestRecordShapes(unittest.TestCase):
    def test_socket_record_has_no_port(self) -> None:
        from vide import contract
        rec = contract.SOCKET_RECORD.format(socket="/run/vide/u/code-server.sock",
                                            fqdn="u.example.com")
        self.assertIn("VIDE_MODE=sso", rec)
        self.assertIn("VIDE_FQDN=u.example.com", rec)
        self.assertNotIn("VIDE_PORT", rec)

    def test_port_record_unchanged(self) -> None:
        from vide import contract
        self.assertEqual(contract.PORT_RECORD, "VIDE_PORT={port}\n")


class TestPhantomInstanceTrap(unittest.TestCase):
    def test_sso_state_never_plants_a_toplevel_env(self) -> None:
        # registry.list_instances globs state_dir/*.env — anything there is an
        # instance. All SSO fleet state must live UNDER sso_dir (a subdir), never
        # as /etc/vide/<x>.env. Exercise a full allow + proxy state write and
        # assert only the instance record itself lands at the top level.
        from fakes import make_config, quiet_reporter
        from vide import sso
        from test_sso_verbs import _FsExecutor  # reuse the fs-backed executor

        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
            sso.claim_binding(cfg, _FsExecutor(), quiet_reporter(), "alice")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "alice", "a@x.com")
            top_envs = sorted(p.name for p in cfg.state_dir.glob("*.env"))
            # exactly the instance record; fleet.env lives under sso_dir, not here
            self.assertEqual(top_envs, ["alice.env"])
            self.assertTrue((Path(cfg.sso_dir) / "fleet.env").exists())


class TestTheReservationUnitCannotBeMadeToLetGo(unittest.TestCase):
    """units/oauth2-proxy.socket is the whole port fix, and every line in it that
    matters is a line that LOOKS removable.

    The unit reserves the fleet's authorization address as PID 1 so no local
    account can bind it while the proxy is stopped, restarting or crash-looping.
    A failed socket unit calls socket_close_fds() and hands the address straight
    back, so the three directives below are not tuning — each one disables one
    documented path to `failed`. They read like rate limits somebody forgot to
    set, which is exactly why they need a row that goes red when a future tuner
    'restores' them."""

    def _s(self) -> str:
        return (REPO / "units" / "oauth2-proxy.socket").read_text()

    def test_both_rate_limiters_are_disabled_on_the_socket(self) -> None:
        s = self._s()
        # trigger-limit-hit: the default is 20 activations per 2s, and systemd's
        # own words are that hitting it puts the unit in a failure mode where it
        # "will not be connectible anymore until restarted". One code-server page
        # load makes more than 20 forward_auth sub-requests.
        self.assertRegex(s, r"(?m)^TriggerLimitIntervalSec=0$")
        # start-limit-hit: the socket's OWN limiter (5 starts / 10s by default),
        # reachable during recovery — the service's Requires= re-attempts this
        # unit on every auto-restart once it is down.
        self.assertRegex(s, r"(?m)^StartLimitIntervalSec=0$")

    def test_exactly_one_listen_stream_because_fd_3_is_an_index(self) -> None:
        """`http_address = "fd:3"` is a POSITION, not a name: oauth2-proxy computes
        fdIndex = fd - SD_LISTEN_FDS_START and takes that slot from the list
        systemd passed, in ListenStream= order. A second directive — an IPv6
        twin, a metrics port — shifts the index and repoints the fleet's
        authorization gate at the wrong socket, silently. The named form is not an
        escape: upstream returns "fd with name is not implemented yet"."""
        s = self._s()
        listens = re.findall(r"(?m)^ListenStream=(.*)$", s)
        self.assertEqual(len(listens), 1, f"exactly one ListenStream=, got {listens}")
        # The LITERAL address, never a bare port: `ListenStream=4180` binds
        # [::]:4180 — the whole internet — on the one unit where that mistake is
        # not recoverable by a reload.
        self.assertTrue(listens[0].startswith("127.0.0.1:"), listens[0])
        # DIRECTIVE lines only, never a substring search: the rationale comments
        # in this file name every directive they explain — including the ones
        # deliberately absent — so a whole-file `assertNotIn` reports the
        # explanation as the offence. That is not a quirk of this test; dense
        # comments beside the code are the house style, so every absence
        # assertion in this class has to be anchored.
        self.assertNotRegex(s, r"(?m)^FileDescriptorName=")
        toml = (REPO / "src" / "vide" / "oauth2proxy.py").read_text()
        self.assertIn('http_address = "fd:3"', toml)

    def test_the_directives_that_would_reopen_the_hole_are_absent(self) -> None:
        s = self._s()
        # SO_REUSEPORT lets a SECOND process bind the same address alongside
        # systemd — the exact hole, reopened, with no error anywhere.
        self.assertNotRegex(s, r"(?m)^ReusePort=")
        # StopWhenUnneeded= frees the port whenever the service is not running,
        # i.e. during precisely the crash loop the reservation exists for.
        self.assertNotRegex(s, r"(?m)^StopWhenUnneeded=")

    def test_it_binds_at_sockets_target_which_is_the_boot_window(self) -> None:
        """The service is ordered after network-online because OIDC discovery
        needs DNS; the BIND needs nothing but loopback. That split is the fix —
        sockets.target is reached before basic.target, therefore before any login
        session, cron job or lingering user unit exists. Being pulled in by the
        service's Requires= is not equivalent: it would bind at multi-user.target
        time instead, silently downgrading an early reservation to a late one."""
        s = self._s()
        self.assertRegex(s, r"(?m)^WantedBy=sockets\.target$")
        # Anchored for the same reason as above — the comment explaining WHY the
        # network ordering is absent necessarily contains the words.
        self.assertNotRegex(s, r"(?m)^(Wants|After|Requires)=.*network-online")
        svc = (REPO / "units" / "oauth2-proxy.service").read_text()
        self.assertRegex(svc, r"(?m)^Requires=vide-oauth2-proxy\.socket$")
        self.assertRegex(svc, r"(?m)^After=vide-oauth2-proxy\.socket$")

    def test_the_port_sentinel_appears_exactly_once(self) -> None:
        """A rotted sentinel renders a unit still containing the literal token,
        which systemd refuses to parse — so the reservation would simply never
        exist while every VIDE verb reported success."""
        from vide import oauth2proxy
        self.assertEqual(self._s().count(oauth2proxy.SOCKET_PORT_SENTINEL), 1)

    def test_no_vide_code_path_stops_or_restarts_the_socket_unit(self) -> None:
        """Requires= propagates BOTH ways: restarting the socket takes the fleet's
        gate down with it, and stopping it frees the address. Neither is ever the
        right thing for VIDE to do on its own, so this is a census rather than a
        convention — `enable` and `start` are the only verbs allowed near it."""
        src = REPO / "src" / "vide"
        offenders = []
        for f in sorted(src.rglob("*.py")):
            for i, line in enumerate(f.read_text().splitlines(), 1):
                if "SOCKET_UNIT" not in line:
                    continue
                if re.search(r'"(stop|restart)"', line):
                    offenders.append(f"{f.name}:{i}: {line.strip()}")
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
