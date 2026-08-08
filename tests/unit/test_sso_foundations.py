"""Phase-1 foundations: Binding, the socket probe pairing, the cookie-secret
encoding, and parse_env_text. Pure value-level pins — the teeth on the render
and verb layers live in test_sso_render / test_sso_verbs and prove-teeth."""
from __future__ import annotations

import base64
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest import mock

# Self-sufficient on purpose — see the note in test_sso_render.py: a bare
# `from fakes import …` made this module importable only through run.py, which
# silently defeated every prove-teeth row that names it.
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import make_config  # noqa: E402
from vide import contract, oauth2proxy, registry, secrets, system  # noqa: E402
from vide.config import parse_env_text  # noqa: E402


class TestBootstrapNeeded(unittest.TestCase):
    """D2/D4: requiredness keys on credentials_needed = provisioned AND
    credentials_recorded, never the fail-open three-file provisioned() alone."""

    def _provision(self, cfg, *, secret="GOCSPX-x", cookie="cook", toml=True):
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        if toml:
            oauth2proxy.toml_path(cfg).write_text("# toml\n")
        oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
            "c.apps.googleusercontent.com", secret, cookie))
        Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).write_text("x")

    def test_fresh_box_needs_bootstrap(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            self.assertFalse(oauth2proxy.credentials_recorded(cfg))
            self.assertTrue(oauth2proxy.credentials_needed(cfg))

    def test_fully_credentialed_proxy_needs_no_bootstrap(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            self._provision(cfg)
            self.assertTrue(oauth2proxy.provisioned(cfg))
            self.assertTrue(oauth2proxy.credentials_recorded(cfg))
            self.assertFalse(oauth2proxy.credentials_needed(cfg))

    def test_torn_env_empty_secret_reads_provisioned_but_needs_bootstrap(self):
        # the D2 hole: three files exist (provisioned() True) but the client
        # secret is empty, so the proxy could never authenticate — it must be
        # re-affirmed, not silently inherited.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            self._provision(cfg, secret="")
            self.assertTrue(oauth2proxy.provisioned(cfg))
            self.assertFalse(oauth2proxy.credentials_recorded(cfg))
            self.assertTrue(oauth2proxy.credentials_needed(cfg))

    def test_missing_toml_needs_bootstrap(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            self._provision(cfg, toml=False)
            self.assertFalse(oauth2proxy.provisioned(cfg))
            self.assertTrue(oauth2proxy.credentials_needed(cfg))


class TestBinding(unittest.TestCase):
    def test_tcp_display_is_the_bare_port(self) -> None:
        self.assertEqual(registry.Binding.tcp(9797).display, "9797")

    def test_unix_display_is_the_distinct_token_not_question_mark(self) -> None:
        d = registry.Binding.unix(Path("/run/vide/u/code-server.sock")).display
        self.assertEqual(d, "unix")
        self.assertNotEqual(d, "?")

    def test_unknown_display_is_question_mark(self) -> None:
        self.assertEqual(registry.Binding.unknown().display, "?")

    def test_mode_absent_record_is_password(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "alice.env").write_text("VIDE_PORT=9800\n")
            self.assertEqual(registry.instance_mode(cfg, "alice"), "password")
            self.assertEqual(registry.instance_binding(cfg, "alice"),
                             registry.Binding.tcp(9800))

    def test_mode_sso_record(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "bob.env").write_text(
                "VIDE_MODE=sso\nVIDE_SOCKET=/run/vide/bob/code-server.sock\n")
            self.assertEqual(registry.instance_mode(cfg, "bob"), "sso")
            b = registry.instance_binding(cfg, "bob")
            self.assertEqual(b.kind, "unix")
            self.assertEqual(b.socket, Path("/run/vide/bob/code-server.sock"))

    def test_missing_record_is_none_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.state_dir.mkdir(parents=True)
            self.assertIsNone(registry.instance_mode(cfg, "ghost"))
            self.assertEqual(registry.instance_binding(cfg, "ghost").kind, "unknown")


class TestCookieSecret(unittest.TestCase):
    def test_decodes_to_exactly_32_bytes(self) -> None:
        s = secrets.gen_cookie_secret()
        # url-safe, no padding, 43 chars — always an AES-256 key
        self.assertEqual(len(s), 43)
        self.assertNotIn("=", s)
        decoded = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        self.assertEqual(len(decoded), 32)

    def test_is_url_safe_alphabet(self) -> None:
        s = secrets.gen_cookie_secret()
        self.assertTrue(all(c.isalnum() or c in "-_" for c in s), s)

    def test_distinct_each_call(self) -> None:
        self.assertNotEqual(secrets.gen_cookie_secret(), secrets.gen_cookie_secret())


class TestSocketPath(unittest.TestCase):
    def test_deterministic_per_user(self) -> None:
        self.assertEqual(str(system.socket_path("alice")),
                         "/run/vide/alice/code-server.sock")

    def test_sun_path_ceiling_guarded(self) -> None:
        from vide.errors import ConfigError
        with self.assertRaises(ConfigError):
            system.socket_path("x" * 90, run_dir=Path("/run/vide"))


class _UnixHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class TestUnixHealthProbe(unittest.TestCase):
    """A real AF_UNIX HTTP server proves the HTTPConnection-over-unix path, and
    the stat pairing is proven separately: a healthy socket at the wrong mode
    must fail instance_health even though the HTTP GET succeeds."""

    def _serve(self, sock_path: str):
        from http.server import HTTPServer

        class UnixServer(HTTPServer):
            address_family = socket.AF_UNIX

        srv = UnixServer(sock_path, _UnixHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv

    def test_healthz_unix_true_on_200(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            sp = str(Path(t) / "s.sock")
            srv = self._serve(sp)
            try:
                self.assertTrue(system.healthz_unix(sp))
            finally:
                srv.shutdown()

    def test_healthz_unix_false_on_missing_socket(self) -> None:
        self.assertFalse(system.healthz_unix("/nonexistent/x.sock", timeout=1.0))

    def test_socket_stat_reports_mode(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            sp = Path(t) / "s.sock"
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(str(sp))
            try:
                st = system.socket_stat(sp)
                self.assertIsNotNone(st)
                self.assertTrue(st.is_socket)
            finally:
                s.close()

    def test_socket_stat_none_when_absent(self) -> None:
        self.assertIsNone(system.socket_stat("/nonexistent/x.sock"))


class TestSocketPermGate(unittest.TestCase):
    """instance_health pairs the HTTP probe with a perms check: root's probe
    bypasses 0660, so a world-writable socket that still answers must be
    reported UNHEALTHY (the perms ARE the authz policy)."""

    def test_wrong_mode_socket_is_unhealthy_even_if_it_answers(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "u.env").write_text(
                "VIDE_MODE=sso\nVIDE_SOCKET=/run/vide/u/code-server.sock\n")
            good = system.SocketStat(is_socket=True, uid=1000, gid=1000, mode=0o660)
            bad = system.SocketStat(is_socket=True, uid=1000, gid=1000, mode=0o666)
            with mock.patch.object(registry.system, "healthz_unix", return_value=True):
                with mock.patch.object(registry.system, "socket_stat", return_value=good):
                    self.assertTrue(registry.instance_health(cfg, "u"))
                with mock.patch.object(registry.system, "socket_stat", return_value=bad):
                    self.assertFalse(registry.instance_health(cfg, "u"),
                                     "a 0666 socket must be unhealthy despite answering")


class TestProcessStartTimeIsNotTheInodeStamp(unittest.TestCase):
    """The reader this replaced answered with /proc/<pid>'s own mtime — which is
    the INODE's creation time, and procfs allocates that inode lazily at lookup
    and restamps it whenever the dentry is reclaimed. So the one predicate that
    decides whether to restart the fleet's sole authorization gate could be told
    that a process which has been up for a week started thirty seconds ago, and
    the error runs in the DECLINING direction: the migration silently never
    lands and every verb reports success.

    A hermetic /proc, built here rather than borrowed from the machine. The
    `proc_root` parameter has existed since the first version of this reader and
    nobody had ever passed it — which is why this whole class is new and why the
    defect it covers survived a green suite."""

    # `getattr` rather than a bare call: the PRODUCT treats this as fallible
    # (system.proc_start_realtime catches ValueError/OSError around it), and a
    # bare call at class-body scope makes an unknown name a whole-MODULE
    # collection error rather than one red row — which matters because "which
    # rows are red" is this round's measurement channel. 100 is USER_HZ on every
    # supported box; the rows below derive from whatever this reports, so the
    # arithmetic stays right either way.
    HZ = getattr(os, "sysconf", lambda _n: 100)("SC_CLK_TCK")
    BTIME = 1_700_000_000
    #: SEVEN WHOLE SECONDS after boot, and the multiplication is deliberate: the
    #: expectation is then the constant `BTIME + 7.0` rather than a copy of the
    #: product's own division, which would agree with any HZ the product happened
    #: to use — including the wrong one.
    TICKS = 7 * HZ

    #: /proc/<pid>/stat fields 3..52, i.e. everything AFTER comm. Field 20
    #: (num_threads, index 17 here) is 3 rather than 0 on purpose: it is what a
    #: naive `line.split()[19]` reads instead of field 22, so the wrong-column
    #: parse produces a WRONG answer rather than accidentally the right one.
    _NUM_THREADS_IDX = 20 - 3
    _STARTTIME_IDX = 22 - 3

    def _proc(self, t: Path, *, pid=4242, comm="(oauth2-proxy)", starttime=None,
              btime=BTIME, stat_line=None) -> Path:
        root = Path(t) / "proc"
        (root / str(pid)).mkdir(parents=True, exist_ok=True)
        rest = ["0"] * 50
        rest[self._NUM_THREADS_IDX] = "3"
        rest[self._STARTTIME_IDX] = str(self.TICKS if starttime is None else starttime)
        line = stat_line if stat_line is not None else \
            f"{pid} {comm} " + " ".join(rest) + "\n"
        (root / str(pid) / "stat").write_text(line)
        # btime is deliberately NOT the first line: an implementation that
        # indexed a line rather than searching for the key would pass against a
        # fixture that put it first, and fail on every real box.
        body = "cpu  1 2 3 4 5 6 7 8\nintr 100 0 0\nctxt 12345\n"
        if btime is not None:
            body += f"btime {btime}\n"
        body += "processes 999\n"
        (root / "stat").write_text(body)
        return root

    def test_the_answer_is_boot_time_plus_the_processs_own_start(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            root = self._proc(Path(t))
            self.assertEqual(system.proc_start_realtime(4242, root),
                             self.BTIME + 7.0)

    def test_restamping_the_proc_directory_does_not_move_the_answer(self) -> None:
        """THE row that pins the whole reason for the change, and the only place
        the reclaim-restamp failure mode is observable without a kernel.

        Asserted against the absolute `BTIME + 7.0` and not merely "the two reads
        agree" — two equally wrong reads satisfy that."""
        with tempfile.TemporaryDirectory() as t:
            root = self._proc(Path(t))
            first = system.proc_start_realtime(4242, root)
            os.utime(root / "4242", (self.BTIME + 10_000, self.BTIME + 10_000))
            second = system.proc_start_realtime(4242, root)
            self.assertEqual(first, self.BTIME + 7.0)
            self.assertEqual(second, first,
                             "restamping /proc/<pid> moved the reported start "
                             "time — the gate's age is being read off an inode "
                             "the kernel recreates under memory pressure")

    def test_a_comm_with_spaces_and_parens_does_not_shift_the_field(self) -> None:
        """proc(5)'s one parsing trap. comm is printed RAW between parentheses:
        it is a filename, so it may contain spaces AND ')'. A `split()` is then
        off by two and the answer is plausible, wrong, and silent."""
        with tempfile.TemporaryDirectory() as t:
            root = self._proc(Path(t), comm="(oauth2 proxy (old))")
            self.assertEqual(system.proc_start_realtime(4242, root),
                             self.BTIME + 7.0)

    def test_a_process_that_vanished_between_the_pid_read_and_the_stat_is_None(self) -> None:
        """The gate can restart between `unit_main_pid` and this call, and
        `upgrade-sso` may not become a traceback for it."""
        with tempfile.TemporaryDirectory() as t:
            root = self._proc(Path(t))
            self.assertIsNone(system.proc_start_realtime(9999, root))

    def test_a_proc_without_btime_is_None_rather_than_a_guess(self) -> None:
        """Fail-safe direction: an unknown boot anchor must not become a licence
        to bounce the fleet's gate. Without btime the number would be seconds
        since BOOT, so every file on the box outranks every process and `stale`
        is permanently true."""
        with tempfile.TemporaryDirectory() as t:
            root = self._proc(Path(t), btime=None)
            self.assertIsNone(system.proc_start_realtime(4242, root))

    def test_an_unreadable_start_time_is_None_rather_than_an_exception(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            rest = ["0"] * 50
            rest[self._STARTTIME_IDX] = "x"
            root = self._proc(Path(t),
                              stat_line="4242 (oauth2-proxy) " + " ".join(rest) + "\n")
            self.assertIsNone(system.proc_start_realtime(4242, root))

    def test_a_truncated_stat_line_is_None_rather_than_an_IndexError(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            root = self._proc(Path(t), stat_line="4242 (oauth2-proxy) S 1\n")
            self.assertIsNone(system.proc_start_realtime(4242, root))


class TestWhoHoldsTheFleetsPort(unittest.TestCase):
    """The holder reader is the only signal in the reservation section that
    separates systemd from an attacker, `usurped` and `holds` both rest on it,
    and it had no parser test of any kind for two rounds.

    IT READS THE KERNEL'S OWN TABLE, and that is the property these rows exist
    to keep. The reader this replaced parsed `ss -Htlnp`, whose process column
    renders `users:(("<comm>",pid=N,fd=M))` — and <comm> is set by the process
    itself through prctl(PR_SET_NAME), no privilege needed. A squatter naming
    itself the five characters `pid=1` put a 1 into any regex over that line and
    thereby earned the affirmative reservation row over a live squat. Here the
    answer is a uid the kernel wrote into its own column, and the threat this
    release names — "any local account, no VIDE instance, no role, no sudo" —
    cannot make it read 0.

    A hermetic /proc rather than the machine's, through the same `proc_root`
    seam the start-time reader carries."""

    PORT = 4180
    #: Addresses as /proc/net/tcp renders them on a little-endian box, which is
    #: every box VIDE supports. Written out rather than computed from the
    #: product's own helper: a test that derives the expectation the same way
    #: the code does agrees with the code about being wrong.
    #:
    #: The v6 forms are PER-WORD host byte order, not a big-endian string — the
    #: kernel prints four `%08X` of the in-memory u32s. `::1` is therefore
    #: 24 zeros + `01000000`, and a `…00000001` spelling (the naive one, and the
    #: one this fixture carried for a round) matches nothing on a real kernel,
    #: so the row using it would survive the mutation it exists to forbid.
    LOCAL = "0100007F:1054"
    ANY4 = "00000000:1054"
    ANY6 = "0" * 32 + ":1054"
    LOOPBACK6 = "0" * 24 + "01000000:1054"
    MAPPED = "0000000000000000FFFF00000100007F:1054"
    MAPPED_ANY = "0000000000000000FFFF000000000000:1054"
    LISTEN = "0A"
    ESTABLISHED = "01"

    _HEAD = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
             "retrnsmt   uid  timeout inode\n")

    def _proc(self, t, rows, *, tcp6_rows=(), tcp6=True):
        root = Path(t) / "proc" / "net"
        root.mkdir(parents=True, exist_ok=True)

        def render(items):
            out = self._HEAD
            for i, (local, st, uid) in enumerate(items):
                out += (f"{i:4d}: {local} 00000000:0000 {st} "
                        f"00000000:00000000 00:00000000 00000000 {uid} 0 12345 1\n")
            return out
        (root / "tcp").write_text(render(rows))
        if tcp6:
            (root / "tcp6").write_text(render(tcp6_rows))
        return Path(t) / "proc"

    def _holders(self, rows, **kw):
        with tempfile.TemporaryDirectory() as t:
            return system.hop_holders(self.PORT, proc_root=self._proc(t, rows, **kw))

    def _certain(self, rows, **kw):
        return set(self._holders(rows, **kw).certain)

    def test_a_systemd_held_reservation_reads_as_uid_zero(self) -> None:
        """The state the whole release exists to produce. systemd creates the
        listening socket as PID 1, and the proxy INHERITS the descriptor — the
        socket's recorded owner is its creator, so it stays 0 even though the
        process reading from it runs as vide-oauth2."""
        self.assertEqual(self._certain([(self.LOCAL, self.LISTEN, "0")]), {0})

    def test_an_unmigrated_proxy_holding_the_port_itself_is_its_own_uid(self) -> None:
        """The other legitimate holder, and the one that made the previous
        design fire a false alarm on every box on upgrade day: before the
        reservation lands, the proxy binds the address itself, as its own
        user."""
        self.assertEqual(self._certain([(self.LOCAL, self.LISTEN, "997")]), {997})

    def test_nothing_listening_is_an_empty_answer_not_unknown(self) -> None:
        """Empty means "the kernel answered: nobody". None means "the kernel
        could not be read", and doctor prints a different row for each — reading
        one as the other is how a measurement that never happened becomes the
        sentence "the fleet's authorization port is open right now"."""
        h = self._holders([])
        self.assertEqual((set(h.certain), set(h.possible), set(h.served)),
                         (set(), set(), set()))

    def test_a_connection_on_the_hop_is_not_a_holder_but_is_not_discarded(self) -> None:
        """`st` 0A is the HOLDER question. 01 on the same local address is an
        ACCEPTED connection — somebody being served on the hop right now — and
        it is the state the containment ladder's step 2 calls not optional: an
        attacker that hands the listening socket back while staying alive keeps
        answering everything Caddy already had open, and every listener-only
        check goes green behind it."""
        h = self._holders([(self.LOCAL, self.ESTABLISHED, "1000")])
        self.assertEqual(set(h.certain), set(), "a connection was read as a holder")
        self.assertEqual(set(h.served), {1000},
                         "the harvest state is invisible to doctor")

    def test_a_different_port_on_the_same_address_is_not_a_holder(self) -> None:
        self.assertEqual(self._certain([("0100007F:1F90", self.LISTEN, "1000")]),
                         set())

    def test_a_wildcard_listener_does_hold_the_fleets_hop(self) -> None:
        """0.0.0.0:<port> really does answer 127.0.0.1:<port>, so leaving it out
        would be a hole an attacker walks through by binding the wildcard."""
        self.assertEqual(self._certain([(self.ANY4, self.LISTEN, "1000")]), {1000})

    def test_a_v4_mapped_listener_holds_it_in_both_forms(self) -> None:
        """An AF_INET6 socket bound to a v4-MAPPED address serves v4 and only
        v4: __inet6_bind sets inet_rcv_saddr from the embedded address. Both
        spellings count — the specific one and ::ffff:0.0.0.0, which was absent
        for a round and is a clean evasion on any box whose hop is free."""
        self.assertEqual(self._certain([], tcp6_rows=[(self.MAPPED, self.LISTEN, "1000")]),
                         {1000})
        self.assertEqual(self._certain([], tcp6_rows=[(self.MAPPED_ANY, self.LISTEN, "1000")]),
                         {1000})

    def test_a_listener_on_another_address_does_not_exonerate_a_squatter(self) -> None:
        """THE ADDRESS IS PART OF THE QUESTION, and the reader this replaced
        threw it away: `ss "sport = :<port>"` matches every local address, so a
        root-held listener on some unrelated address merged into the same answer
        and cleared the suspicion for a squatter on the fleet's real hop."""
        got = self._certain([("0200007F:1054", self.LISTEN, "0"),   # 127.0.0.2
                             (self.LOCAL, self.LISTEN, "1000")])
        self.assertEqual(got, {1000}, "an unrelated root listener exonerated a squatter")

    def test_a_v6_loopback_listener_is_not_the_fleets_hop(self) -> None:
        """[::1]:<port> does NOT receive the v4 traffic Caddy sends. The
        spelling matters as much as the row: `::1` renders as 24 zeros then
        `01000000`, per-word host byte order — the naive big-endian spelling
        matches nothing on a real kernel, so a row written that way would pass
        no matter what the product did."""
        self.assertEqual(self._certain([], tcp6_rows=[(self.LOOPBACK6, self.LISTEN, "0")]),
                         set())

    def test_a_lone_v6_wildcard_may_alarm_but_may_never_reassure(self) -> None:
        """THE AMBIGUOUS ONE. `::` serves v4 unless the socket set IPV6_V6ONLY,
        and procfs exposes no such flag — so this row cannot be resolved from
        the tables. It goes into `possible`, which feeds the alarm and never
        the affirmative: reading it as certain would be a false GREEN, and
        discarding it would be a hole."""
        h = self._holders([], tcp6_rows=[(self.ANY6, self.LISTEN, "1000")])
        self.assertEqual(set(h.certain), set())
        self.assertEqual(set(h.possible), {1000})

    def test_a_v6only_wildcard_beside_the_reservation_is_dropped_entirely(self) -> None:
        """THE ROW THAT STOPS ANY LOCAL ACCOUNT FIRING A FLEET OUTAGE. A v6only
        `[::]:<port>` bind needs no privilege and legally coexists with
        systemd's `127.0.0.1:<port>` — that is what makes sshd's 0.0.0.0:22 +
        :::22 pair possible. Counted, it put a second uid into the answer on a
        correctly reserved box, which clears the affirmative row and fires a
        containment ladder whose first step is `systemctl stop caddy`.

        The kernel supplies the disambiguation for free: a NON-v6only `::` bind
        conflicts with a bound v4 address and gets EADDRINUSE, so a `::` row
        that coexists with a v4 match is provably v6only and provably
        harmless."""
        h = self._holders([(self.LOCAL, self.LISTEN, "0")],
                          tcp6_rows=[(self.ANY6, self.LISTEN, "1000")])
        self.assertEqual(set(h.certain), {0})
        self.assertEqual(set(h.possible), set(),
                         "a v6only wildcard beside the reservation was counted — "
                         "one unprivileged bind(2) now fires `stop caddy` on "
                         "every box in the fleet")

    def test_a_kernel_without_ipv6_is_a_normal_box_not_an_unknown(self) -> None:
        """/proc/net/tcp6 is simply absent there. Only "neither table could be
        read" is unknown."""
        self.assertEqual(self._certain([(self.LOCAL, self.LISTEN, "0")], tcp6=False),
                         {0})

    def test_an_unreadable_proc_is_None_and_never_empty(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self.assertIsNone(system.hop_holders(self.PORT,
                                                 proc_root=Path(t) / "nope"))

    def test_an_unreadable_v4_table_is_unknown_even_when_v6_answers(self) -> None:
        """THE TWO TABLES ARE NOT SYMMETRIC. /proc/net/tcp is where the fleet's
        hop lives, so a box whose v4 table cannot be read is a box this reader
        cannot answer about — even if the v6 one opened fine.

        Read the other way ("if either opened, answer"), an unreadable v4 table
        produced an EMPTY certain set, which doctor reads as "nothing is
        listening on the fleet's hop" and answers with "the fleet's
        authorization port is open right now" — whose remedy restarts the gate.
        A measurement that never happened, prescribing an outage. It was the last
        place this section guessed."""
        with tempfile.TemporaryDirectory() as t:
            root = self._proc(t, [], tcp6_rows=[(self.ANY6, self.LISTEN, "0")])
            (root / "net" / "tcp").unlink()
            self.assertIsNone(system.hop_holders(self.PORT, proc_root=root))

    def test_a_name_the_process_chose_cannot_reach_this_answer(self) -> None:
        """THE ROW THE OLD READER COULD NOT HAVE. There is no process-supplied
        text anywhere in this table — no comm, no argv, nothing a squatter can
        set. The uid column is written by the kernel from the socket's creator,
        so the forgery that defeated `ss -Htlnp` has no surface here at all: a
        squatter is its own uid and says so."""
        self.assertEqual(self._certain([(self.LOCAL, self.LISTEN, "1000")]), {1000})
        self.assertNotIn(0, self._certain([(self.LOCAL, self.LISTEN, "1000")]))


class TestTheAbandonedHop(unittest.TestCase):
    """THE ONE ROW THAT CAN SEE THE TERMINAL STATE of a hand-edited fleet pin,
    and the reason it had to exist: every other row in doctor's reservation
    section is computed against the PIN.

    Walk it. An operator edits VIDE_SSO_PROXY_PORT in fleet.env from P1 to P2, a
    converge writes the socket unit for P2 and reloads, and the box reboots.
    systemd now holds P2; `covers` is true for P2; the holder of P2 is uid 0; the
    real proxy answers /ping on P2. Doctor prints `proxy port: reserved` and
    exits 0 — while P1, the address the operator's own pasted Caddyfile block
    still dials, is unheld and squattable, and every SSO instance on the box
    returns 502. A diagnostic that is green during a fleet-wide outage with an
    open authorization hop is the exact failure this section exists to prevent."""

    PIN = 4199
    OLD = 4180

    def _cfg(self, t, *, pasted_port=None, pin=PIN, block=True):
        from vide import caddy
        cfg = make_config(Path(t))
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        (cfg.sso_dir / "caddy").mkdir(exist_ok=True)
        (cfg.sso_dir / "fleet.env").write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.com\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
            f"VIDE_SSO_PROXY_PORT={pin}\n")
        if block:
            port = pin if pasted_port is None else pasted_port
            (cfg.sso_dir / "caddy" / "auth.caddy").write_text(
                caddy.emit_auth_body("example.com", port))
        return cfg

    def _rows(self, cfg, *, held, certain=None, possible=(), loaded=(),
              on_pin=False, blind=False):
        """`blind` is an UNREADABLE kernel, which is a fourth answer and not a
        synonym for "nothing is there".

        SYSTEMD_DIR AND unit_listen_streams ARE SEAMED HERE because the row now
        attributes the holder, and attribution reads the box: an unseamed fixture
        would stat the developer's own /etc/systemd/system and ask the real
        manager, which is how a mutation row turns ALREADY-RED on a machine that
        happens to have VIDE installed."""
        holders = None if blind else system.HopHolders(
            certain=frozenset({1000} if held else set())
            if certain is None else frozenset(certain),
            possible=frozenset(possible), served=frozenset())
        with tempfile.TemporaryDirectory() as sysd, \
                mock.patch.object(oauth2proxy.system, "hop_holders",
                                  return_value=holders), \
                mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                  return_value=list(loaded)), \
                mock.patch.object(oauth2proxy, "SYSTEMD_DIR", Path(sysd)):
            lines, ok = oauth2proxy._abandoned_hop(cfg, on_pin=on_pin)
        return "\n".join(lines), ok

    def test_a_pin_that_matches_the_pasted_block_is_silent(self) -> None:
        """Silence on a healthy box is what keeps the row readable on a broken
        one — and this is the state of every box that never touched the pin."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t), held=False)
        self.assertTrue(ok)
        self.assertEqual(body, "")

    def test_a_moved_pin_is_RED_and_names_both_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, pasted_port=self.OLD), held=False)
        self.assertFalse(ok, "doctor stayed green over an abandoned hop")
        self.assertIn(f"127.0.0.1:{self.OLD}", body)
        self.assertIn(f"127.0.0.1:{self.PIN}", body)
        # The direction that costs nothing is named FIRST: restoring the pin
        # needs no re-paste and no outage.
        self.assertIn("VIDE_SSO_PROXY_PORT", body)

    def test_it_says_whether_the_abandoned_address_is_held(self) -> None:
        """The pasted port alone says only that two numbers differ. The kernel
        read on the ABANDONED address is what separates "a migration to finish"
        from "an open door", and both sentences must be reachable."""
        with tempfile.TemporaryDirectory() as t:
            free, _ = self._rows(self._cfg(t, pasted_port=self.OLD), held=False)
            taken, _ = self._rows(self._cfg(t, pasted_port=self.OLD), held=True)
        self.assertIn("NOTHING is holding", free)
        self.assertIn("any local account can bind it", free)
        self.assertNotIn("NOTHING is holding", taken)
        self.assertIn("something is currently holding", taken)

    def test_the_boxs_own_reservation_is_not_reported_as_a_squatter(self) -> None:
        """THE STATE THE RELEASE DELIBERATELY PARKS BOXES IN, and the row was
        false in it. The write refusal declines to move the reservation, so
        systemd goes on holding the OLD address — and the row said "something is
        currently holding it, and it is not this reservation" about the box's own
        PID-1 reservation. The natural response to that sentence is the
        containment ladder, and every rung of it either takes the fleet down or
        frees the address the operator's Caddyfile still dials."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(
                self._cfg(t, pasted_port=self.OLD), held=True, certain={0},
                loaded=[f"127.0.0.1:{self.OLD} (Stream)"])
        self.assertFalse(ok)
        self.assertIn("THIS BOX'S OWN reservation", body)
        self.assertNotIn("is NOT this box's reservation", body)
        self.assertNotIn("NOTHING is holding", body)

    def test_a_stranger_on_the_abandoned_address_is_still_named_as_one(self) -> None:
        """The opposite sign: our reservation covers the PIN, not the abandoned
        address, so whatever is on it is not ours."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(
                self._cfg(t, pasted_port=self.OLD), held=True, certain={0},
                loaded=[f"127.0.0.1:{self.PIN} (Stream)"])
        self.assertFalse(ok)
        self.assertIn("is NOT this box's reservation", body)
        self.assertNotIn("THIS BOX'S OWN reservation", body)

    def test_a_v6only_squatter_cannot_buy_the_reassuring_sentence(self) -> None:
        """THE INVERSION HopHolders WAS SPLIT APART TO PREVENT. `possible` is the
        `::` bucket, and a v6only bind there needs no privilege at all — so if
        the benign arm were keyed on `on_hop` rather than on `certain == {0}`,
        any local account could flip an open-door row into a this-is-fine one by
        binding [::]:<old>."""
        with tempfile.TemporaryDirectory() as t:
            body, _ = self._rows(
                self._cfg(t, pasted_port=self.OLD), held=False, certain=set(),
                possible={1000}, loaded=[f"127.0.0.1:{self.OLD} (Stream)"])
        self.assertNotIn("THIS BOX'S OWN reservation", body)

    def test_an_unreadable_kernel_makes_no_claim_in_either_direction(self) -> None:
        """A fourth state, and it is not a synonym for "nothing is there". The
        row used to print "which NOTHING is holding: any local account can bind
        it" from a measurement that never happened — an open-door alarm, and an
        all-clear, both asserted out of a failed read."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, pasted_port=self.OLD),
                                  held=False, blind=True)
        self.assertFalse(ok)
        self.assertIn("could not read /proc/net/tcp", body)
        self.assertNotIn("NOTHING is holding", body)
        self.assertNotIn("THIS BOX'S OWN reservation", body)

    def test_a_landed_move_is_not_told_to_walk_the_pin_back(self) -> None:
        """The remedy's DIRECTION is a live fact. "Put VIDE_SSO_PROXY_PORT back"
        is the cheap, no-outage direction only while the gate is still on the old
        address; on a box where the move LANDED it marches the reservation off an
        address it is now holding — the row prescribing the outage it exists to
        prevent."""
        with tempfile.TemporaryDirectory() as t:
            landed, _ = self._rows(self._cfg(t, pasted_port=self.OLD),
                                   held=False, on_pin=True)
            parked, _ = self._rows(self._cfg(t, pasted_port=self.OLD),
                                   held=False, on_pin=False)
        self.assertNotIn("put VIDE_SSO_PROXY_PORT back", landed)
        self.assertIn("finish it", landed)
        self.assertIn("put VIDE_SSO_PROXY_PORT back", parked)

    def test_several_stale_hops_name_them_all_and_ask_for_a_hand(self) -> None:
        """emit_auth_block renders exactly one address, so two of them means the
        file was hand-edited or merged. The single-number remedy has no correct
        value there — and a remedy that is still true after the operator follows
        it is the one shape this section forbids outright."""
        from vide import caddy
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t, pasted_port=self.OLD)
            p = cfg.sso_dir / "caddy" / "auth.caddy"
            p.write_text(p.read_text()
                         + caddy.emit_auth_body("example.com", self.OLD + 7))
            body, ok = self._rows(cfg, held=False)
        self.assertFalse(ok)
        self.assertIn(f"127.0.0.1:{self.OLD}", body)
        self.assertIn(f"127.0.0.1:{self.OLD + 7}", body)
        self.assertIn("by hand", body)
        self.assertNotIn("put VIDE_SSO_PROXY_PORT back", body)

    def test_it_never_claims_to_know_what_caddy_dials(self) -> None:
        """auth.caddy is what VIDE last WROTE, not truth about what Caddy serves.
        THE REASON CHANGED AND THE PROPERTY DID NOT. It used to be that the
        operator held a pasted copy VIDE could not read; now VIDE owns the file
        and reads it, but Caddy holds its config in MEMORY, so a write that
        nothing reloaded is still not what is being served. Either way the row
        must be evidence about the file and must say what it cannot see — the
        phrasing here is re-aimed at the live reason, not relaxed."""
        with tempfile.TemporaryDirectory() as t:
            body, _ = self._rows(self._cfg(t, pasted_port=self.OLD), held=False)
        self.assertIn("not your running Caddy", body)
        self.assertIn("holding in memory", body)

    def test_no_pasted_copy_at_all_is_silent(self) -> None:
        """Same silence _auth_block_drift keeps, for the same reason: a box with
        no copy either never provisioned SSO or deleted it, and there is nothing
        to compare against. Guessing here would be a permanent false alarm on a
        box VIDE cannot see."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, block=False), held=False)
        self.assertTrue(ok)
        self.assertEqual(body, "")

    def test_an_unreadable_pin_is_left_to_the_row_that_owns_it(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t, pasted_port=self.OLD)
            (cfg.sso_dir / "fleet.env").write_text(
                "VIDE_SSO_PARENT_DOMAIN=example.com\nVIDE_SSO_PROXY_PORT=99999\n")
            body, ok = self._rows(cfg, held=False)
        self.assertTrue(ok)
        self.assertEqual(body, "")


class TestParseEnvText(unittest.TestCase):
    def test_tolerant_of_export_quotes_comments(self) -> None:
        got = parse_env_text('# c\nexport A="1"\nB=2\n\ngarbage-no-eq\n')
        self.assertEqual(got, {"A": "1", "B": "2"})


class TestAuthBlockDrift(unittest.TestCase):
    """The auth body used to be the ONE artefact VIDE could not re-land: the
    operator had pasted it into a Caddyfile VIDE does not own, so a change to the
    emitted text reached nothing until they re-pasted, and the drift was silent
    by construction. It happened — the on-disk copy sat two days behind the live
    config with nothing to say so, and this row is what would have said so.

    VIDE OWNS THE FILE NOW; the operator pastes a site header and an import. So
    this row survives with a NARROWER job: drift means only that no converge or
    `upgrade-sso` has run since the build changed, and the remedy is a verb
    rather than a chore. The one state where that verb will not help gets its own
    sentence — render_auth_host refuses to advance the body when doing so would
    repoint a gate that is not on the pin, and a row telling the operator to run
    a command that declines is worse than one describing what they are looking
    at."""

    def _prepare(self, t, *, domain="example.com", body=None):
        from vide import caddy
        cfg = make_config(Path(t))
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        (cfg.sso_dir / "caddy").mkdir(exist_ok=True)
        if domain:
            (cfg.sso_dir / "fleet.env").write_text(
                f"VIDE_SSO_PARENT_DOMAIN={domain}\n")
        if body is None:
            # sso_dir MUST be threaded through: the body names the pages
            # directory, so a default-rendered fixture differs from what the
            # subject renders for THIS config and every "current copy" test
            # would report drift against itself.
            body = caddy.emit_auth_body(domain, cfg.sso_proxy_port,
                                        sso_dir=str(cfg.sso_dir))
        (cfg.sso_dir / "caddy" / "auth.caddy").write_text(body)
        return cfg

    def test_a_current_copy_says_nothing(self):
        # Silence is the point: a check that speaks on a clean box gets ignored,
        # and then it is not a check.
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(
                oauth2proxy._auth_block_drift(self._prepare(t), on_pin=True), [])

    def test_a_stale_copy_is_named_with_its_path(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = self._prepare(t, body="auth.example.com {\n  respond nope 200\n}\n")
            out = oauth2proxy._auth_block_drift(cfg, on_pin=True)
            self.assertEqual(len(out), 1)
            self.assertIn("auth.caddy", out[0])
            # The remedy is a verb VIDE owns, and the row must say so rather than
            # send the operator to edit a file they no longer maintain. It also
            # must not ask for a re-paste: that instruction was correct only
            # while the body WAS the paste.
            self.assertIn("upgrade-sso", out[0])
            self.assertNotIn("re-paste", out[0].lower())

    def test_drift_never_fails_the_health_verdict(self):
        # A stale paste is a to-do, not an outage: whatever was pasted is still
        # serving. Failing doctor over it would train the operator to ignore
        # doctor, which costs more than the drift does.
        import inspect
        src = inspect.getsource(oauth2proxy.proxy_health)
        self.assertIn("lines.extend(_auth_block_drift(cfg, on_pin=served))", src)
        self.assertNotIn("ok = ok and _auth_block_drift", src)

    def test_no_copy_and_no_domain_are_both_silent(self):
        # A box that never provisioned SSO has nothing to drift from, and the
        # sections above already report that far more usefully.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.sso_dir.mkdir(parents=True, exist_ok=True)
            self.assertEqual(oauth2proxy._auth_block_drift(cfg, on_pin=True), [])
        with tempfile.TemporaryDirectory() as t:
            cfg = self._prepare(t, domain="")
            self.assertEqual(oauth2proxy._auth_block_drift(cfg, on_pin=True), [])

    def test_a_moved_pin_does_not_prescribe_a_verb_that_will_decline(self):
        """The PIN arm, and it now turns on a fact the old one did not read: the
        body must actually name a DIFFERENT hop. Off the pin with a body already
        dialling the destination is an ordinary content drift, and prescribing
        upgrade-sso there is correct."""
        from vide import caddy as _c
        with tempfile.TemporaryDirectory() as t:
            cfg = self._prepare(t, body=_c.emit_auth_body("example.com", 9999,
                                                          sso_dir="/etc/vide/sso"))
            out = oauth2proxy._auth_block_drift(cfg, on_pin=False)
        self.assertEqual(len(out), 1)
        self.assertIn("REFUSING", out[0])
        self.assertIn("9999", out[0], "the row must name the hop the body dials")
        self.assertNotIn("upgrade-sso", out[0])

    def test_a_body_with_no_hop_is_not_called_a_repoint(self):
        """caddy.hops' rule, which this row is the second site to need: EMPTY
        means nothing to compare, never "it disagrees". A stub carrying no
        upstream would otherwise be reported as a refused repoint, in a sentence
        naming the address it dials — with nothing to put there."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._prepare(t, body="  respond x 200\n")
            out = oauth2proxy._auth_block_drift(cfg, on_pin=False)
        self.assertEqual(len(out), 1)
        self.assertNotIn("REFUSING", out[0])
        self.assertIn("upgrade-sso", out[0])


class TestDoctorSeesABodyThatDialsAnotherHop(unittest.TestCase):
    """The sensor for the one state in which this verb ASSERTED cleanliness over
    a live authorization bypass.

    Reachability, because a row that cannot be reached is not a control: follow
    the documented move and skip or fail only its `sudo vide upgrade-sso` step —
    rerender_bodies warns and returns, deliberately — then converge again once
    the gate IS on the pin. auth.caddy is rewritten at the new pin by that
    converge, so
    the drift and abandoned-hop rows go silent; the reservation covers the new
    pin and is root-held, so every reservation row is green. Doctor exits 0 while
    every instance body still sends its forward_auth to the old, now-free
    address, which any local account may bind and answer 202 on — for every
    instance, collecting the fleet cookie on every request."""

    PIN = 4180
    OLD = 4199

    def _cfg(self, t, bodies, *, mode=0o644):
        from vide import caddy
        cfg = make_config(Path(t))
        (cfg.sso_dir / "caddy").mkdir(parents=True, exist_ok=True)
        (cfg.sso_dir / "fleet.env").write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.com\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
            f"VIDE_SSO_PROXY_PORT={self.PIN}\n")
        for user, port in bodies.items():
            p = cfg.sso_dir / "caddy" / f"{user}.caddy"
            p.write_text("" if port is None
                         else caddy.emit_auth_body("example.com", port))
            p.chmod(mode)
        return cfg

    def _rows(self, cfg, *, on_pin=True, holders=None):
        h = holders if holders is not None else system.HopHolders(
            certain=frozenset(), possible=frozenset(), served=frozenset())
        with tempfile.TemporaryDirectory() as sysd, \
                mock.patch.object(oauth2proxy.system, "hop_holders",
                                  return_value=h), \
                mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                  return_value=[]), \
                mock.patch.object(oauth2proxy, "SYSTEMD_DIR", Path(sysd)):
            lines, ok = oauth2proxy._stale_authz_bodies(cfg, on_pin=on_pin)
        return "\n".join(lines), ok

    def test_a_body_that_dials_another_address_is_red_and_names_the_instance(self):
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, {"alice": self.OLD}))
        self.assertFalse(ok, "doctor stayed green over a half-applied move")
        self.assertIn("alice", body)
        self.assertIn(f"127.0.0.1:{self.OLD}", body)
        self.assertIn("upgrade-sso", body)

    def test_a_fleet_whose_bodies_agree_with_the_pin_says_nothing(self):
        """Silence on a healthy box. This row is part of `ok`, so it moves
        `doctor --quiet` — the documented cron hook — on every box it fires on,
        and a false positive there teaches operators to ignore the hook."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, {"alice": self.PIN,
                                                "bob": self.PIN}))
        self.assertTrue(ok)
        self.assertEqual(body, "")

    def test_a_tombstoned_body_carries_no_hop_and_is_not_a_disagreement(self):
        """MANDATORY, not optional: a tombstone carries no upstream, and if
        absence read as disagreement this row would redden every box that ever
        destroyed an instance. Empty means nothing to compare — never "it
        disagrees"."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, {"alice": self.PIN,
                                                "gone": None}))
        self.assertTrue(ok, body)
        self.assertEqual(body, "")

    def test_a_box_with_no_bodies_at_all_is_silent(self):
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, {}))
        self.assertTrue(ok)
        self.assertEqual(body, "")

    def test_a_file_that_is_not_a_body_is_not_read_as_one(self):
        """The suffix filter, which arrived with the switch from glob() to
        iterdir() and was pinned by nothing. `caddy.hops` finds a 127.0.0.1:<port>
        in ANY text, so an editor backup, a `.bak`, a half-written temp file — or
        the operator's own notes — sitting beside the bodies would redden a fleet
        that is perfectly healthy, in the row `doctor --quiet` mails from cron.
        A false positive there is how a monitoring channel gets ignored."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t, {"alice": self.PIN})
            (cfg.sso_dir / "caddy" / "alice.caddy.bak").write_text(
                f"forward_auth 127.0.0.1:{self.OLD}\n")
            (cfg.sso_dir / "caddy" / "notes.txt").write_text(
                f"old hop was 127.0.0.1:{self.OLD}\n")
            body, ok = self._rows(cfg)
        self.assertTrue(ok, body)
        self.assertEqual(body, "")

    def test_auth_caddy_is_not_read_here(self):
        """It has a different owner and a different repair path — _abandoned_hop
        owns it. Mixing them would put one remedy on two artifacts."""
        from vide import caddy
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t, {"alice": self.PIN})
            (cfg.sso_dir / "caddy" / "auth.caddy").write_text(
                caddy.emit_auth_body("example.com", self.OLD))
            body, ok = self._rows(cfg)
        self.assertTrue(ok, body)

    def test_an_unlistable_directory_is_said_and_is_not_agreement(self):
        """THE STATE THE PRODUCT ACTUALLY PRODUCES, and the first version of this
        row tested one it cannot. `<sso_dir>/caddy` ships 0750 root:vide-proxy
        and both `doctor` and `info` are needs_root=False, so the ordinary
        non-root run cannot LIST the directory at all — and `Path.glob` swallows
        that PermissionError and yields nothing. An empty walk then read as
        "every body agrees with the pin": fail-OPEN, in the row whose whole
        purpose is to be fail-closed.

        A per-FILE unreadable arm cannot cover it, which is why testing one was
        a mistake: anyone who can list a 0750 directory can read the 0640 files
        inside it, so the per-file state needs a posture the product never
        ships. It is still not a fault — an unobservable property is not a
        defect — so it is SAID and `ok` is left alone."""
        if os.geteuid() == 0:
            self.skipTest("root lists every directory; this row needs a refusal")
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t, {"alice": self.OLD})
            (cfg.sso_dir / "caddy").chmod(0o000)
            try:
                body, ok = self._rows(cfg)
            finally:
                (cfg.sso_dir / "caddy").chmod(0o750)
        self.assertTrue(ok)
        self.assertIn("not observable", body)

    def test_a_readable_body_still_counts_when_a_sibling_is_not(self):
        """One unreadable file may not hide every other body on the box. The
        first version returned early on `unreadable`, discarding evidence it had
        already collected."""
        if os.geteuid() == 0:
            self.skipTest("root reads every mode; this row needs a real refusal")
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t, {"alice": self.OLD, "bob": self.PIN})
            (cfg.sso_dir / "caddy" / "bob.caddy").chmod(0o000)
            try:
                body, ok = self._rows(cfg)
            finally:
                (cfg.sso_dir / "caddy" / "bob.caddy").chmod(0o640)
        self.assertFalse(ok, body)
        self.assertIn("not observable", body)
        self.assertIn("alice", body)

    def test_it_is_silent_when_the_gate_is_not_on_the_pin(self):
        """A deliberate hole. There the bodies agree with the address the gate is
        actually on, two rows above already carry the red, and the only remedy
        this row could name — upgrade-sso — is the very write
        _refuse_a_hop_move refuses on that box. A row whose remedy the product
        refuses is a row that teaches operators to stop reading rows."""
        with tempfile.TemporaryDirectory() as t:
            body, ok = self._rows(self._cfg(t, {"alice": self.OLD}),
                                  on_pin=False)
        self.assertTrue(ok)
        self.assertEqual(body, "")

    def test_an_unreadable_pin_is_left_to_the_row_that_owns_it(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t, {"alice": self.OLD})
            (cfg.sso_dir / "fleet.env").write_text(
                "VIDE_SSO_PARENT_DOMAIN=example.com\n"
                "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
                "VIDE_SSO_PROXY_PORT=99999\n")
            body, ok = self._rows(cfg)
        self.assertTrue(ok)
        self.assertEqual(body, "")

    def test_a_free_abandoned_address_is_named_as_open(self):
        """The kernel half. "Some other address" and "an address any local
        account can bind right now" are the same row with very different
        urgency."""
        with tempfile.TemporaryDirectory() as t:
            body, _ = self._rows(self._cfg(t, {"alice": self.OLD}))
        self.assertIn("NOTHING is holding it", body)


# TestWhichAuthBlockAdviceTheBoxHasEarned stood here and is gone with its
# subject. `_auth_block_advice` was a message-SELECTION branch shared by two warn
# emitters and one doctor row, and the class existed because one decision reached
# three places: get the sign wrong and either the ordinary drifted box loses its
# instruction, or the moved-pin box is handed the dangerous one.
#
# There is no selection left to test. The operator does not paste the body, so
# neither message is an imperative aimed at them; VIDE re-lands the file itself,
# and the only branch that survives is doctor's — whether the verb it prescribes
# would actually run — which TestAuthBlockDrift above now pins in both signs.
# Deleting the class rather than re-aiming it is deliberate: a test kept alive
# past its subject reports on a decision nothing makes any more.


class TestTheReservationReaderDecidesPresenceOnDisk(unittest.TestCase):
    """loaded_reservation's three answers, and the ORDER it asks in.

    `[]` (no reservation here), `None` (the question could not be answered) and a
    populated list are three states, and the difference between the first two is
    a permit. The ordering is the security property: a POSITIVE reading from the
    manager has to decide, because a file-first reader answers "absent" on a box
    where the operator removed the fragment and has not reloaded — where the unit
    is still loaded and still HOLDING the address."""

    def _at(self, sysd, listen):
        with mock.patch.object(oauth2proxy, "SYSTEMD_DIR", Path(sysd)), \
                mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                  return_value=listen):
            return oauth2proxy.loaded_reservation()

    def test_a_first_install_has_no_reservation_and_permits_the_write(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(self._at(t, []), [])

    def test_an_installed_unit_the_manager_will_not_describe_is_unknown(self):
        """The tie-break, and the reason it is a stat rather than `is-enabled`:
        that word is version-dependent below systemd 253, and Debian 12 and
        Ubuntu 22.04 are both supported and both print nothing."""
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / oauth2proxy.SOCKET_UNIT).write_text("# there\n")
            self.assertIsNone(self._at(t, []))

    def test_a_removed_fragment_that_is_still_loaded_still_refuses(self):
        """THE ORDERING, stated as the box it is about. `rm` without a
        `daemon-reload`: the file is gone, the unit is still loaded and still
        holding the address, and a file-first reader would answer `[]` — permit
        the write, reload, drop the descriptor and bind nothing in its place.
        That is VIDE releasing the fleet's hop by its own hand."""
        with tempfile.TemporaryDirectory() as t:
            got = self._at(t, ["127.0.0.1:4180 (Stream)"])
        self.assertEqual(got, ["127.0.0.1:4180 (Stream)"])

    def test_a_masked_unit_is_present_not_absent(self):
        """`systemctl mask` leaves a symlink to /dev/null, which is not a regular
        file — so an `is_file()` presence test read the unit an operator
        deliberately switched off as "no reservation here". On THIS unit
        switching it off does not close the gate, it gives the address away."""
        with tempfile.TemporaryDirectory() as t:
            link = Path(t) / oauth2proxy.SOCKET_UNIT
            link.symlink_to("/dev/null")
            self.assertIsNone(self._at(t, []))

    def test_an_empty_fragment_reads_as_present_and_refuses(self):
        """Fail-closed on the one answer that PERMITS a move. `_read` maps every
        OSError to "", so unreadable and zero-byte arrived indistinguishable from
        absent — and absent is the permit."""
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / oauth2proxy.SOCKET_UNIT).write_text("")
            self.assertIsNone(self._at(t, []))


class TestWhetherThePinIsBeingServed(unittest.TestCase):
    """`pin_is_served` — may an operator safely PASTE a block naming this
    address? Deliberately BROADER than gate_is_on_hop, and the difference is the
    reason this predicate exists at all.

    gate_is_on_hop is a write permit: it decides whether VIDE may repoint every
    instance's forward_auth, so it insists the holder be the fleet's own
    reservation. Judging a PASTE by that rule got the commonest box in the fleet
    wrong — a converge installs and enables the reservation but deliberately
    restarts nothing, so between that converge and the next restart the socket
    unit is inactive while the running gate still holds the port it bound for
    itself. Every one of those boxes was being told DO NOT RE-PASTE over an
    ordinary content-only drift.

    Its only reader before these rows was `cmd_info`'s fixture, which answers
    `None` from `user_uid` — so the proxy-uid arm, the entire point of the
    function, was unreachable in every test that touched it. That is the same
    shape as the CASE-2 gate this release already had to repair."""

    PIN = 4180
    PROXY_UID = 60001

    def _served(self, *, certain, uid=PROXY_UID, blind=False):
        holders = None if blind else system.HopHolders(
            certain=frozenset(certain), possible=frozenset(), served=frozenset())
        with mock.patch.object(oauth2proxy.system, "hop_holders",
                               return_value=holders), \
                mock.patch.object(oauth2proxy.system, "user_uid",
                                  return_value=uid):
            return oauth2proxy.pin_is_served(self.PIN)

    def test_the_migrated_box_is_served_by_root(self):
        self.assertTrue(self._served(certain={0}))

    def test_the_converged_but_not_restarted_box_is_served_by_the_proxy(self):
        """THE ARM THE FUNCTION EXISTS FOR, and the one no test could reach."""
        self.assertTrue(self._served(certain={self.PROXY_UID}))

    def test_root_plus_somebody_else_is_not_a_demonstration(self):
        """EXACTLY `== {uid}`, never `uid in certain`, for the SO_REUSEPORT
        reason doctor states: a second listener must share the effective uid, so
        "root and somebody else" is a state to alarm about, not to paste over."""
        self.assertFalse(self._served(certain={0, 1000}))

    def test_a_stranger_holding_the_pin_is_not_a_demonstration(self):
        self.assertFalse(self._served(certain={1000}))

    def test_an_unreadable_kernel_is_not_a_demonstration(self):
        """The conservative direction for ADVICE: a needless "do not paste"
        costs one command, and a wrong "paste it" costs the fleet's login flow."""
        self.assertFalse(self._served(certain=set(), blind=True))

    def test_nothing_listening_is_not_a_demonstration(self):
        self.assertFalse(self._served(certain=set()))


if __name__ == "__main__":
    unittest.main()
