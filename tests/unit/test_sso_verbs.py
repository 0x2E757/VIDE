"""Verb-level behavior for the SSO fleet-state module: allow/revoke sequences,
email normalization refusals, the last-email gate, tombstone-not-delete, and
the socket-record claim. Uses a filesystem-backed executor that PERFORMS writes
(so read-back is real) but only RECORDS systemctl/rm actions."""
from __future__ import annotations

import contextlib
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Self-sufficient on purpose — see the note in test_sso_render.py: a bare
# `from fakes import …` made this module importable only through run.py, which
# silently defeated every prove-teeth row that names it.
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import (HOST_SEAMS, FsExecutor, RecordingExecutor,  # noqa: E402
                   bare_host, capturing_reporter, make_config, quiet_reporter)
from vide import contract, oauth2proxy, sso, system  # noqa: E402
from vide.errors import (CommandFailed, ConfigError, StateError,  # noqa: E402
                         UsageError)
from vide.executor import Executor  # noqa: E402
from vide.prompter import PlainPrompter  # noqa: E402


#: A box where VIDE's install step has already created its identities. Every
#: verb in this module — allow, revoke, destroy, rotate, and every converge
#: after the first — only ever executes on such a box, so this is the true
#: fixture for them, not a convenience. The BARE box is the first-install state
#: and gets an explicit `identities=()` in TestFirstInstallOnABareBox: that
#: difference is exactly what the doubles were blind to.
SSO_BOX = ("vide-proxy", "vide-oauth2")


class _FsExecutor(FsExecutor):
    """fakes.FsExecutor on a provisioned box. The shared base is bare by
    default on purpose (see fakes._BoxModel); this module's subject matter is
    what happens AFTER the install, so it names the identities the install
    created once, here, rather than at twenty-five call sites."""

    def __init__(self, *, identities: tuple[str, ...] = SSO_BOX, **kw) -> None:
        super().__init__(identities=identities, **kw)


class TestEnsureProxyPreservesCookieSecret(unittest.TestCase):
    """D4/H1: a (re-)affirm of the shared proxy must PRESERVE any recorded
    cookie secret. Regenerating it signs out the whole fleet — a converge that
    had to re-write a torn proxy.env must not become an outage."""

    def test_recorded_cookie_secret_survives_reaffirm(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.sso_dir.mkdir(parents=True, exist_ok=True)
            oauth2proxy.toml_path(cfg).write_text("# toml\n")
            oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
                "old.apps.googleusercontent.com", "GOCSPX-old", "OLDCOOKIE"))
            Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
            oauth2proxy.current_link(cfg).write_text("x")
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit"), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                changed = oauth2proxy.record_credentials(
                    cfg, ex, quiet_reporter(),
                    client_id="new.apps.googleusercontent.com",
                    client_secret="GOCSPX-new")
            env = oauth2proxy.env_path(cfg).read_text()
            self.assertIn("OLDCOOKIE", env)      # cookie secret preserved (no sign-out)
            self.assertIn("GOCSPX-new", env)     # the supplied client secret applied
            # oauth2-proxy reads proxy.env once at startup, so the caller must
            # learn a restart is owed — a corrected secret written and not
            # re-read has fixed nothing.
            self.assertTrue(changed)


class TestFirstInstallOnABareBox(unittest.TestCase):
    """The state a first SSO install actually starts from — and BARE means bare
    on both axes, which is the whole lesson of this class's history.

    First it meant "no /etc/vide/sso": splitting ensure_proxy moved the proxy.env
    write ahead of the only code that created that directory, the real Executor
    mkstemps into the parent, and the install died there while 508 unit rows
    stayed green because the double mkdir'd parents and the product does not.

    The fix for that crashed one line later, on the OTHER axis: the helper it
    added asserted a directory owned by `vide-proxy` before anything had created
    that group, `install -d` resolves -o/-g before it creates anything, and 515
    rows stayed green because the double accepted any owner string and dropped
    it. The class's own fixture was part of the failure — it started from a
    directory tree that did not exist on a box whose identities it assumed did,
    and it mocked ensure_identities away, so the step whose absence WAS the
    defect could not be observed.

    So: `identities=()`, and ensure_identities is left to run. The identity
    probes are the seam — every identity reports missing, so the trace carries
    the groupadd and the ledger learns from it, exactly as a box does."""

    def _bare(self, t):
        return FsExecutor(identities=(), sandbox=Path(t))

    def test_record_credentials_creates_the_state_home_it_writes_into(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            self.assertFalse(Path(cfg.sso_dir).exists(), "fixture must start bare")
            oauth2proxy.record_credentials(
                cfg, self._bare(t), quiet_reporter(),
                client_id="c.apps.googleusercontent.com", client_secret="GOCSPX-x")
            self.assertTrue(oauth2proxy.env_path(cfg).is_file())

    def test_the_apply_order_survives_a_bare_box_end_to_end(self) -> None:
        # Both halves in the order _apply_sso runs them, against a box where
        # neither the directory tree nor the identities exist yet.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            ex = self._bare(t)
            Path(cfg.oauth2_proxy_dir).mkdir(parents=True)
            oauth2proxy.current_link(cfg).write_text("x")
            with self._nothing_exists_yet():
                oauth2proxy.record_credentials(
                    cfg, ex, quiet_reporter(),
                    client_id="c.apps.googleusercontent.com", client_secret="GOCSPX-x")
                with mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                     mock.patch.object(oauth2proxy, "install_proxy_socket_unit", return_value=False), \
                     mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                    oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(), was_active=False,
                                               parent_domain="example.com")
            self.assertTrue(oauth2proxy.toml_path(cfg).is_file())
            self.assertTrue((Path(cfg.sso_dir) / "caddy" / "auth.caddy").is_file())

    def test_no_artifact_is_owned_by_an_identity_that_does_not_exist_yet(self) -> None:
        """The INVARIANT, where the two rows above pin the instance. Whatever the
        call graph looks like next month, no argv and no chown may name
        vide-proxy or vide-oauth2 before the argv that creates it — `install -d`
        resolves -o/-g during option parsing and exits 1 with `invalid group`,
        and atomic_write's chown resolves through pwd/grp. Both crashes this
        class records were one reordering away from each other."""
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            ex = self._bare(t)
            Path(cfg.oauth2_proxy_dir).mkdir(parents=True)
            oauth2proxy.current_link(cfg).write_text("x")
            with self._nothing_exists_yet():
                oauth2proxy.record_credentials(
                    cfg, ex, quiet_reporter(),
                    client_id="c.apps.googleusercontent.com", client_secret="GOCSPX-x")
                with mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                     mock.patch.object(oauth2proxy, "install_proxy_socket_unit", return_value=False), \
                     mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                    oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(), was_active=False,
                                               parent_domain="example.com")
        created = {}
        for i, a in enumerate(ex.actions):
            if a[0] == "run" and a[1][:1] in (("groupadd",), ("useradd",)):
                created.setdefault(a[1][-1], i)
                if a[1][0] == "useradd":       # USERGROUPS_ENAB: the private group
                    created.setdefault(a[1][-1], i)
        self.assertIn(oauth2proxy.PROXY_GROUP, created, "nothing created the group")
        for i, a in enumerate(ex.actions):
            named = set()
            if a[0] == "run":
                named = {a[1][j + 1] for j, w in enumerate(a[1]) if w in ("-o", "-g")}
            elif a[0] == "atomic_write" and a[3] is not None:
                named = set(a[3])
            for name in named - {"root"}:
                self.assertIn(name, created, f"{a} names {name}, which nothing creates")
                self.assertLess(created[name], i, f"{a} names {name} before it exists")

    def test_the_caddy_dir_helper_stands_alone_on_a_bare_box(self) -> None:
        """The helper establishes the identity it NAMES, rather than carrying an
        invisible "somebody ran ensure_identities first" precondition. That
        precondition is what broke twice, and it cannot be pinned through
        converge_proxy — converge calls ensure_identities itself, so removing the
        helper's own call there changes nothing. The property is about the NEXT
        caller, so the row calls the helper the way a next caller would."""
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            ex = self._bare(t)
            Path(cfg.sso_dir).mkdir(parents=True)
            with self._nothing_exists_yet():
                oauth2proxy._ensure_caddy_dir(cfg, ex, quiet_reporter())
            self.assertTrue((Path(cfg.sso_dir) / "caddy").is_dir())

    @contextlib.contextmanager
    def _nothing_exists_yet(self):
        """A box with no VIDE identity and nothing running — the state
        ensure_identities exists for. Seamed at system level rather than by
        mocking ensure_identities away: the product's own mutations must reach
        the double, because the double's ledger is what makes the ordering
        observable at all. It also makes the rows independent of whether the box
        running the tier happens to have a vide-proxy group already."""
        with mock.patch.object(oauth2proxy.system, "query",
                               return_value=mock.Mock(returncode=1, stdout="")), \
             bare_host(oauth2proxy):
            yield


class TestTheReaffirmRestartIsGatedOnLiveness(unittest.TestCase):
    """A corrected client secret is inert until the process re-reads it —
    oauth2-proxy loads proxy.env once at startup — so `--sso-reaffirm` owes a
    restart. But ONLY when something was already running: converge_proxy's
    `enable --now` starts a dead proxy WITH the new file, and restarting it a
    second later is a second bounce during OIDC discovery, immediately before
    proxy_ready starts timing it.

    The sample is taken at the top of `_apply_sso`, before this run's first
    write, and that ordering is the whole point: taken afterwards it says only
    "we just started it", which cannot tell a first install from a live fleet."""

    def _reaffirm(self, t, *, was_active: bool):
        from vide import install_flow as fl
        cfg = make_config(Path(t))
        Path(cfg.sso_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
            "old.apps.googleusercontent.com", "GOCSPX-old", "COOKIE"))
        Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).write_text("x")
        ex = _FsExecutor(sandbox=Path(t))
        plan = fl.InstallPlan(
            target="alice", action="install", mode="sso", toolchain_force=False,
            is_root_fallback=False, fqdn="alice.example.com",
            parent_domain="example.com", persist_parent=False, sso_bootstrap=False,
            sso_credentials_needed=True, whitelist_email="a@example.test",
            sso_credentials=fl.SsoCredentials(
                client_id="new.apps.googleusercontent.com",
                client_secret="GOCSPX-new"))
        # The dead-proxy arm uses starts_live, not a constant False: converge's
        # `enable --now` makes the unit active, so the honest model answers
        # inactive on the first query and active afterwards. That difference IS
        # the subject — `was_active` exists to be sampled BEFORE the first write,
        # and against a constant both sampling points give the same answer, which
        # left the mutation rows unable to tell them apart.
        host = ({"live": (oauth2proxy.UNIT,)} if was_active
                else {"starts_live": (oauth2proxy.UNIT,)})
        with bare_host(fl, fl.oauth2proxy, **host,
                       identities=(oauth2proxy.PROXY_GROUP, oauth2proxy.PROXY_USER)), \
             mock.patch.object(fl.codeserver, "ensure_code_server", return_value="1.2.3"), \
             mock.patch.object(fl.oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(fl.oauth2proxy, "install_proxy_socket_unit",
                               return_value=False), \
             mock.patch.object(fl.oauth2proxy, "ensure_caddy_membership"), \
             mock.patch.object(fl.oauth2proxy, "proxy_ready", return_value=True), \
             mock.patch.object(fl.sso, "persist_parent_domain"), \
             mock.patch.object(fl.sso, "claim_binding"), \
             mock.patch.object(fl.sso, "allow"), \
             mock.patch.object(fl.sso, "read_allowlist", return_value=["a@example.test"]), \
             mock.patch.object(fl.secrets, "ensure_sso_config"), \
             mock.patch.object(fl.sysd, "install_unit"), \
             mock.patch.object(fl.sysd, "enable_start"), \
             mock.patch.object(fl, "link_cli"), \
             mock.patch.object(fl.transport, "probe_transport"), \
             mock.patch.object(fl, "_summary", return_value=""):
            rep = quiet_reporter()
            fl._apply_sso(cfg, ex, rep, PlainPrompter(rep), plan)
        return ex

    def test_a_live_proxy_is_restarted_so_it_re_reads_the_secret(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ex = self._reaffirm(t, was_active=True)
        self.assertIn(("systemctl", "restart", oauth2proxy.UNIT), ex.ran)

    def test_a_dead_proxy_is_not_restarted_because_enable_now_already_read_it(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ex = self._reaffirm(t, was_active=False)
        self.assertNotIn(("systemctl", "restart", oauth2proxy.UNIT), ex.ran)


class TestAMaskedUnitIsRefused(unittest.TestCase):
    """A masked unit is a symlink to /dev/null: the operator deliberately turned
    the fleet's gate off. atomic_write's os.replace replaces the dest SYMLINK
    itself, so converging would silently unmask it and `enable --now` would start
    what they switched off.

    `masked-runtime` is what `systemctl mask --runtime` reports, and an exact
    compare against "masked" let that path through to a bare CommandFailed at
    `enable --now` instead of the named remedy."""

    def _install(self, state: str):
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            Path(cfg.sso_dir).mkdir(parents=True, exist_ok=True)
            # The unit template a real checkout always carries: the refusal must
            # be reached, not short-circuited by a missing file.
            units = Path(cfg.repo_dir) / "units"
            units.mkdir(parents=True, exist_ok=True)
            (units / "oauth2-proxy.service").write_text("[Unit]\n")
            ex = _FsExecutor(sandbox=Path(t))
            with mock.patch.object(oauth2proxy.system, "unit_enable_state",
                                   return_value=state):
                oauth2proxy.install_proxy_unit(cfg, ex, quiet_reporter())

    def test_a_masked_unit_is_refused(self) -> None:
        with self.assertRaises(StateError):
            self._install("masked")

    def test_a_RUNTIME_masked_unit_is_refused_too(self) -> None:
        with self.assertRaises(StateError):
            self._install("masked-runtime")


class TestTheFleetPortIsOneReader(unittest.TestCase):
    """The pin landed in proxy.toml and nowhere else, which is worse than not
    pinning it at all: proxy.toml said one port and every per-instance
    forward_auth body said another, so Caddy's authz hop pointed at a port the
    proxy was not listening on. `_render_all` runs on every allow and revoke and
    its callers then reload Caddy, so a single `.env` row pushed that live — and
    any local account can bind a free loopback port and answer 202 for every
    instance on the box. One reader, and a row that fails if a second appears."""

    #: Deliberately NEITHER the code default (4180) nor what cfg says: a fixture
    #: that pins the default cannot tell "read the pin" from "fell back", and a
    #: mutation that hardcodes the default would pass against it. Three distinct
    #: numbers is what makes every row here falsifiable.
    PIN = 4199

    def _pinned_box(self, t):
        cfg = make_config(Path(t), sso_proxy_port=9999)   # what `.env` says TODAY
        Path(cfg.sso_dir).mkdir(parents=True, exist_ok=True)
        sso.fleet_file(cfg).write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.com\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
            f"VIDE_SSO_PROXY_PORT={self.PIN}\n")
        return cfg

    def test_every_renderer_names_the_pinned_port(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned_box(t)
            ex = _FsExecutor(sandbox=Path(t))
            sso.allow(cfg, ex, quiet_reporter(), "alice", "a@example.test")
            body = sso.caddy_body(cfg, "alice").read_text()
            toml = oauth2proxy.render_proxy_toml(cfg, "example.com")
            # Inside the tmp tree: fleet_port READS fleet.env, so asking after
            # the directory is gone silently answers from cfg instead — which is
            # exactly the fallback this row exists to prove is not taken.
            self.assertEqual(sso.fleet_port(cfg), self.PIN)
        self.assertIn(f"127.0.0.1:{self.PIN}", body,
                      "the authz hop must name the pinned port, not .env's")
        self.assertNotIn("9999", body)
        self.assertNotIn("4180", body, "the code default is not the pin either")
        # proxy.toml NO LONGER NAMES A PORT AT ALL — it names an inherited
        # descriptor, and the address moved to the socket unit that binds it.
        # Asserting the absence matters as much as the old presence did: a
        # renderer that reverted to `http_address = "127.0.0.1:<port>"` would
        # make the proxy bind for itself, which is precisely the state where the
        # port is free whenever the proxy is not on it.
        self.assertIn('http_address = "fd:3"', toml)
        self.assertNotIn("127.0.0.1:", toml.split("trusted_proxy_ips")[0])
        # …and the socket unit, which is where the pin now lands, must render
        # with the SAME number. The two artifacts cannot be allowed to drift:
        # one binds, the others dial.
        socket_src = (REPO / "units" / "oauth2-proxy.socket").read_text()
        rendered = socket_src.replace(oauth2proxy.SOCKET_PORT_SENTINEL, str(self.PIN))
        self.assertIn(f"ListenStream=127.0.0.1:{self.PIN}", rendered)
        self.assertNotIn(oauth2proxy.SOCKET_PORT_SENTINEL, rendered)

    def test_every_probe_answers_on_the_pinned_port(self) -> None:
        """The three /ping probes are the half a census cannot judge, because
        what matters is not that they read the pin but what happens when they do
        not: rotate_sso reads a failed probe as "the proxy rejected the new
        cookie secret" and RESTORES the secret it was invoked to burn. A port
        divergence there does not fail loudly — it disarms the one lever that
        answers a leaked fleet-wide session cookie."""
        seen: list[int] = []
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned_box(t)
            # `timeout` is in the signature, not swallowed by **kwargs: the poll
            # loops now pass PROXY_PING_TIMEOUT_S rather than the module default,
            # because a failed probe against the reserved port costs its whole
            # timeout instead of refusing instantly. A stub that accepted
            # anything would let a caller silently stop passing it.
            def fake(port, *, path="/", timeout=3.0):
                seen.append(port)
                return True
            # bare_host, because resolving WHICH port to probe now reads the host:
            # gate_port asks whether a reservation is loaded on some other
            # address before it falls back to the pin. Unseamed, this row was
            # green only because the machine running the tier happens to have no
            # reservation unit — and it is the named test of a mutation row, so
            # on a box that HAS VIDE installed the harness would have reported
            # "ALREADY RED on the pristine tree".
            with bare_host(oauth2proxy), \
                 mock.patch.object(oauth2proxy.system, "healthz", fake):
                self.assertTrue(oauth2proxy.proxy_answers(cfg))
                self.assertTrue(oauth2proxy._proxy_pings(cfg))
        self.assertEqual(set(seen), {self.PIN},
                         f"a probe used a port other than the pin: {seen}")

    def test_doctor_probes_the_port_it_reports(self) -> None:
        """A diagnostic that names a number it did not test is the very
        divergence the single reader exists to prevent, reintroduced inside the
        check for it. This row is the one the fix for that shipped without."""
        seen: list[int] = []

        def fake_healthz(port, *, path="/healthz", timeout=3.0):
            if path == "/ping":
                seen.append(port)
            return False
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned_box(t)
            # `probe=`, not a healthz patch entered before bare_host: the seam
            # list now answers /healthz too, mock.patch resolution is
            # last-entered-wins, and this row's whole subject is WHICH PORT the
            # probe was called with. Entered outside, it would have been
            # overridden and `seen` would have stayed empty.
            with bare_host(oauth2proxy, live=(oauth2proxy.UNIT,),
                           identities=(oauth2proxy.PROXY_GROUP,), members=("caddy",),
                           probe=fake_healthz), \
                 mock.patch.object(oauth2proxy, "bootstrap_observed", return_value=True):
                _, lines = oauth2proxy.proxy_health(cfg, check_staleness=False)
        self.assertEqual(seen, [self.PIN], "doctor probed a port other than the pin")
        self.assertIn(f"127.0.0.1:{self.PIN}", "\n".join(lines),
                      "doctor named a port it did not probe")

    def test_a_damaged_pin_is_refused_rather_than_quietly_replaced(self) -> None:
        # It used to be two policies for one broken value: the renderer raised
        # and the other reader silently fell back to config — so the two
        # consumers of one damaged row disagreed about the port, which is the
        # exact divergence the pin exists to prevent.
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned_box(t)
            sso.fleet_file(cfg).write_text(
                "VIDE_SSO_PARENT_DOMAIN=example.com\nVIDE_SSO_PROXY_PORT=99999\n")
            with self.assertRaises(ConfigError):
                sso.fleet_port(cfg)


class TestFleetPinsAreNotEnvLive(unittest.TestCase):
    """Making proxy.toml converge turned two `.env` rows into fleet-wide levers:
    before, the file was written once and they were frozen by that accident.
    `VIDE_SSO_ISSUER_URL` is the fleet's root of trust and `VIDE_SSO_PROXY_PORT`
    is baked into the auth block the operator pasted by hand."""

    def test_a_dot_env_row_cannot_repoint_a_provisioned_fleet(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            sso.persist_fleet(cfg, _FsExecutor(), "example.com",
                              issuer="https://accounts.google.com", proxy_port=4180)
            # …and now the operator's .env says something else entirely.
            hostile = make_config(Path(t), sso_issuer_url="https://evil.example.test",
                                  sso_proxy_port=9999)
            toml = oauth2proxy.render_proxy_toml(hostile, "example.com")
            # The PORT half of this row moved: proxy.toml no longer names an
            # address at all, it names the descriptor systemd hands it, so the
            # artifact a hostile `.env` row could once repoint is the SOCKET unit.
            # Assert the same property there — the renderer must take the port
            # from the pin, never from the hostile config.
            socket_body = (REPO / "units" / "oauth2-proxy.socket").read_text().replace(
                oauth2proxy.SOCKET_PORT_SENTINEL, str(sso.fleet_port(hostile)))
        self.assertIn('oidc_issuer_url = "https://accounts.google.com"', toml)
        self.assertNotIn("evil.example.test", toml)
        self.assertIn('http_address = "fd:3"', toml)
        self.assertIn("ListenStream=127.0.0.1:4180", socket_body)
        self.assertNotIn("9999", socket_body)

    def test_before_a_fleet_exists_config_still_decides(self) -> None:
        # .env may configure the FIRST install; after that the fleet decides.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t), sso_issuer_url="https://idp.example.test")
            toml = oauth2proxy.render_proxy_toml(cfg, "example.com")
        self.assertIn('oidc_issuer_url = "https://idp.example.test"', toml)

    def test_a_damaged_pin_is_refused_not_rendered(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            Path(cfg.sso_dir).mkdir(parents=True)
            sso.fleet_file(cfg).write_text(
                "VIDE_SSO_PARENT_DOMAIN=example.com\n"
                "VIDE_SSO_ISSUER_URL=http://plain.example.test\n"
                "VIDE_SSO_PROXY_PORT=4180\n")
            with self.assertRaises(ConfigError):
                oauth2proxy.render_proxy_toml(cfg, "example.com")


class TestConvergeRelandsTheAuthBody(unittest.TestCase):
    """The class name used to be TestConvergeLeavesTheAuthBlockAlone, and the
    rename is the change rather than a tidy-up.

    While the auth block was pasted verbatim, the persisted copy was the
    operator's reference and _auth_block_drift earned its keep by comparing it
    against what the build emits — so a converge that refreshed it made that
    comparison equal forever, disabling a working control while its code stayed
    in place. That is why the old rows asserted the file was NOT touched.

    The operator now pastes a site header and an import, so this file is the live
    config and VIDE owns it. Leaving it alone is the failure now: the fleet's
    login flow would stay frozen at whatever shipped with the box. What replaces
    the old caution is a lock rather than an abstention — the same one the
    per-instance bodies carry, because a re-render can REPOINT the fleet."""

    def _converged(self, t: Path, seed: str | None, *, held: bool = True,
                   migrated: bool = False):
        cfg = make_config(t)
        # exist_ok: the reload row converges the SAME box twice, which is the
        # only way to ask whether an unchanged body reloads Caddy again.
        Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).write_text("x")
        sso.persist_fleet(cfg, _FsExecutor(), "example.com",
                          issuer="https://accounts.google.com", proxy_port=4180)
        if seed is not None:
            (Path(cfg.sso_dir) / "caddy").mkdir(parents=True, exist_ok=True)
            (Path(cfg.sso_dir) / "caddy" / "auth.caddy").write_text(seed)
        rep, buf = capturing_reporter()
        # SEAMED, and it was not before this change. The auth-block advice used
        # to be a pure function of the pasted file; it now asks the box whether
        # the pin is being served, so an unseamed fixture reads the real
        # /proc/net/tcp, the real manager and the real /etc/systemd/system — and
        # this is T48's named test, so on any box WITHOUT a live root-held
        # reservation on the pin the row would go ALREADY-RED and the mutation
        # proof would report nothing at all. `certain={0}` is the ordinary
        # healthy box, which is what these rows are about.
        sysd = t / "sysd"
        sysd.mkdir(parents=True, exist_ok=True)
        with bare_host(oauth2proxy), \
             mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
             mock.patch.object(oauth2proxy.system, "hop_holders",
                               return_value=system.HopHolders(
                                   certain=frozenset({0}) if held else frozenset(),
                                   possible=frozenset(),
                                   served=frozenset())), \
             mock.patch.object(oauth2proxy, "ensure_identities"), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
            # MIGRATED IS PATCHED HERE, INSIDE, and that placement is the whole
            # reason it is a parameter rather than a `with` at the call site:
            # `bare_host` above patches the same manager readers, so a patch
            # applied outside this block is silently overridden by it and the
            # permit reads False no matter what the caller asked for.
            with contextlib.ExitStack() as stack:
                if migrated:
                    stack.enter_context(mock.patch.object(
                        oauth2proxy.system, "unit_state", return_value="active"))
                    stack.enter_context(mock.patch.object(
                        oauth2proxy.system, "unit_listen_streams",
                        return_value=["127.0.0.1:4180"]))
                oauth2proxy.converge_proxy(cfg, _FsExecutor(), rep,
                                           parent_domain="example.com",
                                           was_active=False)
        return cfg, buf.getvalue()

    def test_an_existing_body_is_re_landed(self) -> None:
        """THE POLICY INVERTED HERE, so this row inverted with it. While the file
        was the operator's reference copy, rewriting it disabled the drift
        detector; now it is the live config behind their import, and NOT
        rewriting it would freeze the fleet's login flow at whatever the box was
        first installed with."""
        with tempfile.TemporaryDirectory() as t:
            cfg, _ = self._converged(Path(t), seed="# stale, no hop here\n")
            landed = (Path(cfg.sso_dir) / "caddy" / "auth.caddy").read_text()
        self.assertNotIn("# stale", landed, "the body was left behind")
        self.assertIn("forward_auth 127.0.0.1:4180", landed)

    def test_a_changed_body_reloads_caddy_and_an_unchanged_one_does_not(self) -> None:
        """THE HALF THAT MAKES THE WRITE MEAN ANYTHING. Caddy holds its config in
        memory, so a re-rendered file nothing re-reads is a silent no-op — the
        converge would report success over a login host still running the old
        body. While the block was pasted verbatim the operator's own reload closed
        that gap; nothing else does now.

        And the negative half is not decoration: reloading on every converge
        regardless would bounce the fleet's front door on runs that changed
        nothing, which is how a safety measure becomes the thing operators
        disable."""
        with mock.patch.object(sso, "reload_caddy") as reload_:
            with tempfile.TemporaryDirectory() as t:
                self._converged(Path(t), seed="# stale, no hop here\n")
            self.assertTrue(reload_.called, "the body changed and Caddy never re-read it")
        with mock.patch.object(sso, "reload_caddy") as reload_:
            with tempfile.TemporaryDirectory() as t:
                cfg, _ = self._converged(Path(t), seed=None)
                current = (Path(cfg.sso_dir) / "caddy" / "auth.caddy").read_text()
                self._converged(Path(t), seed=current)
            self.assertEqual(reload_.call_count, 1,
                             "an unchanged body bounced the operator's front door")

    def test_the_static_pages_land_beside_it(self) -> None:
        """A body that rewrites to pages nobody wrote is a valid config serving
        404s on the fleet's login host."""
        with tempfile.TemporaryDirectory() as t:
            cfg, _ = self._converged(Path(t), seed=None)
            pages = Path(cfg.sso_dir) / "caddy" / "pages"
            for name in ("sign-in.html", "signed-out.html"):
                self.assertTrue((pages / name).is_file(), f"{name} missing")
                self.assertIn("<svg", (pages / name).read_text())

    def test_a_repoint_is_PERMITTED_once_the_gate_has_followed(self) -> None:
        """The other sign, and the one a refusal-only guard would break in
        silence. This is the documented move's LAST state: the pin moved, the
        reservation followed, the gate is demonstrably serving the destination —
        and the body must now be re-landed there, or every instance keeps
        forward_auth'ing at the address the fleet just left. A guard that refused
        every repoint would pass the refusal row above and strand this one."""
        from vide import caddy as _c
        stale = _c.emit_auth_body("example.com", 4199, sso_dir="/etc/vide/sso")
        # migrated=True is CASE 1 of the permit, and it has to be asked for
        # because `certain={0}` alone does NOT satisfy it: uid 0 on the address
        # is satisfied by any unrelated root daemon on a wildcard port, so
        # gate_is_on_hop also demands that OUR reservation is active and covers
        # this port. That conjunct is the false-permit the module's own docstring
        # records, and a fixture that skipped it would assert the permit while
        # proving the weaker claim.
        with tempfile.TemporaryDirectory() as t:
            cfg, out = self._converged(Path(t), seed=stale, held=True,
                                       migrated=True)
            landed = (Path(cfg.sso_dir) / "caddy" / "auth.caddy").read_text()
        self.assertIn("forward_auth 127.0.0.1:4180", landed)
        self.assertNotIn("4199", landed)
        self.assertNotIn("REFUSING", out)

    def test_a_repoint_is_refused_when_the_gate_is_not_on_the_pin(self) -> None:
        """The lock this file inherited when it joined the per-instance bodies'
        class. On a moved-pin box the reservation refuses to follow, so the gate
        stays on the OLD address — and re-rendering the body at the new pin would
        aim the login host at a port nobody serves. VIDE would take the fleet's
        login down out of the very run written to prevent that."""
        from vide import caddy as _c
        stale = _c.emit_auth_body("example.com", 4199, sso_dir="/etc/vide/sso")
        with tempfile.TemporaryDirectory() as t:
            cfg, out = self._converged(Path(t), seed=stale, held=False)
            landed = (Path(cfg.sso_dir) / "caddy" / "auth.caddy").read_text()
        self.assertIn("4199", landed, "the body was repointed anyway")
        self.assertNotIn("forward_auth 127.0.0.1:4180", landed)
        self.assertIn("REFUSING", out, "and the refusal must be said out loud")

    def test_an_absent_block_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg, _ = self._converged(Path(t), seed=None)
            self.assertIn("auth.example.com",
                          (Path(cfg.sso_dir) / "caddy" / "auth.caddy").read_text())


class TestConvergeIsUnconditional(unittest.TestCase):
    """Finding (1): the shared proxy's unit and proxy.toml used to be written
    only inside the first-install branch, so every hardening directive and every
    line of render_proxy_toml — trusted_proxy_ips included — described new boxes
    only, and nothing detected the drift. The split by credential is what makes
    the credential-free half runnable on every converge."""

    def _provisioned(self, t: Path):
        cfg = make_config(t)
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
            "cid.apps.googleusercontent.com", "GOCSPX-live", "COOKIE"))
        oauth2proxy.toml_path(cfg).write_text("# stale\n")
        Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).write_text("x")
        sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
        return cfg

    def test_converge_needs_no_credentials_and_rewrites_a_stale_toml(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                # No client_id/client_secret parameter exists to pass — that is
                # the structural point, not an omission in the test.
                oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(), was_active=False,
                                           parent_domain="example.com")
            self.assertIn("trusted_proxy_ips",
                          oauth2proxy.toml_path(cfg).read_text())

    def _converge_reporting(self, t, *, was_active: bool) -> str:
        import io

        from vide.reporter import Reporter
        cfg = self._provisioned(Path(t))
        buf = io.StringIO()
        # The installer is mocked out here, so the fixture has to leave behind
        # what it would have written: the converge's `enable` is now gated on the
        # fragment existing (an absent one is a hard error, and the move refusal
        # can decline with no file on disk). Unseamed, that gate would read the
        # developer's own /etc/systemd/system.
        sysd = Path(t) / "sysd"
        sysd.mkdir(parents=True, exist_ok=True)
        (sysd / oauth2proxy.SOCKET_UNIT).write_text("# installed\n")
        with mock.patch.object(oauth2proxy, "ensure_identities"), \
             mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=True), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                               return_value=False), \
             mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
            self.ex = _FsExecutor()
            oauth2proxy.converge_proxy(cfg, self.ex, Reporter(stream=buf),
                                       parent_domain="example.com",
                                       was_active=was_active)
        return buf.getvalue()

    def test_a_changed_unit_or_toml_reports_a_pending_restart(self) -> None:
        # It must REPORT, never restart: a converge is usually run for someone
        # else, and a failed restart takes the whole fleet's auth gate down.
        #
        # was_active is passed rather than observed. It used to be an inline
        # `systemctl is-active` inside converge_proxy, so this row — and the
        # mutation proof that names it — passed only where the box running the
        # tier happened to host a live vide-oauth2-proxy.service. Since
        # prove-teeth requires its named test to be green on the PRISTINE tree,
        # that made the whole proof hard-fail anywhere else, which is a green
        # suite that was a property of one machine.
        with tempfile.TemporaryDirectory() as t:
            out = self._converge_reporting(t, was_active=True)
            # The MESSAGE, not the verb name in it. A converge on a live box now
            # emits TWO warnings that both end in "sudo vide upgrade-sso" — this
            # one, and the reservation-pending row — so a substring assertion on
            # the verb stopped distinguishing them and this row silently lost its
            # teeth: the mutation proof that deletes this warn stayed green,
            # satisfied by the other message. Assert the sentence only this one
            # says.
            self.assertIn("the RUNNING process still has the old one", out)
            self.assertNotIn(("systemctl", "restart", oauth2proxy.UNIT), self.ex.ran)

    def test_a_first_install_does_not_report_a_pending_restart(self) -> None:
        """The negative arm, which never existed. was_active is the whole reason
        the gate is there: on a first install every file is trivially "changed"
        and the proxy is about to start fresh, so telling the operator a restart
        is owed is noise they learn to ignore — and noise is how a real pending
        restart later goes unread."""
        with tempfile.TemporaryDirectory() as t:
            out = self._converge_reporting(t, was_active=False)
            self.assertNotIn("upgrade-sso", out)

    T0 = 1_000_000.0

    def test_a_second_converge_does_not_restamp_an_unchanged_proxy_toml(self) -> None:
        """A converge that rewrites a body it just rendered identically restamps
        the file NEWER than the running proxy — and proxy.toml's mtime is an
        INPUT to upgrade-sso's restart decision. So every `sudo ./install.sh` on
        an SSO box made the next `sudo vide upgrade-sso` bounce the fleet's sole
        authorization gate for a run in which not one byte had changed.

        The fixed epoch is load-bearing: comparing "mtime before" against "mtime
        after" inside one test is satisfied by any filesystem whose timestamp
        granularity exceeds the test's runtime, which is a green that means
        nothing."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            toml = oauth2proxy.toml_path(cfg)
            # ONE cfg, converged twice. _converge_reporting re-provisions on
            # every call and re-stales the toml, so using it here would measure
            # the fixture rather than the converge.
            self._converge_twice(cfg, Path(t), toml)
            self.assertEqual(
                toml.stat().st_mtime, self.T0,
                "the converge restamped a byte-identical proxy.toml — the next "
                "upgrade-sso will read the fleet's gate as stale and restart it")

    def _converge_twice(self, cfg, t: Path, toml: Path) -> None:
        for i in range(2):
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(),
                                           parent_domain="example.com",
                                           was_active=True)
            if i == 0:
                os.utime(toml, (self.T0, self.T0))

    def test_a_stale_body_is_rewritten_and_restamped(self) -> None:
        """The anti-vacuity control for the row above, without which it is also
        satisfied by a converge that never writes proxy.toml at all."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            toml = oauth2proxy.toml_path(cfg)
            toml.write_text("# stale\n")
            os.utime(toml, (self.T0, self.T0))
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(),
                                           parent_domain="example.com",
                                           was_active=True)
            self.assertNotEqual(toml.stat().st_mtime, self.T0)
            self.assertIn("trusted_proxy_ips", toml.read_text())

    def test_a_proxy_toml_whose_mode_drifted_is_repaired_without_a_rewrite(self) -> None:
        """BOTH HALVES, and the second is what makes the first safe.

        Guarding the write on a byte-compare retired the only re-assertion of
        this file's 0640 root:vide-oauth2 posture, and the argument for
        accepting that — "the drift is fail-loud" — holds only for a NARROWING.
        A widening is silent: 0660 hands write access over the trusted-proxy
        CIDR to the one account on the box with a pre-authentication surface
        facing the internet, and nothing in the tree reads this file's mode.

        So the repair is back, and it must NOT be a rewrite: chmod moves ctime
        and leaves mtime alone, which is why it can coexist with the rule that
        this file's mtime only moves when its content does. The mtime assertion
        is the row that keeps the two from being reunited by a later tidy-up."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            toml = oauth2proxy.toml_path(cfg)
            # Converge once so the body is current, then widen the mode and
            # freeze the timestamp.
            self._converge_twice(cfg, Path(t), toml)
            toml.chmod(0o644)
            os.utime(toml, (self.T0, self.T0))
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(),
                                           parent_domain="example.com",
                                           was_active=True)
            ran = [tuple(a) for a in ex.ran]
            self.assertIn(("chmod", "0640", str(toml)), ran,
                          "a widened proxy.toml was left widened")
            # INSIDE the tmpdir's scope, deliberately: this assertion stats the
            # file, and outside it the directory is already gone — the failure
            # then reads as FileNotFoundError rather than as a moved mtime.
            self.assertEqual(toml.stat().st_mtime, self.T0,
                             "the posture repair restamped the file — that is a "
                             "rewrite wearing a chmod's name, and it re-arms the "
                             "next upgrade-sso to bounce the fleet's gate")

    def test_a_clean_proxy_toml_is_not_chmodded_on_every_converge(self) -> None:
        """The anti-noise sibling. A repair that fires on a healthy box is a
        line the operator learns to skip, and then it is not a repair.

        `path_facts` is STUBBED rather than arranged with a real `os.chown`: a
        chown to uid 0 needs root, so the arranged version was a row that only
        meant anything when the tier happened to run as root — silently vacuous
        everywhere else, on the same tier whose acceptance note argues that all
        its failures are one property of the runner."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            toml = oauth2proxy.toml_path(cfg)
            self._converge_twice(cfg, Path(t), toml)
            clean = oauth2proxy.system.PathFacts(
                is_symlink=False, is_dir=False, is_file=True,
                uid=0, gid=60000, mode=oauth2proxy.TOML_MODE)
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"), \
                 mock.patch.object(oauth2proxy.system, "path_facts", return_value=clean), \
                 mock.patch.object(oauth2proxy.system, "group_entry",
                                   return_value=(60000, set())):
                oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(),
                                           parent_domain="example.com",
                                           was_active=True)
            verbs = [a[0] for a in ex.ran]
        self.assertNotIn("chmod", verbs)
        self.assertNotIn("chown", verbs)

    def test_a_symlinked_proxy_toml_is_refused_rather_than_repaired(self) -> None:
        """path_facts is an LSTAT — it answers about the link — while chmod and
        chown DEREFERENCE. So repairing through one would read one file's
        posture and rewrite another's, and because a symlink's own mode is 0777
        by construction the comparison can never be satisfied: it would warn and
        mutate on every converge, forever, while the target drifted freely.

        And the state itself is what the lstat exists to catch — root's own
        config replaced by a pointer into somewhere writable — so it is a
        finding, not a thing to heal."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            link = oauth2proxy.system.PathFacts(
                is_symlink=True, is_dir=False, is_file=False,
                uid=1000, gid=1000, mode=0o777)
            ex = _FsExecutor()
            rep, buf = capturing_reporter()
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"), \
                 mock.patch.object(oauth2proxy.system, "path_facts", return_value=link):
                oauth2proxy.converge_proxy(cfg, ex, rep,
                                           parent_domain="example.com",
                                           was_active=True)
            verbs = [a[0] for a in ex.ran]
        self.assertNotIn("chmod", verbs, "VIDE chmod'd through a symlink")
        self.assertNotIn("chown", verbs, "VIDE chown'd through a symlink")
        self.assertIn("SYMLINK", buf.getvalue())

    def test_the_port_reservation_is_installed_and_enabled_but_never_forced(self) -> None:
        """The converge's half of the port fix, and the arm that stops the socket
        install being mocked into nonexistence everywhere else in this file.

        Three properties, and the third is the one that needs a test rather than
        a reading:
          * the socket unit is ENABLED whenever a fragment exists to enable —
            that is what puts the reservation into the boot transaction at
            sockets.target, the window no restart can substitute for, and it is
            deliberately not conditional on the write having CHANGED anything,
            because it is also what repairs the dangling sockets.target.wants
            symlink the documented move's `rm` leaves behind. The one state it
            skips is the one where there is no fragment at all, which `enable`
            cannot act on and which a refusal can now produce;
          * it is STARTED only when nothing was already serving, because a live
            proxy is still bound to the port itself and the socket cannot take it
            until the gate restarts;
          * the gate is NEVER restarted here. A converge runs for someone else.

        (This replaced a row that asserted the readiness budget outlasted the
        unit's StartLimit runway. That runway no longer exists — a start limit
        that fires hands the fleet's port back to the box — and the budget's new
        shape is pinned in TestTheRecoveryVerbsOutlastTheUnitTheyRestart.)"""
        for was_active in (False, True):
            with self.subTest(was_active=was_active), tempfile.TemporaryDirectory() as t:
                self._converge_reporting(t, was_active=was_active)
                ran = [tuple(a) for a in self.ex.ran]
                self.assertIn(("systemctl", "enable", oauth2proxy.SOCKET_UNIT), ran)
                started = ("systemctl", "start", oauth2proxy.SOCKET_UNIT) in ran
                self.assertEqual(started, not was_active)
                self.assertNotIn(("systemctl", "restart", oauth2proxy.UNIT), ran)
                self.assertNotIn(("systemctl", "restart", oauth2proxy.SOCKET_UNIT), ran)
                self.assertNotIn(("systemctl", "stop", oauth2proxy.SOCKET_UNIT), ran)


class TestCaddyAdminProbe(unittest.TestCase):
    """The socket's mode says which PROCESS may connect, not who may command it.
    Caddy's admin API is unauthenticated on 127.0.0.1:2019 by default, and
    `POST /load` replaces the running config — so a local account with no sudo
    can add a site reaching an instance socket with no forward_auth, and an SSO
    instance has no password behind it."""

    def _health(self, cfg, *, admin_open: bool):
        def fake_healthz(port, *, path="/healthz", timeout=3.0):
            if port == oauth2proxy.CADDY_ADMIN_PORT:
                return admin_open
            return True
        # bare_host, not a lone `query` patch: proxy_health's unit and group
        # reads went through grp.getgrnam and the named seams, which a query
        # patch no longer covers — so this row was reading the real box for its
        # unit state and its vide-proxy membership while appearing hermetic.
        # `live=` names the one unit it means to be running.
        with mock.patch.object(oauth2proxy.system, "query") as q, \
             bare_host(oauth2proxy, live=(oauth2proxy.UNIT,),
                       identities=(oauth2proxy.PROXY_GROUP,),
                       members=("caddy",), probe=fake_healthz), \
             mock.patch.object(oauth2proxy, "bootstrap_observed", return_value=True):
            q.return_value = mock.Mock(returncode=0, stdout="0")
            return oauth2proxy.proxy_health(cfg, check_staleness=False)

    def test_an_open_admin_api_fails_the_sso_section_and_names_the_fix(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ok, lines = self._health(make_config(Path(t)), admin_open=True)
        body = "\n".join(lines)
        self.assertFalse(ok)
        self.assertIn("2019", body)
        # It must point at the doc rather than paste a one-liner that does not
        # work: `admin unix//run/caddy/admin.sock` alone fails to bind on a
        # packaged Caddy (User=caddy, /run root-owned, no RuntimeDirectory=) and
        # takes the operator's whole front door down.
        self.assertIn("docs/sso.md", body)
        self.assertIn("RuntimeDirectory=caddy", body)
        # `admin off` would break vide allow/revoke, which reload caddy through
        # this API — recommending it would be worse than the finding.
        self.assertIn("Do NOT use `admin off`", body)

    def test_a_closed_admin_api_says_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            _, lines = self._health(make_config(Path(t)), admin_open=False)
        self.assertNotIn("caddy admin", "\n".join(lines))

    def test_the_probe_never_reads_the_operators_running_config(self) -> None:
        """/config/ returns ACME references, DNS-provider tokens and basic_auth
        hashes. Pulling those into VIDE's process to detect an exposure would be
        worse than the exposure.

        `bare_host`, not a lone `query` patch, and the reason is not tidiness.
        This was the last `proxy_health` call site outside a double: a `query`
        patch cannot reach `grp.getgrnam`, `pwd.getpwnam` or a /proc read, so
        this row consulted the machine running the tier for its group database,
        the proxy user's uid and the fleet port's holder. No assertion depended
        on any of them — which is exactly how the previous three host reads
        survived. What made it worth fixing rather than accepting is that this
        test is NAMED BY A MUTATION ROW: a host read that fails turns the proof
        into "the named test is ALREADY RED on the pristine tree", i.e. a proof
        that reports the box instead of the tree."""
        seen: list[str] = []

        def fake_healthz(port, *, path="/healthz", timeout=3.0):
            seen.append(path)
            return False
        with tempfile.TemporaryDirectory() as t, \
             bare_host(oauth2proxy, probe=fake_healthz), \
             mock.patch.object(oauth2proxy.system, "query") as q, \
             mock.patch.object(oauth2proxy, "bootstrap_observed", return_value=True):
            q.return_value = mock.Mock(returncode=1, stdout="")
            oauth2proxy.proxy_health(make_config(Path(t)), check_staleness=False)
        self.assertIn("/reverse_proxy/upstreams", seen)
        self.assertNotIn("/config/", seen)


class TestRotatePrevHygiene(unittest.TestCase):
    """rotate-sso keeps a .prev (old cookie secret + LIVE client secret) only
    as its own rollback vehicle. It must not outlive the verb on EITHER path:
    after a proven-good rotation it is stale secret material; after a failed
    one its content is already restored into proxy.env."""

    def _provisioned(self, t: Path):
        cfg = make_config(t)
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        oauth2proxy.toml_path(cfg).write_text("# toml\n")
        oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
            "cid.apps.googleusercontent.com", "GOCSPX-live", "OLDCOOKIE"))
        Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).write_text("x")
        return cfg

    def _assert_no_litter(self, cfg) -> None:
        # A directory SWEEP, not a recomputed .prev path: if the rollback file
        # is ever renamed, a path-equality assertion goes vacuously green
        # while the secret material rots under the new name.
        leftovers = ({p.name for p in Path(cfg.sso_dir).iterdir()}
                     - {"proxy.env", "proxy.toml"})
        self.assertEqual(leftovers, set(),
                         "rotate-sso left secret-material litter on disk")

    def test_successful_rotation_removes_the_prev(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "_proxy_pings", return_value=True):
                oauth2proxy.rotate_sso(cfg, ex, quiet_reporter())
            self.assertNotIn("OLDCOOKIE", oauth2proxy.env_path(cfg).read_text(),
                             "the cookie secret was not actually rotated")
            self._assert_no_litter(cfg)

    def test_failed_rotation_restores_and_removes_the_prev(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._provisioned(Path(t))
            ex = _FsExecutor()
            with mock.patch.object(oauth2proxy, "_proxy_pings", return_value=False):
                with self.assertRaises(StateError):
                    oauth2proxy.rotate_sso(cfg, ex, quiet_reporter())
            env = oauth2proxy.env_path(cfg).read_text()
            self.assertIn("OLDCOOKIE", env, "the rollback did not restore")
            self.assertIn("GOCSPX-live", env)
            self._assert_no_litter(cfg)


class TestTheRestartDecisionAsksAboutTheRUNNINGProcess(unittest.TestCase):
    """The decision that restarts the fleet's sole authorization gate had no
    test driving its body. It could `return True` unconditionally — which is
    "bounce the gate on every run", the defect that actually shipped — or return
    nothing, which is "the migration never lands", and BOTH were green: the one
    row that named it mocked the predicate itself, and its sibling ran on a
    fixture with no process at all.

    Driven here as the pure function it was refactored into, one input at a
    time, which is the only shape in which "unknown does not decide" can be
    asserted separately from "unchanged does not decide". The end-to-end chain
    through real files and real mtimes is
    TestTheRecoveryVerbsOutlastTheUnitTheyRestart._upgrade_with_socket; the
    reader underneath is TestProcessStartTimeIsNotTheInodeStamp."""

    T0 = 1_000_000.0        # a fixed epoch, never time.time(). See the note on
                            # the same constant below: a before/after comparison
                            # against "now" is vacuous wherever the filesystem's
                            # granularity is coarser than the test.
    SERVICE = f"/etc/systemd/system/{oauth2proxy.UNIT}"
    SOCKET = f"/etc/systemd/system/{oauth2proxy.SOCKET_UNIT}"
    TOML = "/etc/vide/sso/proxy.toml"

    def _decide(self, **over):
        """Everything current and readable — a fully migrated box that owes
        nothing — with one input replaced per row. A default fixture that is
        already interesting cannot tell you which input moved the answer."""
        kw = dict(wrote=[], gate_state="active", pid=4242, started=self.T0 + 60,
                  written={self.SERVICE: self.T0, self.SOCKET: self.T0,
                           self.TOML: self.T0},
                  socket_state="active")
        kw.update(over)
        return oauth2proxy._restart_reasons(**kw)

    def test_the_three_gate_inputs_are_exactly_these_three(self) -> None:
        """THE INPUT SELECTION, which the refactor moved out of the tested
        surface and nothing put back. `_restart_reasons` receives `written` as a
        caller-built dict, so every row in this class proves what the decision
        does with three names it was HANDED — never that those are the right
        three. And every end-to-end row moves all three files at once, so any
        single member could be deleted with the whole suite green.

        The box that breaks is the one this release is about: a converge writes
        a hardened SERVICE unit on a migrated box, warns that a restart is
        pending, and the operator runs the verb that message names. By then
        `unit_changed` is False (the converge wrote it), the gate is active, the
        socket is active and proxy.toml is unchanged — so the service unit's
        mtime is the only clause left. Drop it and the hardening never lands
        while the verb reports success: defect 1, verbatim."""
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            names = [p.name for p in oauth2proxy._gate_inputs(cfg)]
        self.assertEqual(names, [oauth2proxy.UNIT, oauth2proxy.SOCKET_UNIT,
                                 "proxy.toml"])
        # …AND THE TWO EXCLUSIONS THE DOCSTRING ARGUES FOR, which are the half a
        # membership list cannot express by being right about what it contains.
        # The union file is HOT-RELOADED by the proxy, so listing it would make
        # every `vide allow` owe the fleet a gate restart; proxy.env IS read
        # once at exec, but its writers restart the gate themselves AND
        # record_credentials rewrites it unconditionally — which would re-import
        # the bounce-every-run defect through the back door.
        self.assertNotIn("proxy.env", names)
        self.assertNotIn("authenticated-emails", " ".join(names))

    def test_a_process_younger_than_all_three_is_not_stale(self) -> None:
        """THE arm the restamp defect broke, and the baseline every row below
        varies from: nothing was written, the gate is up, the reservation is in
        effect, and the running process is newer than its files. Silence is the
        only correct answer, and it must be silence in BOTH channels — an
        `unreadable` here would make the verb warn on every migrated box."""
        reasons, unreadable = self._decide()
        self.assertEqual(reasons, [])
        self.assertEqual(unreadable, [])

    def test_a_service_unit_newer_than_the_process_is_stale(self) -> None:
        reasons, _ = self._decide(
            written={self.SERVICE: self.T0 + 600, self.SOCKET: self.T0,
                     self.TOML: self.T0})
        self.assertEqual(len(reasons), 1)
        self.assertIn(oauth2proxy.UNIT, reasons[0])

    def test_a_socket_unit_newer_than_the_process_is_stale(self) -> None:
        """The artifact this release ADDS. A decision watching only the service
        and proxy.toml would miss the migration entirely — the box would keep
        the unit it had, and the reservation would never take effect."""
        reasons, _ = self._decide(
            written={self.SERVICE: self.T0, self.SOCKET: self.T0 + 600,
                     self.TOML: self.T0})
        self.assertEqual(len(reasons), 1)
        self.assertIn(oauth2proxy.SOCKET_UNIT, reasons[0])

    def test_a_proxy_toml_newer_than_the_process_is_stale(self) -> None:
        reasons, _ = self._decide(
            written={self.SERVICE: self.T0, self.SOCKET: self.T0,
                     self.TOML: self.T0 + 600})
        self.assertEqual(len(reasons), 1)
        self.assertIn("proxy.toml", reasons[0])

    def test_no_running_process_is_reported_rather_than_decided(self) -> None:
        """The exit that made "an already-migrated gate is not bounced" vacuous:
        with no MainPID the decision stops before it reaches any file compare,
        so a fixture without a process asserts nothing about staleness at all.

        It must not restart — an unattributable process is not evidence that it
        is behind — and it must SAY so, or the verb prints "current" over a box
        it could not read."""
        reasons, unreadable = self._decide(pid=None, started=None)
        self.assertEqual(reasons, [])
        self.assertTrue(any("could not read when the running" in u
                            for u in unreadable), unreadable)

    def test_an_unreadable_start_time_does_not_bounce_the_gate(self) -> None:
        """hidepid=, a masked /proc, a pid that exited between the two reads.
        Fail-safe direction, and its sibling above is the row that stops this
        being satisfied by "never restart"."""
        reasons, unreadable = self._decide(started=None)
        self.assertEqual(reasons, [])
        self.assertNotEqual(unreadable, [])

    def test_a_file_that_cannot_be_stat_ed_is_reported_not_read_as_stale(self) -> None:
        """AN INPUT THAT CANNOT BE READ MAY NOT DECIDE. None here is "I could
        not look", and counting it as "newer" would restart the gate on every
        run of a box mid-install."""
        reasons, unreadable = self._decide(
            written={self.SERVICE: None, self.SOCKET: self.T0, self.TOML: self.T0})
        self.assertEqual(reasons, [])
        self.assertTrue(any(self.SERVICE in u for u in unreadable), unreadable)

    def test_a_gate_that_is_not_running_is_always_a_reason(self) -> None:
        """Printing "unit and config current" over a dead gate is the
        silence-that-reads-as-health this tree keeps paying for."""
        for word in ("inactive", "failed"):
            with self.subTest(word=word):
                reasons, _ = self._decide(gate_state=word)
                self.assertTrue(any(word in r for r in reasons), reasons)

    def test_a_gate_mid_transition_is_neither_restarted_nor_believed(self) -> None:
        """`activating` is NOT "not running": restarting a proxy in the middle
        of a slow OIDC discovery turns a healthy start into a failed one and
        sends the operator to roll back a binary that is fine. And `unknown` is
        this reader failing, not a state word — counting it would bounce the
        gate on every run of a box whose systemctl is wedged."""
        for word in ("activating", "deactivating", "reloading", "unknown"):
            with self.subTest(word=word):
                reasons, unreadable = self._decide(gate_state=word)
                self.assertEqual(reasons, [])
                self.assertNotEqual(unreadable, [])

    def test_a_reservation_that_is_not_in_effect_is_a_reason(self) -> None:
        """The one state disk cannot show. A socket unit stopped or masked AFTER
        the gate came up leaves no file trace: the live process keeps serving on
        the descriptor it already holds, and the address goes back to the box
        the moment it exits."""
        for word in ("inactive", "failed", "masked"):
            with self.subTest(word=word):
                reasons, _ = self._decide(socket_state=word)
                self.assertTrue(any(oauth2proxy.SOCKET_UNIT in r for r in reasons),
                                reasons)

    def test_an_unreadable_socket_state_does_not_decide_either(self) -> None:
        """This exact clause shipped as a restart: a timed-out
        `systemctl is-active` bounced the fleet's gate on every run."""
        reasons, unreadable = self._decide(socket_state="unknown")
        self.assertEqual(reasons, [])
        self.assertNotEqual(unreadable, [])

    def test_this_runs_own_writes_decide_without_any_host_read(self) -> None:
        """The one clause that touches no host read at all. On a box where
        nothing can be attributed it is still a FACT that this run rewrote those
        files seconds ago — which is what stops an unreadable box becoming a
        silent no-op."""
        reasons, _ = self._decide(
            wrote=[oauth2proxy.SOCKET_UNIT], gate_state="unknown",
            pid=None, started=None,
            written={self.SERVICE: None, self.SOCKET: None, self.TOML: None},
            socket_state="unknown")
        self.assertTrue(any(oauth2proxy.SOCKET_UNIT in r for r in reasons), reasons)

    def test_the_slack_absorbs_btimes_rounding_and_nothing_larger(self) -> None:
        """btime is printed in WHOLE SECONDS and floored, so the reader is up to
        one second EARLY and never late — an error whose direction is "the
        running process looks older than it is", i.e. toward bouncing a freshly
        installed box. The slack cancels exactly that.

        Both directions are asserted, because a slack that quietly widened would
        swallow a real operator edit and leave the fix permanently unapplied."""
        near, _ = self._decide(
            written={self.SERVICE: self.T0 + 60.5, self.SOCKET: self.T0,
                     self.TOML: self.T0}, started=self.T0 + 60)
        self.assertEqual(near, [], "sub-second rounding was read as a real edit")
        real, _ = self._decide(
            written={self.SERVICE: self.T0 + 62, self.SOCKET: self.T0,
                     self.TOML: self.T0}, started=self.T0 + 60)
        self.assertEqual(len(real), 1, "a two-second-newer unit was swallowed")


class TestTheRecoveryVerbsOutlastTheUnitTheyRestart(unittest.TestCase):
    """Both SSO recovery verbs restart the fleet's SOLE authentication gate, and
    both were wrong about what happens next in opposite directions: one gave up
    before the unit's own retry runway had elapsed, the other never looked."""

    def test_the_wait_spends_the_whole_budget_in_WALL_CLOCK_not_iterations(self) -> None:
        """It waited 20s against a 120s runway, so a slow OIDC discovery — the
        exact transient the runway exists for — read as "the proxy rejected the
        new cookie secret", and rotate-sso RESTORED the secret it was invoked to
        burn.

        MEASURED ON A DRIVEN CLOCK, and that is the point of the test rather than
        an implementation detail of it. The loop used to be
        `for _ in range(BUDGET)` with `sleep(1)`, i.e. it counted ITERATIONS and
        called them seconds. That equivalence held only while a failed probe was
        free — and it stopped being free the day the port was reserved, because
        connect(2) now succeeds into systemd's accept queue instead of being
        refused, so every miss also costs its own timeout. Counting iterations
        overshot the documented budget by more than half again.

        So the loop reads a clock, and this test owns the clock: sleep advances
        it, and the probe charges PROXY_PING_TIMEOUT_S for every miss exactly as
        the real one does. A test that patched sleep to a no-op and counted calls
        would not merely be weaker here — it would spin for the full budget in
        REAL seconds, which is how this was found."""
        now = [0.0]
        slept: list[float] = []

        def fake_sleep(n: float) -> None:
            slept.append(n)
            now[0] += n

        # `port` is accepted and IGNORED, which is the double telling the truth
        # about the real signature: _proxy_pings resolves the gate's address ONCE
        # and hands it to every probe, so a double that refused the argument would
        # make this row red for a reason that has nothing to do with the clock.
        def charging_probe(_cfg, *, timeout: float, port=None) -> bool:
            now[0] += timeout       # a miss costs its timeout, as in production
            return False

        # bare_host because resolving that address reads the host: the loop now
        # asks the manager what the reservation is configured for before it
        # probes anything. Unseamed, this row's clock arithmetic would sit on top
        # of a `systemctl` against the machine running the tier.
        with bare_host(oauth2proxy), \
             mock.patch.object(oauth2proxy, "proxy_answers", charging_probe), \
             mock.patch("time.monotonic", lambda: now[0]), \
             mock.patch("time.sleep", fake_sleep):
            self.assertFalse(oauth2proxy._proxy_pings(make_config(Path("/nonexistent"))))
        # Wall clock spent is the budget — not more, and the loop terminated.
        self.assertGreaterEqual(now[0], oauth2proxy.UNIT_RESTART_BUDGET_S)
        self.assertLess(now[0], oauth2proxy.UNIT_RESTART_BUDGET_S
                        + 1 + oauth2proxy.PROXY_PING_TIMEOUT_S)
        # And it did NOT simply iterate BUDGET times: charging the probe means
        # fewer, larger steps. This is the assertion that goes red if anyone
        # re-anchors the loop on an iteration count.
        self.assertLess(len(slept), oauth2proxy.UNIT_RESTART_BUDGET_S)

    def test_the_budget_is_a_stated_willingness_to_wait_not_a_grep(self) -> None:
        """The budget used to be derived from the unit's own StartLimit runway and
        pinned against it here. That derivation is GONE — the limiter had to be
        switched off, because a start limit that fires makes systemd close the
        listening descriptor and hand the fleet's authorization port back to the
        box. So the unit must carry no start limit at all, and the budget must be
        written as the decision it now is: RestartSec x an attempt count.

        Both halves are asserted, because either alone is satisfiable by an
        accident: a constant that happens to equal 120, or a unit that happens to
        have no StartLimitBurst because someone deleted the wrong line."""
        unit = (REPO / "units" / "oauth2-proxy.service").read_text()
        self.assertIsNone(re.search(r"^StartLimitBurst=", unit, re.M),
                          "a start limit on this unit frees the fleet's port when "
                          "it fires — see the four-link chain in the unit comment")
        self.assertRegex(unit, r"(?m)^StartLimitIntervalSec=0$")
        sec = int(re.search(r"^RestartSec=(\d+)$", unit, re.M).group(1))
        self.assertEqual(oauth2proxy.UNIT_RESTART_S, sec,
                         "UNIT_RESTART_S must track the unit's RestartSec")
        self.assertEqual(
            oauth2proxy.UNIT_RESTART_BUDGET_S,
            oauth2proxy.UNIT_RESTART_S * oauth2proxy.UNIT_RESTART_ATTEMPTS)
        # The value itself must still cover a slow cold-boot OIDC discovery; it is
        # the one property that did not change when the derivation did.
        self.assertGreaterEqual(oauth2proxy.UNIT_RESTART_BUDGET_S, 100)

    def _upgradeable(self, t: Path):
        cfg = make_config(t)
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        d = Path(cfg.oauth2_proxy_dir)
        for v in ("7.15.2", "7.15.3"):
            (d / v).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).symlink_to(d / "7.15.2")
        oauth2proxy.toml_path(cfg).write_text("# toml\n")
        oauth2proxy.env_path(cfg).write_text("X=1\n")
        return cfg, d

    def test_an_upgrade_that_leaves_the_fleet_dark_does_not_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg, d = self._upgradeable(Path(t))
            with mock.patch.object(oauth2proxy, "resolve_version", return_value="7.15.4"), \
                 mock.patch.object(oauth2proxy, "installed_version", return_value="7.15.2"), \
                 mock.patch.object(oauth2proxy, "install_version", return_value="sha"), \
                 mock.patch.object(oauth2proxy, "flip_current"), \
                 mock.patch.object(oauth2proxy, "record_version"), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit",
                                   return_value=False), \
                 mock.patch.object(sso, "rerender_bodies"), \
                 mock.patch.object(oauth2proxy, "_proxy_pings", return_value=False):
                with self.assertRaises(StateError) as cm:
                    oauth2proxy.upgrade_sso(cfg, _FsExecutor(), quiet_reporter())
            msg = str(cm.exception)
            self.assertIn("only authentication gate is down", msg)
            self.assertIn("reset-failed", msg)
            # …and the rollback lever is still on disk. prune() keeps exactly one
            # previous version; running it on the way out of a failed upgrade
            # would delete the one thing the operator needs.
            self.assertTrue((d / "7.15.3").is_dir(),
                            "the failed upgrade pruned the version it tells the "
                            "operator to roll back to")

    def test_a_healthy_upgrade_still_prunes(self) -> None:
        # The opposite sign, because a guard that never lets prune run and one
        # that never runs it are the same defect with different symptoms.
        with tempfile.TemporaryDirectory() as t:
            cfg, d = self._upgradeable(Path(t))
            (d / "7.14.0").mkdir(parents=True, exist_ok=True)
            with mock.patch.object(oauth2proxy, "resolve_version", return_value="7.15.4"), \
                 mock.patch.object(oauth2proxy, "installed_version", return_value="7.15.2"), \
                 mock.patch.object(oauth2proxy, "install_version", return_value="sha"), \
                 mock.patch.object(oauth2proxy, "flip_current"), \
                 mock.patch.object(oauth2proxy, "record_version"), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit",
                                   return_value=False), \
                 mock.patch.object(sso, "rerender_bodies"), \
                 mock.patch.object(oauth2proxy, "_proxy_pings", return_value=True):
                oauth2proxy.upgrade_sso(cfg, _FsExecutor(), quiet_reporter())
            self.assertFalse((d / "7.14.0").is_dir(), "prune did not run")

    def test_upgrade_lands_the_port_reservation_on_both_paths(self) -> None:
        """`upgrade-sso` is the ONLY lever that migrates an existing box, so the
        socket unit must be asserted on both paths through the verb — including
        the one where the binary is already at the pinned version, which is the
        box that has been un-migrated longest.

        This row exists because every other test in this file mocks
        install_proxy_socket_unit, and a mocked call that nothing asserts is a
        call that can be deleted without a single test going red."""
        for already_current in (True, False):
            with self.subTest(already_current=already_current), \
                 tempfile.TemporaryDirectory() as t:
                cfg, _ = self._upgradeable(Path(t))
                ex = _FsExecutor()
                installed = "7.15.4" if already_current else "7.15.2"
                # See _converge_reporting: the installer is mocked, so the
                # fragment its `enable` is gated on has to be modelled.
                sysd = Path(t) / "sysd"
                sysd.mkdir(parents=True, exist_ok=True)
                (sysd / oauth2proxy.SOCKET_UNIT).write_text("# installed\n")
                with mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                     mock.patch.object(oauth2proxy, "resolve_version", return_value="7.15.4"), \
                     mock.patch.object(oauth2proxy, "installed_version", return_value=installed), \
                     mock.patch.object(oauth2proxy, "install_version", return_value="sha"), \
                     mock.patch.object(oauth2proxy, "flip_current"), \
                     mock.patch.object(oauth2proxy, "record_version"), \
                     mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
                     mock.patch.object(oauth2proxy, "_proxy_pings", return_value=True), \
                     mock.patch.object(sso, "rerender_bodies"), \
                     mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                       return_value=False) as sock:
                    oauth2proxy.upgrade_sso(cfg, ex, quiet_reporter())
                self.assertTrue(sock.called, "the reservation unit was not asserted")
                # …and with the PIN. `called` alone would survive this verb
                # passing cfg.sso_proxy_port, which would reserve one port while
                # every renderer dials another.
                self.assertEqual(sock.call_args.args[-1], sso.fleet_port(cfg),
                                 "upgrade-sso reserved a port that is not the pin")
                self.assertIn(("systemctl", "enable", oauth2proxy.SOCKET_UNIT),
                              [tuple(a) for a in ex.ran])

    T0 = 1_000_000.0        # a fixed epoch, never time.time(): an mtime assertion
                            # written as before/after "now" is vacuous wherever
                            # the filesystem's timestamp granularity is coarser
                            # than the test.

    def _upgrade_with_socket(self, t: Path, socket_state: str, *,
                             proxy_started: str = "after",
                             gate_state: str = "active"):
        """upgrade-sso on a box where every FILE is already current — the state a
        converge leaves behind — with the socket unit in a given live state AND
        the running gate's age said out loud.

        `proxy_started` is why this helper changed shape. The old one patched
        nothing below `unit_state`, so on a box with no systemd `unit_main_pid`
        answered None and the staleness question exited at its first line: the
        row asserting "an already-migrated gate is not bounced" was green because
        there was NO PROCESS, not because the gate was current. A negative
        assertion whose subject does not exist is not an assertion — and that is
        precisely the gap a converge restamping proxy.toml walked through.

        SYSTEMD_DIR is redirected into the sandbox for the same reason: with the
        literal path inlined, this row stat'd the unit files of the machine
        running the tier."""
        cfg, _ = self._upgradeable(Path(t))
        sysd = Path(t) / "systemd"
        sysd.mkdir(parents=True, exist_ok=True)
        for name in (oauth2proxy.UNIT, oauth2proxy.SOCKET_UNIT):
            (sysd / name).write_text("[Unit]\n")
            os.utime(sysd / name, (self.T0, self.T0))
        os.utime(oauth2proxy.toml_path(cfg), (self.T0, self.T0))
        started = self.T0 + 60 if proxy_started == "after" else self.T0 - 60
        ex = _FsExecutor()
        with mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
             mock.patch.object(oauth2proxy, "resolve_version", return_value="7.15.4"), \
             mock.patch.object(oauth2proxy, "installed_version", return_value="7.15.4"), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "_proxy_pings", return_value=True), \
             mock.patch.object(sso, "rerender_bodies"), \
             mock.patch.object(oauth2proxy.system, "unit_main_pid", return_value=4242), \
             mock.patch.object(oauth2proxy.system, "proc_start_realtime", return_value=started), \
             mock.patch.object(oauth2proxy.system, "unit_state",
                               side_effect=lambda u: (socket_state
                                                      if u == oauth2proxy.SOCKET_UNIT
                                                      else gate_state)):
            oauth2proxy.upgrade_sso(cfg, ex, quiet_reporter())
        return [tuple(a) for a in ex.ran]

    def test_upgrade_restarts_when_the_reservation_is_not_yet_in_effect(self) -> None:
        """THE CLOSED LOOP, and the reason this row exists at all.

        The documented order is "install this version, then run upgrade-sso". By
        the time the operator gets here the converge has already written the
        socket unit, proxy.toml and the service unit — so a restart condition
        made of FILE comparisons is all-False, the verb reports "unit and config
        current", nothing restarts, the running proxy keeps holding the port it
        bound itself, and `vide doctor` goes on naming the same command. The fix
        would never have landed on any box in the fleet, and every register in
        the tree would have been describing a closure that never happened.

        The question a file compare cannot answer is whether the reservation is
        IN EFFECT, which is live state: the socket unit listening."""
        with tempfile.TemporaryDirectory() as t:
            # proxy_started="after": this row now restarts because the
            # RESERVATION is not in effect and for no other reason. Previously,
            # on any box that runs VIDE, the staleness clause was true as well
            # and the row passed for two reasons at once.
            ran = self._upgrade_with_socket(Path(t), "inactive",
                                            proxy_started="after")
        self.assertIn(("systemctl", "restart", oauth2proxy.UNIT), ran,
                      "upgrade-sso declined to restart on a box whose port "
                      "reservation is not in effect — the migration can never "
                      "complete")

    def test_upgrade_restarts_when_the_running_proxy_predates_its_config(self) -> None:
        """The OTHER half of the same loop, and it survived the first fix.

        On a migrated box a converge writes a changed unit or proxy.toml, warns
        MSG_PROXY_RESTART_PENDING, and deliberately does not restart. The
        operator then runs the verb that message names — and its byte-compares
        are all equal, because the converge wrote those very files moments ago.
        So the pending-restart warning dead-ended: doctor and the message both
        pointed at a command that declined to act.

        The live question is whether the RUNNING process is older than what it is
        supposed to be running with."""
        # THE MOCK THAT HID DEFECT 2 IS GONE. This used to patch the staleness
        # predicate itself, so it proved the call site and nothing below it —
        # while its sibling below was green because the fixture had no running
        # process at all. Now the real decision runs, and this row restarts
        # because of the file ages ALONE: nothing else in the fixture differs
        # from the sibling.
        with tempfile.TemporaryDirectory() as t:
            ran = self._upgrade_with_socket(Path(t), "active", proxy_started="before")
        self.assertIn(("systemctl", "restart", oauth2proxy.UNIT), ran,
                      "a proxy running an older unit/config was left running it")

    def test_upgrade_does_not_bounce_a_gate_that_is_already_migrated(self) -> None:
        """The opposite sign, which is what stops the fix above being 'restart
        always'. `vide upgrade-sso` is a verb operators run to check on things;
        if it bounced the fleet's sole authorization gate every time, they would
        stop running it — and it is the lever three messages point at."""
        with tempfile.TemporaryDirectory() as t:
            ran = self._upgrade_with_socket(Path(t), "active")
        self.assertNotIn(("systemctl", "restart", oauth2proxy.UNIT), ran)


class TestAConvergeDoesNotMakeTheNextUpgradeBounceTheGate(unittest.TestCase):
    """THE row this round was missing, and the shape of the miss is worth
    recording: BOTH HALVES WERE GREEN IN ISOLATION. The converge wrote a
    byte-identical proxy.toml and no row asserted an mtime; upgrade-sso's
    "already migrated" row passed on a fixture that had no running process at
    all. The defect lived in the gap between two green tests, and only a row
    that spans two verbs can stand in that gap.

    The documented order, executed: install this version (converge), then run
    the verb three separate messages point at.

    What is mocked here and why, because a cross-verb row that mocks the wrong
    thing proves nothing: `resolve_version`/`installed_version` (network),
    `install_proxy_unit`/`install_proxy_socket_unit` (they write into
    /etc/systemd/system, outside every sandbox — so the two files are placed by
    hand at T0, which is exactly what those installers would have left),
    `_proxy_pings`, `rerender_bodies`, `ensure_identities`,
    `ensure_caddy_membership`. NOT mocked: the proxy.toml write, the restart
    decision, and system.path_mtime — the three things the defect ran through."""

    T0 = 1_000_000.0
    STARTED = T0 + 1        # the gate came up one second after its files, which
                            # is what "a converge, then enable --now" leaves

    def _provisioned(self, t: Path):
        cfg = make_config(t)
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
            "cid.apps.googleusercontent.com", "GOCSPX-live", "COOKIE"))
        oauth2proxy.toml_path(cfg).write_text("# stale\n")
        Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).write_text("x")
        sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
        return cfg

    def _converge(self, cfg, *, was_active: bool) -> None:
        ex = _FsExecutor()
        with mock.patch.object(oauth2proxy, "ensure_identities"), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                               return_value=False), \
             mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
            oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(),
                                       parent_domain="example.com",
                                       was_active=was_active)

    def _walk(self, t: Path, *, edit=None):
        """converge → stamp everything at T0 → converge again → upgrade-sso.

        The stamping stands in for "this is what the box looked like when the
        gate last started". Everything after it is the product's own doing, and
        `path_mtime` reads the real files."""
        cfg = self._provisioned(Path(t))
        toml = oauth2proxy.toml_path(cfg)
        sysd = Path(t) / "systemd"
        sysd.mkdir(parents=True, exist_ok=True)
        self._converge(cfg, was_active=False)
        for name in (oauth2proxy.UNIT, oauth2proxy.SOCKET_UNIT):
            (sysd / name).write_text("[Unit]\n")
            os.utime(sysd / name, (self.T0, self.T0))
        os.utime(toml, (self.T0, self.T0))
        # The second converge — the ordinary `sudo ./install.sh` for some other
        # user, on a box whose gate is already up. Nothing about it has changed
        # a byte, and it must leave nothing behind that the next verb reads as a
        # reason to restart.
        self._converge(cfg, was_active=True)
        if edit is not None:
            edit(toml)
        ex = _FsExecutor()
        with mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
             mock.patch.object(oauth2proxy, "resolve_version", return_value="7.15.4"), \
             mock.patch.object(oauth2proxy, "installed_version", return_value="7.15.4"), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                               return_value=False), \
             mock.patch.object(oauth2proxy, "_proxy_pings", return_value=True), \
             mock.patch.object(sso, "rerender_bodies"), \
             mock.patch.object(oauth2proxy.system, "unit_main_pid", return_value=4242), \
             mock.patch.object(oauth2proxy.system, "proc_start_realtime",
                               return_value=self.STARTED), \
             mock.patch.object(oauth2proxy.system, "unit_state", return_value="active"):
            oauth2proxy.upgrade_sso(cfg, ex, quiet_reporter())
        return cfg, toml, [tuple(a) for a in ex.ran]

    def test_a_converge_then_an_upgrade_leaves_the_gate_alone(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            _, _, ran = self._walk(Path(t))
        self.assertNotIn(
            ("systemctl", "restart", oauth2proxy.UNIT), ran,
            "the converge restamped a file the restart decision reads, so every "
            "`sudo ./install.sh` on an SSO box now costs the fleet's sole "
            "authorization gate a bounce on the next upgrade-sso")

    def test_an_operator_edit_to_proxy_toml_still_earns_a_restart(self) -> None:
        """The opposite sign, and without it the row above is satisfied by an
        upgrade-sso that never restarts anything. A CONTENT change, which is the
        one form that is correct under either shape of the decision."""
        with tempfile.TemporaryDirectory() as t:
            _, toml, ran = self._walk(
                Path(t), edit=lambda p: p.write_text(p.read_text() + "\n# edit\n"))
            body = toml.read_text()
        self.assertIn(("systemctl", "restart", oauth2proxy.UNIT), ran)
        self.assertNotIn("# edit", body, "VIDE's render was not restored")
        self.assertIn("trusted_proxy_ips", body)

    def test_a_bare_touch_of_proxy_toml_is_a_restart_and_that_is_chosen(self) -> None:
        """The decision is MTIME-based, so `touch /etc/vide/sso/proxy.toml`
        restarts the fleet's gate. That is asserted rather than left as an
        accident, because it is the cost of the shape and somebody will meet it.

        Why mtime and not content: the file's content being current is exactly
        what a converge guarantees — it wrote it — so a content compare answers
        "nothing changed" on precisely the box that has not applied anything.
        That closed loop is the first of this round's two defects. The mtime
        answers the live question instead, and the price is that a bare touch is
        indistinguishable from an edit."""
        with tempfile.TemporaryDirectory() as t:
            _, _, ran = self._walk(
                Path(t),
                edit=lambda p: os.utime(p, (self.T0 + 500, self.T0 + 500)))
        self.assertIn(("systemctl", "restart", oauth2proxy.UNIT), ran)


class _MigratingFleet:
    """The half of a real box the un-migrated → migrated walk needs, and NO
    tier walks that transition today: 3.1 installs fresh, so `was_active=False`
    and the box is migrated from birth; the container's §13d and §14 only ever
    see the end state. `MSG_PROXY_RESERVATION_PENDING`, the pending clause and
    the whole upgrade lever are executed nowhere outside mocks.

    ITS GREEN IS A CLAIM ABOUT THIS MODEL, not the container's evidence, and it
    must never be quoted as such. A model agreeing with itself is not a
    measurement, however many rows agree.

    THE ONE RULE THAT STOPS IT BEING KINDER THAN SYSTEMD: `systemctl start` on
    the socket unit FAILS while the proxy holds the address itself. It is not
    invented for the fixture — it is what converge_proxy states in its own
    words, and why that call is wrapped in a tolerated `except CommandFailed`.

    What that rule buys, said accurately: on TODAY'S tree it is a guard against
    a future converge rather than a suppression of a present one. Every row in
    this class converges with `was_active=True`, and converge_proxy only issues
    `systemctl start` on the socket when `not was_active` — the class asserts
    that absence itself. Delete the `raise` and only the self-check row goes
    red. An earlier draft of this docstring claimed the rule was holding the
    whole walk up, which was a claim about a suppression that cannot happen.

    State is mutated by the SAME argv the product issues, never by a test
    helper (the `_BoxModel.note` rule): `systemctl enable` is what enables here
    as on the box."""

    def __init__(self, port: int, *, main_pid: int = 4242) -> None:
        self.port = port
        self.holder = "proxy"          # "proxy" | "systemd" | None
        self.socket_enabled = False
        self.socket_active = False
        self.service_active = True     # a LIVE box: that is the whole subject
        self.main_pid = main_pid

    def note(self, argv) -> None:
        argv = list(argv)
        if argv[:2] == ["systemctl", "enable"] and argv[-1] == oauth2proxy.SOCKET_UNIT:
            self.socket_enabled = True
        elif argv[:2] == ["systemctl", "start"] and argv[-1] == oauth2proxy.SOCKET_UNIT:
            if self.holder == "proxy":
                # EADDRINUSE. The running proxy bound the address for itself and
                # will not give it up until it exits.
                raise CommandFailed(tuple(argv), 1)
            self.socket_active = True
            self.holder = "systemd"
        elif argv[:2] == ["systemctl", "enable"] and argv[-1] == oauth2proxy.UNIT:
            # `enable --now` starts a STOPPED unit and is a no-op on a running
            # one, which is exactly what the product relies on.
            if not self.service_active:
                self.service_active = True
                self.main_pid += 1
                self.holder = "systemd" if self.socket_active else "proxy"
        elif argv[:2] == ["systemctl", "restart"] and argv[-1] == oauth2proxy.UNIT:
            # THE MOMENT THE MIGRATION LANDS. The proxy exits and releases the
            # address; `Requires=` pulls the socket unit in, so systemd takes it
            # first and the new process inherits the descriptor.
            self.holder = None
            if self.socket_enabled:
                self.socket_active = True
                self.holder = "systemd"
            else:
                self.holder = "proxy"
            self.main_pid += 1

    #: Everything below is what a box in this state answers. Named against
    #: fakes.HOST_SEAMS rather than listed by hand, so a reader added to the
    #: product cannot reach this model unanswered.
    T0 = 1_000_000.0

    #: What `vide-oauth2` resolves to on the modelled box. Distinct from 0 so
    #: the two legitimate holders are told apart by the same number the product
    #: compares.
    PROXY_UID = 997

    def seams(self) -> dict:
        def uids(port, **kw):
            # THE OWNER IS THE CREATOR. systemd creates the socket as PID 1, so
            # a migrated box reads uid 0 even though the process serving on the
            # descriptor runs as vide-oauth2; before the reservation lands the
            # proxy created it itself and reads as its own uid.
            if self.holder == "systemd":
                return {0}
            return {self.PROXY_UID} if self.holder == "proxy" else set()
        return {
            "unit_is_active": lambda u: u == oauth2proxy.UNIT and self.service_active,
            "unit_is_failed": lambda u: False,
            "unit_state": lambda u: (
                ("active" if self.socket_active else "inactive")
                if u == oauth2proxy.SOCKET_UNIT
                else ("active" if self.service_active else "inactive")),
            "unit_enable_state": lambda u: (
                ("enabled" if self.socket_enabled else "disabled")
                if u == oauth2proxy.SOCKET_UNIT else "enabled"),
            "unit_main_pid": lambda u: (self.main_pid
                                        if u == oauth2proxy.UNIT and self.service_active
                                        else None),
            "unit_listen_streams": lambda u: ([f"127.0.0.1:{self.port} (Stream)"]
                                              if self.socket_active else []),
            "unit_n_restarts": lambda u: 0,
            "listening_ports": lambda: ({self.port} if self.holder else set()),
            "hop_holders": lambda port, **kw: oauth2proxy.system.HopHolders(
                certain=frozenset(uids(port)), possible=frozenset(),
                served=frozenset()),
            "user_uid": lambda u: (self.PROXY_UID
                                   if u == oauth2proxy.PROXY_USER else None),
            "path_facts": lambda p: None,
            "proc_no_new_privs": lambda pid, **kw: True,
            "proc_groups": lambda pid: set(),
            # Older than every file below, so the restart in the walk is earned
            # by the RESERVATION clause alone and not by a stale-file clause
            # riding along with it.
            "proc_start_realtime": lambda pid, **kw: self.T0 + 60,
            "path_is_denied": lambda p: False,
            "path_mtime": lambda p: self.T0,
            "group_exists": lambda g: True,
            # A COHERENT BOX: a group that exists but has no gid and no members
            # is not one. It answered None, which made proxy_health skip the
            # whole caddy-membership block — so `test_and_then_doctor_reads_clean`,
            # the strongest assertion in the class, was green partly because two
            # red rows had been made unreachable.
            "group_entry": lambda g: (60000, {"caddy"}),
            "user_exists": lambda u: True,
            "healthz": lambda port, *, path="/healthz", timeout=3.0:
                (port == self.port and self.holder is not None
                 and self.service_active),
        }


class TestTheUnmigratedBoxWalksToMigrated(unittest.TestCase):
    """The transition nothing anywhere executes — modelled, and labelled as a
    model. See _MigratingFleet for what that costs and what it buys.

    The order is the documented one, run end to end: converge (which installs
    and enables the reservation but must NOT take the fleet's gate down for
    somebody else's install), doctor, `upgrade-sso`, doctor again."""

    PORT = 4181

    class _Executor(_FsExecutor):
        """Routes the product's OWN argv into the model, then records it. The
        recording comes first so a refused command is still visible as an
        ATTEMPT — `systemctl start` on the socket unit is issued and fails, and
        a fixture that hid the attempt could not tell that from never trying."""

        def __init__(self, fleet, **kw) -> None:
            super().__init__(**kw)
            self.fleet = fleet

        def run(self, argv, **kw):  # type: ignore[override]
            super().run(argv, **kw)
            self.fleet.note(argv)

    def _box(self, t: Path):
        cfg = make_config(Path(t))
        self._sysd = Path(t) / "sysd"
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
            "cid.apps.googleusercontent.com", "GOCSPX-live", "COOKIE"))
        oauth2proxy.toml_path(cfg).write_text("# stale\n")
        d = Path(cfg.oauth2_proxy_dir)
        (d / "7.15.2").mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).symlink_to(d / "7.15.2")
        sso.fleet_file(cfg).write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.com\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
            f"VIDE_SSO_PROXY_PORT={self.PORT}\n")
        return cfg, _MigratingFleet(self.PORT)

    @contextlib.contextmanager
    def _seamed(self, fleet):
        answers = fleet.seams()
        if set(answers) != set(HOST_SEAMS):
            raise AssertionError(
                "the migration model and HOST_SEAMS disagree: "
                f"{sorted(set(answers) ^ set(HOST_SEAMS))}")
        with contextlib.ExitStack() as stack:
            for name, fn in answers.items():
                if hasattr(oauth2proxy.system, name):
                    stack.enter_context(
                        mock.patch.object(oauth2proxy.system, name, fn))
            # SYSTEMD_DIR TOO, and it is not decoration. The fragment's presence
            # is a RAW Path read, not a `system.*` call, so HOST_SEAMS does not
            # cover it and neither does bare_host — an unseamed one here reads
            # the developer's own /etc/systemd/system and the modelled box stops
            # being the thing under test. This fleet models a box that HAS the
            # reservation unit, so the sandbox says so.
            sysd = Path(self._sysd)
            sysd.mkdir(parents=True, exist_ok=True)
            (sysd / oauth2proxy.SOCKET_UNIT).write_text("# modelled\n")
            stack.enter_context(
                mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd))
            yield

    def _converge(self, cfg, fleet):
        ex = self._Executor(fleet)
        rep, buf = capturing_reporter()
        with self._seamed(fleet), \
             mock.patch.object(oauth2proxy, "ensure_identities"), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                               return_value=False), \
             mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
            oauth2proxy.converge_proxy(cfg, ex, rep, parent_domain="example.com",
                                       was_active=True)
        return ex, buf.getvalue()

    def _doctor(self, cfg, fleet):
        with self._seamed(fleet), \
             mock.patch.object(oauth2proxy, "bootstrap_observed", return_value=True):
            ok, lines = oauth2proxy.proxy_health(cfg, check_staleness=False)
        return ok, "\n".join(lines)

    def _upgrade(self, cfg, fleet):
        ex = self._Executor(fleet)
        with self._seamed(fleet), \
             mock.patch.object(oauth2proxy, "resolve_version", return_value="7.15.2"), \
             mock.patch.object(oauth2proxy, "installed_version", return_value="7.15.2"), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                               return_value=False), \
             mock.patch.object(oauth2proxy, "_proxy_pings", return_value=True), \
             mock.patch.object(sso, "rerender_bodies"):
            # The binary is already at the pinned version — the ONLY path that
            # matters here. A version bump restarts unconditionally, which would
            # make "the reservation is what earned the restart" unassertable.
            oauth2proxy.upgrade_sso(cfg, ex, quiet_reporter())
        return [tuple(a) for a in ex.ran]

    def test_the_model_refuses_to_hand_the_port_to_systemd_while_the_proxy_holds_it(self) -> None:
        """The double's own self-check, and the row without which every other
        row in this class is a claim about a machine that does not exist."""
        fleet = _MigratingFleet(self.PORT)
        with self.assertRaises(CommandFailed):
            fleet.note(["systemctl", "start", oauth2proxy.SOCKET_UNIT])
        # …and the opposite sign: once the address is free it succeeds, or the
        # refusal above is satisfied by a model that refuses unconditionally.
        fleet.holder = None
        fleet.note(["systemctl", "start", oauth2proxy.SOCKET_UNIT])
        self.assertTrue(fleet.socket_active)
        self.assertEqual(fleet.holder, "systemd")

    def test_a_converge_installs_the_reservation_and_says_it_is_not_in_effect(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg, fleet = self._box(Path(t))
            ex, out = self._converge(cfg, fleet)
        ran = [tuple(a) for a in ex.ran]
        self.assertIn(("systemctl", "enable", oauth2proxy.SOCKET_UNIT), ran)
        # NEVER started on a live box, and never a restart: a converge runs FOR
        # SOMEONE ELSE, and installing user B may not drop the gate for A, C
        # and D.
        self.assertNotIn(("systemctl", "start", oauth2proxy.SOCKET_UNIT), ran)
        self.assertNotIn(("systemctl", "restart", oauth2proxy.UNIT), ran)
        self.assertTrue(fleet.socket_enabled)
        self.assertFalse(fleet.socket_active)
        self.assertEqual(fleet.holder, "proxy",
                         "the model let systemd take the port while the proxy "
                         "still held it — it is kinder than systemd")
        # THE WHOLE MESSAGE, not the verb name inside it. A converge on a live
        # box emits two warnings that both end in `sudo vide upgrade-sso`, and a
        # substring assertion on that verb has already lost its teeth here once
        # — the mutation that deleted one warn stayed green, satisfied by the
        # other. The formatted constant cannot collide with anything.
        self.assertIn(contract.MSG_PROXY_RESERVATION_PENDING.format(
            socket_unit=oauth2proxy.SOCKET_UNIT, port=self.PORT), out)

    def test_doctor_on_that_box_says_not_yet_reserved_and_never_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg, fleet = self._box(Path(t))
            self._converge(cfg, fleet)
            ok, body = self._doctor(cfg, fleet)
        self.assertFalse(ok)
        self.assertIn("NOT YET RESERVED", body)
        # The false alarm this state invites. The proxy legitimately holds the
        # port ITSELF here, so under root the holder is not PID 1 — and reading
        # that as a usurpation would tell every operator in the fleet, on
        # upgrade day, to stop caddy.
        self.assertNotIn("BYPASS", body)
        self.assertNotIn("stop caddy", body)

    def test_upgrade_sso_is_what_lands_the_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg, fleet = self._box(Path(t))
            self._converge(cfg, fleet)
            before = fleet.main_pid
            ran = self._upgrade(cfg, fleet)
        self.assertIn(("systemctl", "restart", oauth2proxy.UNIT), ran)
        self.assertEqual(fleet.holder, "systemd",
                         "the migration lever did not hand the fleet's "
                         "authorization port to systemd")
        self.assertTrue(fleet.socket_active)
        self.assertNotEqual(fleet.main_pid, before)

    def test_and_then_doctor_reads_clean(self) -> None:
        """The end state the whole release exists to produce, reached by the
        documented route rather than arranged by hand."""
        with tempfile.TemporaryDirectory() as t:
            cfg, fleet = self._box(Path(t))
            self._converge(cfg, fleet)
            self._upgrade(cfg, fleet)
            ok, body = self._doctor(cfg, fleet)
        self.assertTrue(ok, body)
        self.assertIn("proxy port: reserved", body)
        # The uid, not just the word: this is the end of the walk, so it is the
        # one place that asserts the reservation was verified from the kernel's
        # own table rather than from the manager's claim about a unit.
        self.assertIn("owned by uid 0", body)
        self.assertNotIn("DRIFT", body)
        self.assertNotIn("BYPASS", body)
        self.assertNotIn("NOT YET RESERVED", body)

    def test_a_half_applied_move_is_not_green(self) -> None:
        """THE STATE THIS VERB USED TO ASSERT CLEANLINESS OVER, reached from the
        same migrated box the row above ends on.

        `rerender_bodies` warns and returns rather than raising — correctly:
        refuse the write, never the verb. So `upgrade-sso` can finish with the
        reservation moved and a per-instance body still dialling the old address.
        auth.caddy is rewritten at the new pin, so the drift and abandoned-hop
        rows go silent; the reservation covers the pin and is root-held, so every
        reservation row is green. Doctor exited 0 while every request to that
        instance's host was authorized by whatever holds a now-free loopback
        port — and `doctor --quiet`, the documented cron hook, prints exactly
        these lines and nothing else.

        The answer to a fail-soft control is a sensor, not a raise."""
        from vide import caddy as _caddy
        with tempfile.TemporaryDirectory() as t:
            cfg, fleet = self._box(Path(t))
            self._converge(cfg, fleet)
            self._upgrade(cfg, fleet)
            (cfg.sso_dir / "caddy" / "alice.caddy").write_text(
                _caddy.emit_auth_body("example.com", self.PORT + 19))
            ok, body = self._doctor(cfg, fleet)
        self.assertFalse(ok, body)
        self.assertIn("instance bodies", body)
        self.assertIn("alice", body)
        self.assertIn(f"127.0.0.1:{self.PORT + 19}", body)
        self.assertIn("upgrade-sso", body)

    def test_a_migrated_box_is_not_told_its_reservation_is_pending(self) -> None:
        """The alarm that fired forever. The converge's pending warning was
        gated on `was_active` ALONE — and `was_active` is True on a migrated box
        too, because the service is running, on the inherited descriptor. So
        every `sudo ./install.sh` on a converged fleet printed NOT YET RESERVED
        about a box where systemd had held the address since sockets.target,
        and pointed the operator at a verb with nothing to do.

        Worse than noise: it is the SAME STRING doctor uses as its migration-day
        red row, and doctor reaches that row only after ruling out `holds`, NOT
        BOUND and DRIFT. On one box, in one minute, install.sh said NOT YET
        RESERVED while `vide doctor` said reserved and exited green.

        Reached through the walk rather than arranged: converge, upgrade, then
        converge again — the ordinary second install, on the box the release
        exists to produce."""
        with tempfile.TemporaryDirectory() as t:
            cfg, fleet = self._box(Path(t))
            self._converge(cfg, fleet)
            self._upgrade(cfg, fleet)
            self.assertEqual(fleet.holder, "systemd")    # precondition, asserted
            _, out = self._converge(cfg, fleet)
        self.assertNotIn(contract.MSG_PROXY_RESERVATION_PENDING.format(
            socket_unit=oauth2proxy.SOCKET_UNIT, port=self.PORT), out)

    def test_a_second_upgrade_on_the_migrated_box_does_not_bounce_the_gate(self) -> None:
        """The loop check, at the level where a loop would actually be felt:
        every clause must be FALSE immediately after the restart it demanded.
        Run the lever twice and the second run must be silent.

        WHICH CLAUSE IT ACTUALLY OBSERVES, because the name promises more than
        one row can deliver: the model answers `path_mtime` and
        `proc_start_realtime` as CONSTANTS, so the file clauses are False before,
        during and after — only the SOCKET-STATE clause is seen self-clearing
        here. That is consistent with the falsification pass, where this class
        was blind to the reverted converge guard and only the cross-verb row
        went red. Do not quote this row as evidence about the file clauses;
        TestAConvergeDoesNotMakeTheNextUpgradeBounceTheGate is where those
        live."""
        with tempfile.TemporaryDirectory() as t:
            cfg, fleet = self._box(Path(t))
            self._converge(cfg, fleet)
            self._upgrade(cfg, fleet)
            settled = fleet.main_pid
            ran = self._upgrade(cfg, fleet)
        self.assertNotIn(("systemctl", "restart", oauth2proxy.UNIT), ran)
        self.assertEqual(fleet.main_pid, settled)


class TestTheReservationUnitIsActuallyRendered(unittest.TestCase):
    """`install_proxy_socket_unit` was mocked at every one of its call sites and
    tested at none of them — so the function that writes the unit reserving the
    fleet's authorization port had no coverage at all, and the two rows that
    looked like they covered it did the sentinel substitution INSIDE the test.
    Those pin the unit FILE's text; they say nothing about what VIDE renders.

    The gap that leaves is exact: swapping `vide_sso.fleet_port(cfg)` for
    `cfg.sso_proxy_port` at the call site would reserve one port while every
    renderer dials another — the one-reader violation this file exists to
    forbid — with the whole suite green."""

    PIN = 4199          # what fleet.env says
    ENV = 9999          # what a hostile/stale `.env` says

    def _pinned(self, t: Path):
        cfg = make_config(Path(t), sso_proxy_port=self.ENV)
        Path(cfg.sso_dir).mkdir(parents=True, exist_ok=True)
        sso.fleet_file(cfg).write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.com\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
            f"VIDE_SSO_PROXY_PORT={self.PIN}\n")
        units = Path(cfg.repo_dir) / "units"
        units.mkdir(parents=True, exist_ok=True)
        # The REAL unit body, not a stub: the substitution has to be exercised
        # against the file that ships, or a sentinel rename passes here.
        (units / "oauth2-proxy.socket").write_text(
            (REPO / "units" / "oauth2-proxy.socket").read_text())
        (units / "oauth2-proxy.service").write_text(
            (REPO / "units" / "oauth2-proxy.service").read_text())
        return cfg

    def _recorder(self, ex):
        """Capture what VIDE asks the executor to write, and where.

        The unit's destination is `/etc/systemd/system`, which is outside any
        sandbox, so FsExecutor correctly refuses the write and there is no file
        to read back — which is exactly why this function had no coverage. The
        executor IS the mutation seam, so recording the content it is handed is
        the right observation, not a workaround."""
        written: dict[str, str] = {}

        def rec(dest, content, *, mode, owner=None):
            written[str(dest)] = content
        return written, mock.patch.object(ex, "atomic_write", rec)

    def _body(self, written: dict[str, str]) -> str:
        # Matched by BASENAME: the move-refusal rows redirect SYSTEMD_DIR into
        # their sandbox, so the destination is no longer the literal
        # /etc/systemd/system path the first rows here were written against.
        hits = [v for k, v in written.items()
                if k.endswith(oauth2proxy.SOCKET_UNIT)]
        self.assertTrue(hits, f"nothing was written for "
                              f"{oauth2proxy.SOCKET_UNIT}: {list(written)}")
        return hits[0]

    def test_the_rendered_unit_listens_on_the_port_it_is_given(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            ex = _FsExecutor(sandbox=Path(t))
            written, patched = self._recorder(ex)
            # bare_host FIRST, the row's own patch second — last entered wins.
            # Without it `unit_listen_streams` is a live `systemctl show -p Listen`
            # against the machine running the tier, and this row would be green
            # there only because that box happens to have no reservation unit:
            # on a box that has VIDE installed on 4180 the writer would refuse the
            # 4199 pin and the row would go red for a reason that is not in the
            # tree. That is the shape prove-teeth reports as "ALREADY RED".
            #
            # AND SYSTEMD_DIR, which the paragraph above did not cover and had to
            # learn: presence is now the TIE-BREAK under that manager read, and it
            # is a raw Path stat rather than a `system.*` call, so bare_host does
            # not reach it and neither does the seam census. With the manager
            # stubbed to `[]` the file decides — so an unseamed row on a box that
            # has the fragment installed reads `None`, refuses, and goes red for
            # the machine rather than for the tree. Measured, not argued: running
            # this suite with SYSTEMD_DIR pointed at a directory that really
            # contains the unit turned exactly two rows red, and this was one.
            sysd = Path(t) / "sysd"
            sysd.mkdir(parents=True, exist_ok=True)
            with bare_host(oauth2proxy), patched, \
                 mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                 mock.patch.object(oauth2proxy.system, "unit_enable_state",
                                   return_value="disabled"):
                changed = oauth2proxy.install_proxy_socket_unit(
                    cfg, ex, quiet_reporter(), self.PIN)
            body = self._body(written)
        self.assertTrue(changed)
        self.assertIn(f"ListenStream=127.0.0.1:{self.PIN}", body)
        self.assertNotIn(oauth2proxy.SOCKET_PORT_SENTINEL, body,
                         "an unsubstituted sentinel is a unit systemd refuses to "
                         "parse — the reservation would simply never exist while "
                         "every verb reported success")

    def test_converge_reserves_THE_PIN_never_the_env_row(self) -> None:
        """The row the mocks hid. `.env` says one port, the fleet is pinned to
        another, and the unit that BINDS must agree with the bodies that DIAL —
        which read the pin. A converge that passed cfg here would reserve a port
        nobody dials and leave the real hop free, with no other row noticing."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            # A binary is already present, so converge takes no download path —
            # this row is about which PORT reaches the unit, nothing else.
            d = Path(cfg.oauth2_proxy_dir)
            (d / "7.15.2").mkdir(parents=True, exist_ok=True)
            oauth2proxy.current_link(cfg).symlink_to(d / "7.15.2")
            ex = _FsExecutor(sandbox=Path(t))
            written, patched = self._recorder(ex)
            # SYSTEMD_DIR for the reason spelled out in the row above: a raw Path
            # stat that bare_host does not cover, reached now that presence is
            # the tie-break under the manager read.
            sysd = Path(t) / "sysd"
            sysd.mkdir(parents=True, exist_ok=True)
            with bare_host(oauth2proxy), patched, \
                 mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                 mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False):
                oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(),
                                           parent_domain="example.com",
                                           was_active=False)
            body = self._body(written)
        self.assertIn(f"ListenStream=127.0.0.1:{self.PIN}", body)
        self.assertNotIn(str(self.ENV), body,
                         "the reservation took the port from .env instead of the "
                         "fleet pin — it would bind a port nothing dials")

    def test_a_masked_reservation_unit_is_refused(self) -> None:
        """Masking this unit does not switch the SSO gate off; it hands the
        fleet's authorization address to whoever binds it next. Converging over
        that silently would be VIDE agreeing to it."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            for word in ("masked", "masked-runtime"):
                with self.subTest(word=word), bare_host(oauth2proxy), \
                     mock.patch.object(oauth2proxy.system, "unit_enable_state",
                                       return_value=word), \
                     self.assertRaises(StateError):
                    oauth2proxy.install_proxy_socket_unit(
                        cfg, _FsExecutor(sandbox=Path(t)), quiet_reporter(), self.PIN)

    def test_a_rotted_sentinel_is_refused_rather_than_shipped(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            p = Path(cfg.repo_dir) / "units" / "oauth2-proxy.socket"
            p.write_text(p.read_text().replace(
                oauth2proxy.SOCKET_PORT_SENTINEL, "4180"))
            with bare_host(oauth2proxy), \
                 mock.patch.object(oauth2proxy.system, "unit_enable_state",
                                   return_value="disabled"), \
                 self.assertRaises(StateError):
                oauth2proxy.install_proxy_socket_unit(
                    cfg, _FsExecutor(sandbox=Path(t)), quiet_reporter(), self.PIN)

    # ---- the move refusal ----------------------------------------------------
    def _write_attempt(self, t: Path, loaded, enabled="disabled", installed=None):
        """Drive the writer against a box whose reservation unit is configured
        for `loaded`, and report both what it returned and what it wrote.

        SYSTEMD_DIR is redirected into the sandbox and a unit body is placed
        there whenever `loaded` says one is loaded, because presence is a DISK
        fact rather than a word from `is-enabled` — that word is `not-found`
        only from systemd 253, and Debian 12 and Ubuntu 22.04 are supported.

        Note the ordering the product settled on, which this fixture can express
        and the earlier one could not: the manager is asked FIRST and the file
        only breaks an empty tie, so `loaded` non-empty with `installed=False` is
        a real box — the operator removed the fragment and has not reloaded, the
        unit is still loaded and still holding — and it must refuse."""
        cfg = self._pinned(t)
        sysd = t / "systemd"
        sysd.mkdir(parents=True, exist_ok=True)
        if bool(loaded) if installed is None else installed:
            (sysd / oauth2proxy.SOCKET_UNIT).write_text(
                "# a reservation is installed here\n")
        ex = _FsExecutor(sandbox=t)
        written, patched = self._recorder(ex)
        rep, out = capturing_reporter()
        with bare_host(oauth2proxy), patched, \
             mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
             mock.patch.object(oauth2proxy.system, "unit_enable_state",
                               return_value=enabled), \
             mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                               return_value=loaded):
            changed = oauth2proxy.install_proxy_socket_unit(
                cfg, ex, rep, self.PIN)
        return changed, written, out.getvalue(), ex

    def test_a_removed_fragment_that_is_still_loaded_refuses_the_write(self) -> None:
        """The arm the manager-first ordering added, and the box it is about:
        `rm` without a `daemon-reload`. The file is gone, the unit is still
        loaded and still HOLDING the address. A file-first reader answered "no
        reservation here", permitted the write, reloaded — and systemd dropped
        the descriptor and bound nothing in its place. That is VIDE releasing the
        fleet's authorization hop by its own hand, out of the one function
        written to prevent it."""
        with tempfile.TemporaryDirectory() as t:
            changed, written, warned, _ = self._write_attempt(
                Path(t), ["127.0.0.1:4180 (Stream)"], installed=False)
        self.assertFalse(changed)
        self.assertEqual(written, {})
        self.assertIn("REFUSING", warned)

    def test_a_refused_converge_does_not_die_at_the_enable(self) -> None:
        """The refusal's contract is "nothing was written; the rest of this run
        continues" — and the arm above can leave the box with NO fragment while
        the very next statement in the converge is `systemctl enable`, which is a
        hard error on every supported systemd when the unit file is absent. An
        unguarded enable turns a deliberate, recoverable refusal into a dead
        run."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            sysd = Path(t) / "systemd"
            sysd.mkdir(parents=True, exist_ok=True)     # deliberately EMPTY
            ex = _FsExecutor(sandbox=Path(t))
            rep, out = capturing_reporter()
            with bare_host(oauth2proxy), \
                 mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                 mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                   return_value=["127.0.0.1:4180 (Stream)"]), \
                 mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "resolve_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "installed_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "install_version",
                                   return_value="sha"), \
                 mock.patch.object(oauth2proxy, "flip_current"), \
                 mock.patch.object(oauth2proxy, "record_version"), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(cfg, ex, rep,
                                           parent_domain="example.com",
                                           was_active=True)
            ran = [tuple(a) for a in ex.ran]
        self.assertIn("REFUSING", out.getvalue())
        self.assertNotIn(("systemctl", "enable", oauth2proxy.SOCKET_UNIT), ran,
                         "enabled a unit file that is not there")

    def test_a_dry_run_first_install_still_previews_the_enable(self) -> None:
        """THE OTHER SIGN OF THE SAME GUARD, and the one that keeps a preview
        honest. A dry run writes nothing, so on a first install the fragment is
        legitimately absent AT THIS INSTANT while the real run will create it and
        enable it moments later. Testing the file alone would drop the step from
        every preview of the commonest path there is — a preview lying about what
        the run does, which is the one thing previews exist not to do."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            sysd = Path(t) / "systemd"
            sysd.mkdir(parents=True, exist_ok=True)     # a first install: EMPTY
            ex = _FsExecutor(sandbox=Path(t))
            ex.dry_run = True
            with bare_host(oauth2proxy), \
                 mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                 mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "resolve_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "installed_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "install_version",
                                   return_value="sha"), \
                 mock.patch.object(oauth2proxy, "flip_current"), \
                 mock.patch.object(oauth2proxy, "record_version"), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(cfg, ex, quiet_reporter(),
                                           parent_domain="example.com",
                                           was_active=False)
            ran = [tuple(a) for a in ex.ran]
        self.assertIn(("systemctl", "enable", oauth2proxy.SOCKET_UNIT), ran,
                      "the preview dropped a step the real run performs")

    def test_a_refused_converge_survives_an_unresolvable_requires(self) -> None:
        """FOUND BY A TIER, NOT BY A READING, which is why it has a row now. The
        SERVICE carries `Requires=<socket unit>`, so on the same box — fragment
        removed, unit still loaded and still holding — systemd resolves that
        against a unit file that is gone and exits 5. The refusal's contract is
        "nothing was written; the rest of this run continues", and dying three
        statements past the guard broke it exactly as an unguarded `enable` on
        the socket unit would have. §16d-b measured it as `exit 5` on a real
        manager; this row is the hermetic half, and the fake has to be told to
        fail because a fake `ex.run` succeeds at everything."""
        class _Failing(_FsExecutor):
            def run(self, argv, **kw):       # type: ignore[override]
                if list(argv)[:3] == ["systemctl", "enable", "--now"]:
                    raise CommandFailed("Unit vide-oauth2-proxy.socket not found.", 5)
                return super().run(argv, **kw)

        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            sysd = Path(t) / "systemd"
            sysd.mkdir(parents=True, exist_ok=True)     # deliberately EMPTY
            ex = _Failing(sandbox=Path(t))
            rep, out = capturing_reporter()
            with bare_host(oauth2proxy), \
                 mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                 mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                   return_value=["127.0.0.1:4180 (Stream)"]), \
                 mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "resolve_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "installed_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "install_version",
                                   return_value="sha"), \
                 mock.patch.object(oauth2proxy, "flip_current"), \
                 mock.patch.object(oauth2proxy, "record_version"), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(cfg, ex, rep,
                                           parent_domain="example.com",
                                           was_active=True)
        # It survived, and it SAID why — a swallowed failure with no sentence is
        # the same silence this whole family exists to remove. The CONSTANT, not
        # a substring of it: an oracle that cannot tell this sentence from a
        # neighbour is not an oracle, which this file has already had to learn
        # once for MSG_PROXY_RESERVATION_UNREADABLE.
        self.assertIn(contract.MSG_PROXY_RESERVATION_FRAGMENT_GONE.format(
            socket_unit=oauth2proxy.SOCKET_UNIT, unit=oauth2proxy.UNIT,
            unit_path=sysd / oauth2proxy.SOCKET_UNIT), out.getvalue())

    def test_a_failing_enable_still_takes_the_run_down_normally(self) -> None:
        """The other sign, and it is what keeps the clause above from being a
        bare `except`: with the fragment present, an `enable --now` that fails
        is a real fault and must still stop the run."""
        class _Failing(_FsExecutor):
            def run(self, argv, **kw):       # type: ignore[override]
                if list(argv)[:3] == ["systemctl", "enable", "--now"]:
                    raise CommandFailed("some other failure", 1)
                return super().run(argv, **kw)

        with tempfile.TemporaryDirectory() as t:
            cfg = self._pinned(Path(t))
            sysd = Path(t) / "systemd"
            sysd.mkdir(parents=True, exist_ok=True)
            (sysd / oauth2proxy.SOCKET_UNIT).write_text("# present\n")
            with bare_host(oauth2proxy), \
                 mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                 mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                   return_value=[f"127.0.0.1:{self.PIN} (Stream)"]), \
                 mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "resolve_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "installed_version",
                                   return_value="7.15.3"), \
                 mock.patch.object(oauth2proxy, "install_version",
                                   return_value="sha"), \
                 mock.patch.object(oauth2proxy, "flip_current"), \
                 mock.patch.object(oauth2proxy, "record_version"), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"), \
                 self.assertRaises(CommandFailed):
                oauth2proxy.converge_proxy(cfg, _Failing(sandbox=Path(t)),
                                           quiet_reporter(),
                                           parent_domain="example.com",
                                           was_active=True)

    def test_a_pin_that_moved_away_from_the_loaded_unit_refuses_the_write(self) -> None:
        """The one transition VIDE could perform by its own hand. Writing a
        changed ListenStream= and reloading releases the address systemd holds and
        binds NOTHING in its place — so the fleet's gate is down and its address
        unowned at the same moment, while the operator's own Caddyfile still
        dials the old number."""
        with tempfile.TemporaryDirectory() as t:
            changed, written, warned, ex = self._write_attempt(
                Path(t), ["127.0.0.1:4180 (Stream)"])
        self.assertFalse(changed, "a refused write must not be reported as a write")
        self.assertEqual(written, {}, "the unit body was written anyway")
        # THE LOAD-BEARING HALF. Withholding the write while still reloading is
        # the shape that frees the address regardless, and a row that only
        # checked the file would pass straight over it.
        self.assertNotIn(("run", ("systemctl", "daemon-reload")), ex.actions,
                         "the reload happened without the write")
        self.assertIn("4180", warned)
        self.assertIn(str(self.PIN), warned)

    def test_a_first_install_has_nothing_to_move_away_from(self) -> None:
        """Absence of a reservation is not evidence that the pin moved — it is
        how every first install and every completed move begins."""
        with tempfile.TemporaryDirectory() as t:
            changed, written, _, _ = self._write_attempt(Path(t), [])
        self.assertTrue(changed)
        self.assertIn(f"ListenStream=127.0.0.1:{self.PIN}", self._body(written))

    def test_a_unit_already_on_the_pin_is_re_rendered_normally(self) -> None:
        """The refusal is direction-aware: it refuses the write that MOVES the
        address, never the write that keeps it. The reservation's own hardening
        has to stay shippable to every migrated box."""
        with tempfile.TemporaryDirectory() as t:
            changed, written, _, _ = self._write_attempt(
                Path(t), [f"127.0.0.1:{self.PIN} (Stream)"])
        self.assertTrue(changed)
        self.assertIn(f"ListenStream=127.0.0.1:{self.PIN}", self._body(written))

    def test_a_manager_that_did_not_answer_may_not_permit_the_move(self) -> None:
        """`unit_listen_streams` answers [] for BOTH "no such unit" and
        "systemctl did not answer", so on that reader alone no rule is right. The
        empty `is-enabled` word is the tell, and an input that cannot be read may
        not permit a move — only report one."""
        with tempfile.TemporaryDirectory() as t:
            # A reservation IS installed — the destination exists — and the
            # manager answered nothing about it. That is the only shape the
            # unreadable case can take now that presence is a file fact, and it
            # is the shape a wedged systemctl really produces.
            changed, written, warned, _ = self._write_attempt(
                Path(t), [], enabled="", installed=True)
        self.assertFalse(changed)
        self.assertEqual(written, {})
        # THE CONSTANT, not `assertTrue(warned)`. This row's only oracle used to
        # be "some warning happened", which cannot tell this sentence from the
        # move refusal's — and the move refusal is checkably FALSE here: it
        # asserts a reservation exists and names the address to put the pin back
        # to, on a box where the read just failed. A row that cannot distinguish
        # its own subject from its neighbour is not an assertion.
        self.assertIn(contract.MSG_PROXY_RESERVATION_UNREADABLE.format(
            socket_unit=oauth2proxy.SOCKET_UNIT, port=self.PIN), warned)
        self.assertNotIn("Cheapest way out", warned)


class TestDoctorTellsTheTruthAboutTheReservation(unittest.TestCase):
    """The reservation rows had no test at all, which made them the softest part
    of the change: `_covers_port` could `return True` unconditionally — or revert
    to the substring form its own docstring exists to forbid — and every tier
    stayed green, because nothing in the suite could reach `holds=True`.

    Six states, and each of them is a different sentence to an operator. The
    dangerous ones are not the loud failures: they are `DRIFT` and `NOT BOUND`,
    where the fleet's authorization port is open RIGHT NOW while a naive check
    reports a healthy socket unit."""

    PORT = 4199
    PROXY_UID = 997         # what `vide-oauth2` resolves to on the fixture box
    STRANGER = 1000         # an ordinary local account: no VIDE instance, no
                            # role, no sudo — the threat this release names

    def _rows(self, *, socket_state: str, enabled: str, listening: list[str],
              uids, service_active: bool, answers: bool = False,
              restarts: int = 0, possible=(), served=()):
        """`uids` REPLACED a `pids` set and a separate `bound` flag, and the
        replacement is the subject of half this class. The holder used to be
        read out of `ss -Htlnp`, whose process column carries a name the process
        chooses — so a squatter calling itself `pid=1` cleared the usurpation
        suspicion, and because `holds` carried `not usurped` as a conjunct, that
        RESTORED the affirmative row over a live squat. It now comes from
        /proc/net/tcp's uid column, which the kernel writes; `bound` is derived
        from the same read instead of from a second `ss` at a second instant.
        Pass None to mean "the kernel could not be read at all" — a different
        state from "nobody is listening", and one that now has its own row.

        `answers` used to be a constant False, and that single default made six
        rows here vacuous: with the proxy answering nothing, the NO ANSWER row
        reddened EVERY fixture, so `assertFalse(ok)` was guaranteed regardless
        of what the reservation rows decided. Port-keyed rather than a flat True
        so the Caddy-admin probe two rows down still answers False.

        `proc_no_new_privs` is stubbed for the reason fakes.bare_host records:
        this class fabricates MainPID 7, and unstubbed the sandbox row reads
        /proc/7/status ON THE MACHINE RUNNING THE TIER — a kernel thread on most
        Linux hosts, which answers NoNewPrivs: 0 and appends a phantom row.

        A COHERENT BOX, and it took two rounds to get here. `group_entry`
        answered None for every group, which made proxy_health skip the entire
        caddy-membership block — so `assertTrue(ok)` in the strongest row of this
        class was a conjunction over SIX rows while its docstring claimed eight,
        and two red rows had been made unreachable rather than green. And
        `unit_main_pid` answered 7 for EVERY unit, including caddy.service, which
        is not a box either: it would have sent the membership check to read
        `proc_groups(7)`. Both are now keyed the way the model in
        _MigratingFleet.seams already keyed them."""
        cfg = make_config(Path("/nonexistent"))
        holders = None if uids is None else oauth2proxy.system.HopHolders(
            certain=frozenset(uids), possible=frozenset(possible),
            served=frozenset(served))
        with mock.patch.object(oauth2proxy.system, "hop_holders",
                               return_value=holders), \
             mock.patch.object(oauth2proxy.system, "user_uid",
                               side_effect=lambda u: (self.PROXY_UID
                                                      if u == oauth2proxy.PROXY_USER
                                                      else None)), \
             mock.patch.object(oauth2proxy.system, "unit_state", return_value=socket_state), \
             mock.patch.object(oauth2proxy.system, "unit_enable_state", return_value=enabled), \
             mock.patch.object(oauth2proxy.system, "unit_listen_streams", return_value=listening), \
             mock.patch.object(oauth2proxy.system, "unit_is_active", return_value=service_active), \
             mock.patch.object(oauth2proxy.system, "unit_is_failed", return_value=False), \
             mock.patch.object(oauth2proxy.system, "unit_main_pid",
                               side_effect=lambda u: (7 if (u == oauth2proxy.UNIT
                                                            and service_active)
                                                      else None)), \
             mock.patch.object(oauth2proxy.system, "proc_no_new_privs", return_value=True), \
             mock.patch.object(oauth2proxy.system, "healthz",
                               side_effect=lambda port, *, path="/healthz", timeout=3.0:
                                   answers and port == self.PORT), \
             mock.patch.object(oauth2proxy.system, "unit_n_restarts", return_value=restarts), \
             mock.patch.object(oauth2proxy.system, "group_entry",
                               return_value=(60000, {"caddy"})), \
             mock.patch.object(oauth2proxy, "bootstrap_observed", return_value=True), \
             mock.patch.object(sso, "fleet_port", return_value=self.PORT):
            ok, lines = oauth2proxy.proxy_health(cfg, check_staleness=False)
        return ok, "\n".join(lines)

    _LISTENING = [f"127.0.0.1:{PORT} (Stream)"]

    def test_a_covered_port_reports_reserved(self) -> None:
        """A FULLY MIGRATED BOX READS CLEAN — the state this whole release
        exists to produce, and it was asserted nowhere. `assertTrue(ok)` is the
        load-bearing direction here precisely because `ok` is a conjunction over
        eight independent rows: True requires every one of them green, while a
        False can never identify which one fired."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids={0},
                              service_active=True, answers=True)
        self.assertTrue(ok, body)
        self.assertIn("proxy port: reserved", body)
        self.assertIn("owned by uid 0", body)
        self.assertNotIn("BYPASS", body)
        self.assertNotIn("DRIFT", body)

    def test_the_proxy_inheriting_the_descriptor_leaves_the_owner_at_root(self) -> None:
        """The shape a MIGRATED box actually has, and the reason the holder
        question moved from pids to uids. systemd creates the listening socket
        as PID 1 and the proxy INHERITS the descriptor — a socket's recorded
        owner is its creator, so the answer stays uid 0 even though the process
        reading from it runs as vide-oauth2 with a MainPID of its own. The pid
        reader had to special-case that second process; this one never sees it."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids={0},
                              service_active=True, answers=True)
        self.assertTrue(ok, body)
        self.assertNotIn("TAKEN", body)

    def test_root_beside_a_stranger_is_not_reserved(self) -> None:
        """A second listener sharing the hop, through SO_REUSEPORT — which the
        kernel only permits between sockets with equal effective uids, so
        against a root socket the sharer is also root."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids={0, self.STRANGER},
                              service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertNotIn("proxy port: reserved", body)
        self.assertIn("TAKEN", body)

    def test_root_beside_the_proxy_is_still_not_reserved(self) -> None:
        """THE ROW THAT ACTUALLY PINS `certain == {0}` rather than `0 in
        certain`, and its absence made the sibling above vacuous on that point:
        with a STRANGER in the set, `usurped` fires and `_reservation_rows`
        returns before it ever reaches the affirmative row, so that row passes
        under either spelling.

        Both uids here are LEGITIMATE, so `usurped` is False and the ladder is
        silent — the only thing left to decide the verdict is whether `reserved`
        requires the set to be exactly root's. It must: "root holds it and so
        does something else" is not the state this release exists to produce,
        and on this hop root is the only identity that may hold it once the
        reservation has landed."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING,
                              uids={0, self.PROXY_UID},
                              service_active=True, answers=True)
        self.assertNotIn("proxy port: reserved", body)
        self.assertNotIn("BYPASS", body, "a legitimate pair is not an attack")
        self.assertFalse(ok)

    def test_a_v6_wildcard_may_alarm_and_may_never_reassure(self) -> None:
        """`possible` is the `::` row the kernel's tables cannot resolve: it
        serves v4 unless the socket set IPV6_V6ONLY, and procfs exposes no such
        flag. So it must be able to raise the alarm — it may genuinely be the
        squatter — and it must never be able to say `reserved`, which would be
        the mirror-image false green."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids=set(),
                              possible={self.STRANGER}, service_active=True,
                              answers=True)
        self.assertFalse(ok)
        self.assertIn("TAKEN", body)
        # …and a LEGITIMATE `::` holder is not an alarm, but is still not proof.
        ok2, body2 = self._rows(socket_state="active", enabled="enabled",
                                listening=self._LISTENING, uids=set(),
                                possible={0}, service_active=True, answers=True)
        self.assertFalse(ok2)
        self.assertNotIn("proxy port: reserved", body2)
        self.assertNotIn("BYPASS", body2)

    def test_a_stranger_serving_connections_on_the_hop_is_a_bypass(self) -> None:
        """THE STATE NO LISTENER-ONLY CHECK CAN SEE, and the one the containment
        ladder's step 2 calls not optional: an attacker hands the LISTENING
        socket back — so the address reads reserved and every holder signal goes
        green — while staying alive and serving every connection Caddy already
        had open. The evidence is in the same read: accepted sockets on the hop
        carry the uid of whoever created the listener they came from."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids={0},
                              served={self.STRANGER}, service_active=True,
                              answers=True)
        self.assertFalse(ok)
        self.assertIn("BYPASS", body)
        self.assertIn("stop caddy", body)
        # The opposite sign: the proxy's own accepted connections are the normal
        # state of a working box, and reddening them would make this row noise.
        ok2, _ = self._rows(socket_state="active", enabled="enabled",
                            listening=self._LISTENING, uids={0},
                            served={0}, service_active=True, answers=True)
        self.assertTrue(ok2)

    def test_a_squatter_cannot_turn_the_reservation_row_green(self) -> None:
        """THE inversion, and the reason `bound` is no longer a positive
        conjunct. In the reload-orphaned state — socket unit `active`,
        configured for the pin, systemd holding nothing — one unprivileged
        `bind(2)` used to satisfy `bound`, flip `holds` to True so this row
        printed the affirmative "reserved", AND cancel the /ping probe on the
        way past. The attack produced the health report."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids={self.STRANGER},
                              service_active=True, answers=True)
        self.assertFalse(ok)
        # THE AFFIRMATIVE SENTENCE, anchored to text the product can actually
        # emit. This used to assert `assertNotIn("reserved on", …)` — a string
        # that appears nowhere in src/ except inside a comment, so the row whose
        # NAME is this claim could not fail for any product reason.
        self.assertNotIn("proxy port: reserved", body)
        # The STATE CLAUSE, not a shared word: three different states emit
        # MSG_PROXY_PORT_UNRESERVED, so asserting that token cannot tell this
        # row's subject from a masked unit.
        self.assertIn("TAKEN", body)
        self.assertIn(f"uid {self.STRANGER}", body)

    def test_no_name_a_process_can_choose_reaches_this_verdict(self) -> None:
        """THE CONSUMER-LEVEL ROW FOR THE SPOOF, which is where the defect
        actually lived. The reader had a row pinning that `ss`'s process column
        is forgeable; nothing asserted what the ROWS then said, and what they
        said was: `usurped` cleared, `holds` restored (it carried `not usurped`
        as a conjunct), the affirmative sentence printed over a live squat, and
        the containment ladder withheld.

        There is no process-supplied text on this path any more — the verdict is
        a function of a kernel-written uid — so the property to pin is that
        EVERY holder which is neither root nor the proxy gets the same treatment,
        including the two values the old forgery aimed at: 1 (`pid=1`) and the
        proxy's own MainPID."""
        for uid in (1, 7, self.STRANGER, 65534):
            with self.subTest(uid=uid):
                ok, body = self._rows(socket_state="active", enabled="enabled",
                                      listening=self._LISTENING, uids={uid},
                                      service_active=True, answers=True)
                self.assertFalse(ok)
                self.assertNotIn("proxy port: reserved", body)
                self.assertIn("BYPASS", body)

    def test_an_unreadable_kernel_is_a_row_and_not_a_verdict(self) -> None:
        """None is "/proc/net/tcp could not be read", and it must not become
        "nobody is listening": that reading turns a measurement which never
        happened into "the fleet's authorization port is open right now", with a
        remedy that restarts the fleet's gate."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids=None,
                              service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("UNREADABLE", body)
        self.assertNotIn("NOT BOUND", body)
        self.assertNotIn("proxy port: reserved", body)

    def test_an_unmigrated_box_is_not_accused_of_a_squat(self) -> None:
        """The false alarm this change nearly shipped twice. On a
        converged-but-not-yet-restarted box the proxy still holds the port
        ITSELF, so the holder is legitimately not root. Treating that as a
        usurpation printed the containment ladder — "stop caddy" — on every
        healthy box on upgrade day.

        Recognised by UID and not by MainPID, which is the fix for the fix: the
        pid-shaped exclusion could be forged by any local account, because
        MainPID is world-readable. Becoming vide-oauth2 requires root."""
        ok, body = self._rows(socket_state="inactive", enabled="enabled",
                              listening=[], uids={self.PROXY_UID},
                              service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("NOT YET RESERVED", body)
        self.assertNotIn("BYPASS", body)
        self.assertNotIn("stop caddy", body)

    def test_a_disabled_reservation_unit_is_named_even_while_it_is_holding(self) -> None:
        """The lapse with NO live symptom. `systemctl disable` removes the
        sockets.target symlink and touches nothing that is running, so the unit
        can be up, covering the pin and held by root right now — and absent from
        the next boot transaction. The window this unit exists to close is
        exactly the one that reopens, and every other signal here stays green."""
        ok, body = self._rows(socket_state="active", enabled="disabled",
                              listening=self._LISTENING, uids={0},
                              service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("NOT ENABLED AT BOOT", body)

    def test_a_crash_looping_gate_is_named_by_its_restart_count(self) -> None:
        """NRestarts REPLACED a signal this change had to give up: with the
        start limiter off, a permanently broken proxy never lands in `failed` —
        it rests in `activating (auto-restart)` forever, which looks far more
        alive than it is. The row had no behavioural test at all; every fixture
        in the tree answered 0, so it was never produced and its `and not
        answers` conjunct — the one that stops maintenance restarts being
        nagged — was unexercised."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids={0},
                              service_active=True, answers=False, restarts=2)
        self.assertFalse(ok)                       # NO ANSWER carries the red
        self.assertIn("proxy restarts: 2", body)
        # …and the opposite sign, without which the row above is satisfied by a
        # line that is always printed: a box that restarted twice during
        # maintenance and is answering is not broken, and reddening doctor for
        # remembering history is noise the operator learns to skip.
        _, healthy = self._rows(socket_state="active", enabled="enabled",
                                listening=self._LISTENING, uids={0},
                                service_active=True, answers=True, restarts=2)
        self.assertNotIn("proxy restarts", healthy)

    def test_a_drifted_unit_is_never_called_reserved(self) -> None:
        """The unit is up and listening — on the WRONG port. The fleet's real hop
        is free and squattable while every naive signal says healthy."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=["127.0.0.1:4180 (Stream)"], uids=set(),
                              service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("DRIFT", body)
        self.assertNotIn("proxy port: reserved", body)
        # Drift ALONE is an advisory-shaped red, not a containment ladder: the
        # real hop is free, but nothing has taken it. The compound state — drift
        # PLUS a stranger on the hop — is the row below, and it is the one that
        # earns BYPASS.
        self.assertNotIn("BYPASS", body)

    def test_a_drifted_unit_over_a_squatted_hop_gets_the_containment_ladder(self) -> None:
        """The compound state, and the one that earns the `usurped` disjunct its
        place in a fail-loud arm: the socket unit reloaded onto the WRONG
        address AND something else took the fleet's real hop.

        The service is `active` with a MainPID and is not `failed`, so every
        other clause in that predicate is False — the arm rests on `usurped` and
        on nothing else. Without it the operator gets an advisory reservation
        row and NO containment ladder while a stranger answers forward_auth for
        every instance on the box."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=["127.0.0.1:4180 (Stream)"],
                              uids={self.STRANGER}, service_active=True,
                              answers=True)
        self.assertFalse(ok)
        self.assertIn("BYPASS", body)
        self.assertIn("stop caddy", body, "the containment step must come first")
        self.assertIn("TAKEN", body)

    def test_the_containment_ladder_does_not_wait_for_the_squatter_to_answer(self) -> None:
        """The ladder used to be gated on `answers` — i.e. on the ATTACKER's
        cooperation. A squatter that answers Caddy's real forward_auth request
        while 404-ing /ping left `answers` False, so the operator got an
        advisory row and no containment steps, during the harvest the ladder
        exists to stop.

        The uid read is a kernel fact about who is on the fleet's hop; it needs
        no corroboration from the process being reported, so it raises
        containment by itself."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids={self.STRANGER},
                              service_active=True, answers=False)
        self.assertFalse(ok)
        self.assertIn("BYPASS", body)
        self.assertIn("stop caddy", body)

    def test_a_prefix_port_is_not_mistaken_for_the_pin(self) -> None:
        """4180 is a substring of 41800. The compare that shipped first would
        have called this covered and gone green over an open port."""
        self.assertFalse(oauth2proxy._covers_port(["127.0.0.1:41990 (Stream)"], self.PORT))
        self.assertTrue(oauth2proxy._covers_port(["127.0.0.1:4199 (Stream)"], self.PORT))
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=[f"127.0.0.1:{self.PORT}0 (Stream)"],
                              uids=set(), service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("DRIFT", body)

    def test_configured_but_unbound_is_reported_not_believed(self) -> None:
        """`show -p Listen` answers from the unit FILE, so after a ListenStream=
        edit plus a bare daemon-reload it names an address systemd is no longer
        holding. A check that trusted it agreed with itself over an open port."""
        ok, body = self._rows(socket_state="active", enabled="enabled",
                              listening=self._LISTENING, uids=set(),
                              service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("NOT BOUND", body)

    def test_masked_and_absent_are_named_from_the_right_vocabulary(self) -> None:
        """`is-active` never says "masked", and an absent unit reads `inactive` —
        so both of these rows were dead code when they keyed on unit_state."""
        for word in ("masked", "masked-runtime"):
            with self.subTest(word=word):
                ok, body = self._rows(socket_state="inactive", enabled=word,
                                      listening=[], uids=set(),
                                      service_active=True, answers=True)
                self.assertFalse(ok)
                # The ENABLE-STATE WORD itself. `assertIn("UNRESERVED")` is
                # satisfied by all three states that emit that message — it
                # could not distinguish `masked` from `masked-runtime`, which
                # is the entire subject of this subTest.
                self.assertIn(word, body)
        ok, body = self._rows(socket_state="inactive", enabled="", listening=[],
                              uids=set(), service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("NO RESERVATION UNIT", body)

    def test_installed_but_inert_says_pending_not_healthy(self) -> None:
        """Every pre-existing box lands here the moment this version converges,
        and it is the state most likely to be read as done."""
        ok, body = self._rows(socket_state="inactive", enabled="enabled",
                              listening=[], uids={self.PROXY_UID},
                              service_active=True, answers=True)
        self.assertFalse(ok)
        self.assertIn("NOT YET RESERVED", body)


class TestSomethingElseAnsweringTheAuthzHopIsNamedAsBypass(unittest.TestCase):
    """Nothing reserves the fleet's loopback port, so any local account can bind
    it whenever oauth2-proxy is not holding it and answer the forward_auth
    sub-request for every instance on the box. An answer on /ping proves that
    SOMETHING answers, never that it is the proxy — and until this row existed,
    the probe was gated on the unit being active, so the squat case was the one
    state doctor never looked at."""

    def _health(self, t: Path, *, live: bool, failed: bool, pid, answers: bool):
        cfg = make_config(t)
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        (Path(cfg.sso_dir) / "fleet.env").write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.test\nVIDE_SSO_PROXY_PORT=4180\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.test\n")
        with bare_host(oauth2proxy, live=("vide-oauth2-proxy.service",) if live else (),
                       probe=lambda port, *, path="", timeout=3.0:
                           answers and port == 4180), \
             mock.patch.object(oauth2proxy.system, "unit_is_failed", return_value=failed), \
             mock.patch.object(oauth2proxy.system, "unit_main_pid", return_value=pid):
            return oauth2proxy.proxy_health(cfg, check_staleness=False)

    def test_an_answer_from_a_dead_unit_is_called_a_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ok, lines = self._health(Path(t), live=False, failed=True, pid=None, answers=True)
        body = "\n".join(lines)
        self.assertFalse(ok)
        self.assertIn("BYPASS", body)
        self.assertIn("stop caddy", body, "the containment step must come first")
        self.assertIn("reset-failed", body)

    def test_a_healthy_fleet_never_says_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            _, lines = self._health(Path(t), live=True, failed=False, pid=42, answers=True)
        self.assertNotIn("BYPASS", "\n".join(lines))

    def test_a_restarting_proxy_is_not_accused_of_being_an_attacker(self) -> None:
        """THE row that decides whether this line is readable. unit_is_active is
        False for `activating` and `deactivating`, so the naive predicate fires
        during every legitimate restart — accusing the operator mid-remediation,
        which is how a diagnostic gets ignored. `failed`-or-no-MainPID is
        structurally unreachable during a restart window."""
        with tempfile.TemporaryDirectory() as t:
            _, lines = self._health(Path(t), live=False, failed=False, pid=42, answers=True)
        self.assertNotIn("BYPASS", "\n".join(lines))

    def test_an_ordinary_outage_is_still_an_outage(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ok, lines = self._health(Path(t), live=False, failed=True, pid=None, answers=False)
        self.assertFalse(ok)
        self.assertNotIn("BYPASS", "\n".join(lines))


class TestDoctorDescribesABoxItCannotParse(unittest.TestCase):
    """A DIAGNOSTIC REPORTS; it does not die — this module states that rule for
    the fleet-port read and then broke it twice, three sections lower, on the two
    version parses. Both arguments are host state: one is a directory name under
    oauth2_proxy_dir, the other is whatever github answered. So a hand-made
    directory took doctor down with a traceback, on the one verb whose job is to
    describe a box in that state."""

    def _lines(self, t: Path, *, installed: str, latest: str = ""):
        cfg = make_config(t)
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        (Path(cfg.sso_dir) / "fleet.env").write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.test\nVIDE_SSO_PROXY_PORT=4180\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.test\n")
        with bare_host(oauth2proxy), \
             mock.patch.object(oauth2proxy, "installed_version", return_value=installed), \
             mock.patch.object(oauth2proxy.net, "resolve_latest_version",
                               return_value=latest):
            ok, lines = oauth2proxy.proxy_health(cfg, check_staleness=bool(latest))
        return ok, "\n".join(lines)

    def test_an_unparseable_installed_version_is_a_line_not_an_exception(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ok, body = self._lines(Path(t), installed="not-a-version")
        self.assertFalse(ok)
        self.assertIn("UNREADABLE", body)
        # …and the rest of the section still ran: a diagnostic that stops at the
        # first unreadable thing describes less of the box than one that does not.
        self.assertIn("proxy unit:", body)

    def test_an_unparseable_upstream_tag_does_not_redden_a_healthy_fleet(self) -> None:
        # The other direction. github's release naming is not this box's fault,
        # and the floor check has already passed by the time we look at it.
        with tempfile.TemporaryDirectory() as t:
            _, body = self._lines(Path(t), installed="7.15.3", latest="nightly")
        self.assertIn("could not compare", body)
        self.assertNotIn("UNREADABLE", body)

    def test_a_normal_version_still_reports_normally(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            _, body = self._lines(Path(t), installed="7.15.3")
        self.assertIn("proxy version: 7.15.3", body)
        self.assertNotIn("UNREADABLE", body)


class TestRotateWarnsAboutItsOwnRecovery(unittest.TestCase):
    """rotate-sso voids the CSRF cookie along with the session cookies, so the
    operator's next attempt FROM THE SAME BROWSER is refused once with upstream's
    "CSRF token mismatch, potential attack" page. Found 2026-07-27 walking
    sso-smoke §7 against real Google. The verb must say so before it happens:
    this is the stolen-cookie kill switch, pulled by someone already alarmed."""

    def _rotate(self, cfg) -> str:
        import io

        from vide.reporter import Reporter
        buf = io.StringIO()
        ex = _FsExecutor()
        with mock.patch.object(oauth2proxy, "_proxy_pings", return_value=True):
            oauth2proxy.rotate_sso(cfg, ex, Reporter(stream=buf))
        return buf.getvalue()

    def _provisioned(self, t: Path, *, domain: str | None = None):
        cfg = make_config(t)
        cfg.sso_dir.mkdir(parents=True, exist_ok=True)
        oauth2proxy.toml_path(cfg).write_text("# toml\n")
        oauth2proxy.env_path(cfg).write_text(oauth2proxy.render_proxy_env(
            "cid.apps.googleusercontent.com", "GOCSPX-live", "OLDCOOKIE"))
        Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).write_text("x")
        if domain:
            sso.persist_parent_domain(cfg, _FsExecutor(), domain)
        return cfg

    def test_it_names_the_403_before_the_operator_meets_it(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            out = self._rotate(self._provisioned(Path(t), domain="example.com"))
            self.assertIn("403", out)
            self.assertIn("potential attack", out)
            # and the lever that clears it, with THIS fleet's domain in it
            self.assertIn("https://auth.example.com/oauth2/sign_out", out)

    def test_the_warning_survives_a_fleet_with_no_recorded_domain(self) -> None:
        # A torn/partial fleet.env must not turn the advice into a traceback.
        with tempfile.TemporaryDirectory() as t:
            out = self._rotate(self._provisioned(Path(t)))
            self.assertIn("potential attack", out)

    def test_the_kill_switch_still_reports_what_it_did(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            out = self._rotate(self._provisioned(Path(t), domain="example.com"))
            self.assertIn("all sessions are signed out", out)


class _ReloadFailsExecutor(_FsExecutor):
    """A filesystem executor whose `systemctl reload caddy` always fails — the
    box a failed SSO install leaves behind (Caddy absent or unconfigured)."""

    def run(self, argv, **kw):  # type: ignore[override]
        from vide.errors import CommandFailed
        if list(argv)[:3] == ["systemctl", "reload", "caddy"]:
            raise CommandFailed(tuple(argv), 1)
        super().run(argv, **kw)


class TestDestroyFailSoftReload(unittest.TestCase):
    """D6: tombstone (and thus destroy) must complete stop/disable/rm even when
    the caddy reload fails — else the one cleanup verb is broken on exactly the
    box the defect produces. But allow/revoke stay fail-HARD (a silent reload
    failure there is fail-open)."""

    def test_tombstone_drops_allowlist_even_when_reload_fails(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            rep = quiet_reporter()
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.test")
            sso.allow(cfg, _FsExecutor(), rep, "u", "a@example.test")
            self.assertTrue(sso.allowlist_file(cfg, "u").exists())
            sso.tombstone_instance(cfg, _ReloadFailsExecutor(), rep, "u")  # must NOT raise
            self.assertFalse(sso.allowlist_file(cfg, "u").exists(),
                             "the allow-list must drop even when the reload fails")

    def test_allow_stays_fail_hard_on_reload_failure(self) -> None:
        from vide.errors import CommandFailed
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.test")
            with self.assertRaises(CommandFailed):
                sso.allow(cfg, _ReloadFailsExecutor(), quiet_reporter(), "u", "b@example.test")


class TestI10DestroyTearsDownWriteSet(unittest.TestCase):
    """I10: every durable per-instance artifact an SSO install writes has a
    teardown — the allow-list is removed and the imported Caddy body is
    tombstoned (never deleted: a dangling import breaks the operator's caddy)."""

    def test_sso_per_instance_writes_are_torn_down(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            rep = quiet_reporter()
            ex = _FsExecutor()
            sso.persist_parent_domain(cfg, ex, "example.test")
            sso.allow(cfg, ex, rep, "u", "a@example.test")   # writes allow-list + caddy body
            body = sso.caddy_body(cfg, "u")
            self.assertTrue(sso.allowlist_file(cfg, "u").exists())
            self.assertTrue(body.exists())
            sso.tombstone_instance(cfg, ex, rep, "u")
            self.assertFalse(sso.allowlist_file(cfg, "u").exists())   # removed
            self.assertTrue(body.exists())                           # kept, not deleted
            self.assertIn("410", body.read_text())                   # rewritten to a tombstone


class TestNormalize(unittest.TestCase):
    def test_lowercases_and_strips(self) -> None:
        self.assertEqual(sso.normalize_email("  Alice@Example.Com "), "alice@example.com")

    def test_refuses_comma_whitespace_and_shape(self) -> None:
        for bad in ("a,b@x.com", "a b@x.com", "noat", "@x.com", "a@", "a@nodot"):
            with self.assertRaises(UsageError, msg=bad):
                sso.normalize_email(bad)

    def test_refuses_markup_so_the_vide_page_can_reflect_it(self) -> None:
        # An allow-listed address is echoed back as HTML by the per-instance
        # /vide page. Refusing markup HERE — at the only door that writes an
        # allow-list — is what makes that reflection safe. An escaping routine
        # downstream of a validator that let the payload through is the weaker
        # arrangement: it has to be remembered at every future call site.
        for bad in ("a<script>@x.com", "a>b@x.com", 'a"b@x.com', "a'b@x.com",
                    "a&b@x.com", "a`b@x.com", "a{b@x.com", "a}b@x.com",
                    "a\\b@x.com", "a\x01b@x.com"):
            with self.assertRaises(UsageError, msg=bad):
                sso.normalize_email(bad)

    def test_ordinary_addresses_still_pass(self) -> None:
        # The guard above must not cost a legitimate address its login.
        for good in ("first.last@gmail.com", "user+tag@example.co.uk",
                     "a_b-c@sub.domain.example", "123@x.io"):
            self.assertEqual(sso.normalize_email(good), good)

    def test_gmail_variant_warns(self) -> None:
        self.assertIsNotNone(sso.gmail_variant_warning("j.doe@gmail.com"))
        self.assertIsNotNone(sso.gmail_variant_warning("jdoe+x@googlemail.com"))
        self.assertIsNone(sso.gmail_variant_warning("jdoe@gmail.com"))
        self.assertIsNone(sso.gmail_variant_warning("j.doe@example.com"))


class TestAllowRevoke(unittest.TestCase):
    def _cfg(self, t):
        cfg = make_config(Path(t))
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
        return cfg

    def test_allow_adds_renders_and_reloads_caddy(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t)
            ex = _FsExecutor()
            sso.allow(cfg, ex, quiet_reporter(), "u", "Alice@Example.com")
            self.assertEqual(sso.read_allowlist(cfg, "u"), ["alice@example.com"])
            # union file written; per-instance body written; caddy reloaded.
            self.assertIn("alice@example.com\n", sso.union_file(cfg).read_text())
            self.assertIn("alice@example.com", sso.caddy_body(cfg, "u").read_text())
            self.assertIn(("systemctl", "reload", "caddy"), ex.ran)

    def test_allow_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t)
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            self.assertEqual(sso.read_allowlist(cfg, "u"), ["a@x.com"])

    def test_revoke_removes_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t)
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "b@x.com")
            ex = _FsExecutor()
            sso.revoke(cfg, ex, quiet_reporter(), "u", "a@x.com")
            self.assertEqual(sso.read_allowlist(cfg, "u"), ["b@x.com"])
            self.assertNotIn("a@x.com", sso.union_file(cfg).read_text())
            self.assertIn(("systemctl", "reload", "caddy"), ex.ran)

    def test_would_empty_detects_last_email(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t)
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            self.assertTrue(sso.would_empty(cfg, "u", "a@x.com"))
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "b@x.com")
            self.assertFalse(sso.would_empty(cfg, "u", "a@x.com"))

    def test_emptied_whitelist_renders_deny_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(t)
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            sso.revoke(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            body = sso.caddy_body(cfg, "u").read_text()
            self.assertIn("deny@vide.invalid", body)


class TestWhatAConvergeSaysAboutTheReservationItJustInstalled(unittest.TestCase):
    """Two warnings that were missing, and both are about a converge telling the
    operator something FALSE rather than saying nothing.

    NOT YET RESERVED claims "the running proxy still holds 127.0.0.1:<pin>
    itself" and then prescribes upgrade-sso or a reboot on the strength of it. On
    a box whose pin was hand-edited the claim is false and BOTH remedies move the
    fleet's authorization hop instead of landing a reservation on it.

    NOT BOUND is the state nothing said at all: the unit reads `active`, is
    configured for the pin, and holds nothing — a reload orphan. `systemctl
    start` returns -EALREADY there and reports success, so it is reachable from
    both converge branches and neither of them noticed."""

    PIN = 4180

    def _converge(self, t, *, was_active, listening=None, holders=(),
                  socket_live=True, dry_run=False):
        cfg = make_config(Path(t))
        Path(cfg.sso_dir).mkdir(parents=True, exist_ok=True)
        sso.fleet_file(cfg).write_text(
            "VIDE_SSO_PARENT_DOMAIN=example.com\n"
            "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
            f"VIDE_SSO_PROXY_PORT={self.PIN}\n")
        units = Path(cfg.repo_dir) / "units"
        units.mkdir(parents=True, exist_ok=True)
        for u in ("oauth2-proxy.socket", "oauth2-proxy.service"):
            (units / u).write_text((REPO / "units" / u).read_text())
        d = Path(cfg.oauth2_proxy_dir)
        (d / "7.15.2").mkdir(parents=True, exist_ok=True)
        oauth2proxy.current_link(cfg).symlink_to(d / "7.15.2")
        rep, out = capturing_reporter()
        ex = _FsExecutor(sandbox=Path(t))
        # The fakes are constructed dry_run=False (they perform their writes);
        # flipped here rather than plumbed through, because the only thing this
        # row needs from a preview is that ex.dry_run is what the warning reads.
        ex.dry_run = dry_run
        live = (oauth2proxy.SOCKET_UNIT,) if socket_live else ()
        hh = (None if holders is None else system.HopHolders(
            certain=frozenset(holders), possible=frozenset(), served=frozenset()))
        with bare_host(oauth2proxy, live=live), \
             mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                               return_value=(listening if listening is not None
                                             else [f"127.0.0.1:{self.PIN} (Stream)"])), \
             mock.patch.object(oauth2proxy.system, "hop_holders", return_value=hh), \
             mock.patch.object(oauth2proxy, "ensure_identities"), \
             mock.patch.object(oauth2proxy, "ensure_caddy_membership"), \
             mock.patch.object(oauth2proxy, "install_proxy_unit", return_value=False), \
             mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                               return_value=False):
            oauth2proxy.converge_proxy(cfg, ex, rep, parent_domain="example.com",
                                       was_active=was_active)
        return out.getvalue()

    def test_an_active_reservation_that_holds_nothing_is_named(self) -> None:
        said = self._converge(tempfile.mkdtemp(), was_active=True, holders=())
        self.assertIn("NOT BOUND", said)

    def test_a_reservation_that_is_actually_held_says_nothing(self) -> None:
        """Silence on a healthy box. Without this the warning is unconditional
        and every converge in the fleet prints it — an alarm that keeps firing
        after the migration is a token that stops meaning anything."""
        said = self._converge(tempfile.mkdtemp(), was_active=True, holders=(0,))
        self.assertNotIn("NOT BOUND", said)

    def test_an_unreadable_kernel_does_not_produce_the_warning(self) -> None:
        """A measurement that never happened may not print "the fleet's
        authorization port is open right now" and prescribe a gate restart."""
        said = self._converge(tempfile.mkdtemp(), was_active=True, holders=None)
        self.assertNotIn("NOT BOUND", said)

    def test_a_drifted_unit_is_not_described_in_not_bounds_words(self) -> None:
        """Active-and-NOT-covering is DRIFT, whose remedy is not a restart. The
        two states were described in each other's words for two rounds; the
        converge must not re-import the conflation."""
        said = self._converge(tempfile.mkdtemp(), was_active=True, holders=(),
                              listening=["127.0.0.1:9999 (Stream)"])
        self.assertNotIn("NOT BOUND", said)

    def test_a_dry_run_warns_about_nothing(self) -> None:
        said = self._converge(tempfile.mkdtemp(), was_active=True, holders=(),
                              dry_run=True)
        self.assertNotIn("NOT BOUND", said)

    def test_a_pin_with_nothing_on_it_is_not_told_the_ordinary_remedy(self) -> None:
        """The migration-day row, on a box whose pin moved. `upgrade-sso` and a
        reboot are exactly the two commands that would perform the move."""
        said = self._converge(tempfile.mkdtemp(), was_active=True,
                              socket_live=False, holders=())
        self.assertIn("NOT ON THE PIN", said)
        self.assertNotIn("NOT YET RESERVED", said)

    def test_the_ordinary_unmigrated_box_still_gets_the_migration_lever(self) -> None:
        """The opposite sign, and it is mandatory: without it the move-aware
        branch could swallow the remedy on every un-migrated box in the fleet."""
        said = self._converge(tempfile.mkdtemp(), was_active=True,
                              socket_live=False, holders=(60001,))
        self.assertIn("NOT YET RESERVED", said)
        self.assertIn("upgrade-sso", said)

    def test_an_unreadable_kernel_keeps_the_status_quo_message(self) -> None:
        said = self._converge(tempfile.mkdtemp(), was_active=True,
                              socket_live=False, holders=None)
        self.assertIn("NOT YET RESERVED", said)


class TestAGrantMayNotMoveTheFleetsAuthorizationHop(unittest.TestCase):
    """`_render_all` reads the pin live, rewrites EVERY instance's forward_auth
    upstream, and its callers then reload Caddy — on every allow, revoke and
    destroy. So one edited `fleet.env` row plus one routine grant repointed the
    authorization sub-request of every `auth: none` IDE on the box at an address
    nothing was holding, and pushed it live. Any local account could then bind
    that address and answer 202 for every instance, collecting the fleet cookie.

    The detection is FILES — the hop already rendered into the bodies, compared
    against the pin — so on a healthy box and on every first install nothing
    moves, no host read happens, and this guard costs nothing."""

    HELD = 4180         # what the existing bodies dial
    MOVED = 4181        # what a hand-edited fleet.env now says

    def _cfg(self, t, port=None):
        cfg = make_config(Path(t))
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
        if port is not None:
            f = sso.fleet_file(cfg)
            f.write_text(f.read_text() + f"VIDE_SSO_PROXY_PORT={port}\n")
        return cfg

    def _settled(self, t):
        """A box with one instance whose body already dials HELD."""
        cfg = self._cfg(t, self.HELD)
        sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
        self.assertIn(f"127.0.0.1:{self.HELD}", sso.caddy_body(cfg, "u").read_text())
        return cfg

    def _repin(self, cfg, port):
        f = sso.fleet_file(cfg)
        f.write_text(f.read_text().replace(
            f"VIDE_SSO_PROXY_PORT={self.HELD}", f"VIDE_SSO_PROXY_PORT={port}"))

    def test_a_moved_pin_does_not_repoint_every_instances_authz_hop(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._settled(Path(t))
            self._repin(cfg, self.MOVED)
            ex = _FsExecutor()
            with bare_host(oauth2proxy), self.assertRaises(StateError):
                sso.allow(cfg, ex, quiet_reporter(), "u", "b@x.com")
            body = sso.caddy_body(cfg, "u").read_text()
        self.assertIn(f"127.0.0.1:{self.HELD}", body)
        self.assertNotIn(f"127.0.0.1:{self.MOVED}", body)
        # THE ASSERTION WITH AN ATTACKER BEHIND IT. Rendering the wrong upstream
        # is inert until something pushes it live, and the callers of this
        # function reload Caddy on the very next line.
        self.assertNotIn(("systemctl", "reload", "caddy"), ex.ran)

    def test_a_revoke_still_evicts_fleet_wide_when_the_body_render_refuses(self) -> None:
        """The ordering inside `_render_all` is a security property, not style:
        the union is the fail-closed authn base and is written FIRST, so a
        revocation still lands fleet-wide even when the body render refuses.
        Moved above that write, this guard would turn `vide revoke` into a no-op
        during the one incident it exists for."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._settled(Path(t))
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "b@x.com")
            self._repin(cfg, self.MOVED)
            # Seeded by hand so the mutation this row exists to catch fails for
            # ITS OWN reason. Deleting the union write from _render_all would
            # otherwise leave no union file at all, and the assertion below would
            # die of FileNotFoundError — a red row that proves the file is
            # missing, not that a revocation stopped landing.
            sso.union_file(cfg).write_text("a@x.com\nb@x.com\n")
            with bare_host(oauth2proxy), self.assertRaises(StateError):
                sso.revoke(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            union = sso.union_file(cfg).read_text()
        self.assertNotIn("a@x.com", union, "the revocation did not reach the union")
        self.assertIn("b@x.com", union)

    def test_a_box_with_no_bodies_yet_renders_and_reads_no_host_seam(self) -> None:
        """Absence of a reservation is NOT evidence that the pin moved. A first
        install has no bodies, so nothing can move, so the permit is never
        consulted — which is what keeps every existing allow/revoke row hermetic
        without a single new double."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(Path(t), self.MOVED)
            with mock.patch.object(oauth2proxy.system, "hop_holders",
                                   side_effect=AssertionError("host read on the "
                                                              "no-move path")):
                sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            self.assertIn(f"127.0.0.1:{self.MOVED}",
                          sso.caddy_body(cfg, "u").read_text())

    def test_a_completed_move_is_permitted_because_the_gate_is_demonstrably_there(self) -> None:
        """The other sign. Once the documented move has completed — the
        reservation is active, configured for the pin, and the socket there is
        owned by uid 0 alone — the bodies are the half still lagging and
        rendering them is the repair, not the attack."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._settled(Path(t))
            self._repin(cfg, self.MOVED)
            with bare_host(oauth2proxy, live=(oauth2proxy.SOCKET_UNIT,)), \
                 mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                   return_value=[f"127.0.0.1:{self.MOVED} (Stream)"]), \
                 mock.patch.object(oauth2proxy.system, "hop_holders",
                                   return_value=system.HopHolders(
                                       certain=frozenset({0}), possible=frozenset(),
                                       served=frozenset())):
                sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "b@x.com")
            self.assertIn(f"127.0.0.1:{self.MOVED}",
                          sso.caddy_body(cfg, "u").read_text())

    def test_root_holding_some_other_wildcard_port_is_not_our_reservation(self) -> None:
        """`certain == {0}` alone proves ROOT holds the address, never that OUR
        reservation does — hop_holders' v4 match set includes the 0.0.0.0
        wildcard, so any unrelated root daemon on a wildcard port satisfies it.
        Without the `covers` conjunct a hand-edited pin landing on such a port
        would repoint every instance's forward_auth — and the fleet cookie with
        it — at that service."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._settled(Path(t))
            self._repin(cfg, self.MOVED)
            with bare_host(oauth2proxy, live=(oauth2proxy.SOCKET_UNIT,)), \
                 mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                   return_value=[f"127.0.0.1:{self.HELD} (Stream)"]), \
                 mock.patch.object(oauth2proxy.system, "hop_holders",
                                   return_value=system.HopHolders(
                                       certain=frozenset({0}), possible=frozenset(),
                                       served=frozenset())), \
                 self.assertRaises(StateError):
                sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "b@x.com")

    def _case2(self, sysd, port, *, loaded):
        """CASE 2 with the ONE account that can actually reach it.

        `identities=(PROXY_USER,)` is not decoration and the parity row above
        cannot substitute for this: bare_host without it answers `None` from
        `user_uid`, so `certain == {proxy_uid}` is unsatisfiable and CASE 2
        returns False whatever the gate does. Every subTest there stays green
        under both signs of the gate's mutation — which is exactly how a control
        gets deleted invisibly."""
        with bare_host(oauth2proxy, identities=(oauth2proxy.PROXY_USER,)), \
                mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                mock.patch.object(oauth2proxy.system, "unit_state",
                                  return_value="inactive"), \
                mock.patch.object(oauth2proxy.system, "unit_listen_streams",
                                  return_value=loaded), \
                mock.patch.object(oauth2proxy.system, "hop_holders",
                                  return_value=system.HopHolders(
                                      certain=frozenset({60001}),
                                      possible=frozenset(),
                                      served=frozenset())):
            return oauth2proxy.gate_is_on_hop(port)

    def test_a_gate_that_bound_a_moved_pin_itself_is_not_a_permit(self) -> None:
        """THE ATTACKER'S STATE, and the only permit in this predicate anything
        can actually reach. `certain == {0}` is not attacker-reachable —
        SO_REUSEPORT needs a matching effective uid and the unit carries no
        ReusePort= — but `certain == {proxy_uid}` is reachable by exactly one
        account: the gate itself, which is the one identity on this box with a
        pre-authentication surface facing the internet.

        On a MIGRATED box whose pin was hand-edited (a steady state by design,
        because the write refusal parks it there) the new pin is free and the
        service unit carries no SocketBindDeny=. A compromised gate binds it,
        and without this conjunct the next `vide allow` repoints every instance's
        forward_auth — and the fleet cookie with it — at the attacker."""
        with tempfile.TemporaryDirectory() as t:
            sysd = Path(t) / "systemd"
            sysd.mkdir()
            (sysd / oauth2proxy.SOCKET_UNIT).write_text("# a migrated box\n")
            got = self._case2(sysd, self.MOVED,
                              loaded=[f"127.0.0.1:{self.HELD} (Stream)"])
        self.assertFalse(got, "a reservation exists, so CASE 2 may not apply")

    def test_the_unmigrated_box_where_the_proxy_holds_the_pin_is_permitted(self) -> None:
        """The opposite sign, and it is mandatory rather than decorative: CASE 2
        exists so a box that has not migrated yet — the gate bound the port
        itself, before any reservation — can still have its bodies rendered. If
        the conjunct were `return False` unconditionally this row is the only
        thing that notices, and every un-migrated box in the fleet would lose
        `vide allow` on the day it upgraded."""
        with tempfile.TemporaryDirectory() as t:
            sysd = Path(t) / "systemd"
            sysd.mkdir()          # NO reservation unit at all
            got = self._case2(sysd, self.HELD, loaded=[])
        self.assertTrue(got, "an un-migrated box lost its permit")

    def test_the_permit_agrees_with_doctors_holds_wherever_they_overlap(self) -> None:
        """`gate_is_on_hop` is a SECOND spelling of doctor's `holds` triple, and
        deliberately so: doctor's line is the byte-exact anchor of a mutation row,
        and this predicate is strictly broader (it also admits the un-migrated
        box, where no reservation exists at all). Its docstring promises this row,
        and a promised mitigation nobody wrote is how a deliberate duplication
        becomes an accidental divergence.

        Overlap = a box that HAS a reservation. There, the two must be identical
        across all eight combinations of the triple."""
        for active in (True, False):
            for covers in (True, False):
                for root in (True, False):
                    with self.subTest(active=active, covers=covers, root=root), \
                         tempfile.TemporaryDirectory() as t:
                        sysd = Path(t) / "systemd"
                        sysd.mkdir()
                        (sysd / oauth2proxy.SOCKET_UNIT).write_text("# installed\n")
                        listening = ([f"127.0.0.1:{self.HELD} (Stream)"] if covers
                                     else ["127.0.0.1:9999 (Stream)"])
                        certain = frozenset({0}) if root else frozenset()
                        with bare_host(oauth2proxy), \
                             mock.patch.object(oauth2proxy, "SYSTEMD_DIR", sysd), \
                             mock.patch.object(oauth2proxy.system, "unit_state",
                                               return_value="active" if active
                                               else "inactive"), \
                             mock.patch.object(oauth2proxy.system,
                                               "unit_listen_streams",
                                               return_value=listening), \
                             mock.patch.object(oauth2proxy.system, "hop_holders",
                                               return_value=system.HopHolders(
                                                   certain=certain,
                                                   possible=frozenset(),
                                                   served=frozenset())):
                            # Doctor's own triple, spelled exactly as proxy_health
                            # spells it, from the same three readings.
                            holds = (oauth2proxy.system.unit_state(
                                         oauth2proxy.SOCKET_UNIT) == "active"
                                     and oauth2proxy._covers_port(listening,
                                                                  self.HELD)
                                     and set(certain) == {0})
                            self.assertEqual(
                                holds, oauth2proxy.gate_is_on_hop(self.HELD),
                                "the render permit and doctor's reserved row "
                                "disagree about the same box")

    def test_auth_caddy_still_refuses_when_every_body_is_gone(self) -> None:
        """The leg that exists for the box body-side detection cannot reach. On a
        fleet whose instances were all destroyed there are no bodies left to
        disagree with the pin — while auth.caddy still remembers what the
        operator pasted from. That is the pre-pin `sudo -E VIDE_SSO_PROXY_PORT=<n>`
        window, where one environment variable on one command re-points a whole
        fleet with no file written and nothing left behind."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._cfg(Path(t), self.MOVED)
            # No bodies at all — only the record of what was pasted.
            (Path(cfg.sso_dir) / "caddy").mkdir(parents=True, exist_ok=True)
            (Path(cfg.sso_dir) / "caddy" / "auth.caddy").write_text(
                f"forward_auth 127.0.0.1:{self.HELD} {{\n}}\n")
            with bare_host(oauth2proxy), self.assertRaises(StateError):
                sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")

    def test_the_upgrade_lever_warns_instead_of_dying_in_the_re_render(self) -> None:
        """`rerender_bodies` runs at the TAIL of upgrade-sso — after the binary
        was swapped, the gate restarted and the old version pruned. A raise there
        reports failure for a run that already succeeded at its primary purpose.
        Refuse the write, not the verb, one module over."""
        with tempfile.TemporaryDirectory() as t:
            cfg = self._settled(Path(t))
            self._repin(cfg, self.MOVED)
            rep, out = capturing_reporter()
            ex = _FsExecutor()
            with bare_host(oauth2proxy):
                sso.rerender_bodies(cfg, ex, rep)      # must not raise
            body = sso.caddy_body(cfg, "u").read_text()
        self.assertIn(f"127.0.0.1:{self.HELD}", body)
        self.assertIn("REFUSING", out.getvalue())
        self.assertNotIn(("systemctl", "reload", "caddy"), ex.ran)


class TestUnionSeed(unittest.TestCase):
    """The bootstrap union seed must DERIVE from the canonical allow-lists,
    under the verbs' lock. The old blind `write "" if missing` raced a
    concurrent `vide allow` between its exists() check and its write,
    truncating a just-populated union — fail-closed fleet-wide 401s until the
    next re-render."""

    def test_seed_union_derives_from_allowlists_never_blind_empty(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            sso.union_file(cfg).unlink()   # the torn-union / race window state
            sso.seed_union(cfg, _FsExecutor())
            self.assertIn("a@x.com\n", sso.union_file(cfg).read_text())

    def test_converge_preserves_populated_union(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
            oauth2proxy.current_link(cfg).write_text("x")
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit"), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(
                    cfg, _FsExecutor(), quiet_reporter(),
                    parent_domain="example.com", was_active=False)
            self.assertIn("a@x.com\n", sso.union_file(cfg).read_text())

    def test_converge_seeds_missing_union_from_allowlists(self) -> None:
        # The race outcome pinned deterministically AT THE converge_proxy
        # BOUNDARY: union MISSING while allow-lists are populated. The
        # historical exists()-guarded blind write left "" here; an
        # unconditional one truncated a live union — both must go red on this.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            sso.union_file(cfg).unlink()
            Path(cfg.oauth2_proxy_dir).mkdir(parents=True, exist_ok=True)
            oauth2proxy.current_link(cfg).write_text("x")
            with mock.patch.object(oauth2proxy, "ensure_identities"), \
                 mock.patch.object(oauth2proxy, "install_proxy_unit"), \
                 mock.patch.object(oauth2proxy, "install_proxy_socket_unit",
                                   return_value=False), \
                 mock.patch.object(oauth2proxy, "ensure_caddy_membership"):
                oauth2proxy.converge_proxy(
                    cfg, _FsExecutor(), quiet_reporter(),
                    parent_domain="example.com", was_active=False)
            self.assertIn("a@x.com\n", sso.union_file(cfg).read_text())

    def test_seed_union_dry_run_creates_no_lock(self) -> None:
        # The allow() precedent: a preview must not create <sso_dir>/.lock.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            ex = Executor(dry_run=True, reporter=quiet_reporter(), cfg=cfg)
            sso.seed_union(cfg, ex)
            self.assertFalse((Path(cfg.sso_dir) / ".lock").exists())
            self.assertFalse(sso.union_file(cfg).exists())


class TestParentDomainGuard(unittest.TestCase):
    """Rendering authz bodies without a recorded parent domain must refuse
    LOUDLY: an empty parent writes `redir * https://auth.//oauth2/start...`
    into every body and reloads caddy with no error anyone sees — exactly the
    restored-from-backup box that lost fleet.env."""

    def _damaged_box(self, t):
        cfg = make_config(Path(t))
        sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
        sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
        sso.fleet_file(cfg).unlink()          # the restore damage
        return cfg

    def test_allow_refuses_when_parent_domain_lost(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._damaged_box(t)
            with self.assertRaises(StateError) as cm:
                sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "b@x.com")
            self.assertIn("VIDE_SSO_PARENT_DOMAIN", str(cm.exception))
            # fail-loud must beat fail-broken: the body never carries the
            # empty-parent redirect.
            self.assertNotIn("auth.//", sso.caddy_body(cfg, "u").read_text())

    def test_corrupt_parent_domain_refused_by_shape(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = self._damaged_box(t)
            sso.fleet_file(cfg).write_text("VIDE_SSO_PARENT_DOMAIN=EXAMPLE..com\n")
            with self.assertRaises(ConfigError) as cm:
                sso.revoke(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            # the refusal names WHERE the corrupt value came from...
            self.assertIn("fleet.env", str(cm.exception))
            # ...and the artifact never carries it
            self.assertNotIn("EXAMPLE..com", sso.caddy_body(cfg, "u").read_text())

    def test_check_dns_name_rejects_trailing_newline(self) -> None:
        # $ matches before a final \n; the backstop must use \Z — this regex
        # is the newline-smuggling gate for proxy.toml and the Caddy redirect.
        with self.assertRaises(ConfigError):
            oauth2proxy.check_dns_name("example.com\n")

    def test_tombstone_survives_corrupt_parent_domain(self) -> None:
        # The ConfigError leg of the D6 catch: a shape-corrupt fleet.env must
        # not abort teardown either, and the union still drops the revoked email.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "v", "b@x.com")
            sso.fleet_file(cfg).write_text("VIDE_SSO_PARENT_DOMAIN=EXAMPLE..com\n")
            sso.tombstone_instance(cfg, _FsExecutor(), quiet_reporter(), "u")  # must NOT raise
            self.assertFalse(sso.allowlist_file(cfg, "u").exists())
            self.assertNotIn("a@x.com", sso.union_file(cfg).read_text())

    def test_tombstone_survives_lost_parent_domain(self) -> None:
        # D6: destroy still tears down on the damaged box, and the union —
        # written before the guard can fire — still reflects the revocation.
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "v", "b@x.com")
            sso.fleet_file(cfg).unlink()
            sso.tombstone_instance(cfg, _FsExecutor(), quiet_reporter(), "u")  # must NOT raise
            self.assertFalse(sso.allowlist_file(cfg, "u").exists())
            union = sso.union_file(cfg).read_text()
            self.assertNotIn("a@x.com", union)
            self.assertIn("b@x.com", union)


class TestClaimAndTombstone(unittest.TestCase):
    def test_claim_binding_writes_socket_record(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.state_dir.mkdir(parents=True)
            ex = _FsExecutor()
            b = sso.claim_binding(cfg, ex, quiet_reporter(), "u")
            self.assertEqual(b.kind, "unix")
            rec = (cfg.state_dir / "u.env").read_text()
            self.assertIn("VIDE_MODE=sso", rec)
            self.assertIn("VIDE_SOCKET=/run/vide/u/code-server.sock", rec)
            self.assertNotIn("VIDE_PORT", rec)

    def test_tombstone_writes_410_and_never_deletes_body(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            sso.persist_parent_domain(cfg, _FsExecutor(), "example.com")
            sso.allow(cfg, _FsExecutor(), quiet_reporter(), "u", "a@x.com")
            ex = _FsExecutor()
            sso.tombstone_instance(cfg, ex, quiet_reporter(), "u")
            body = sso.caddy_body(cfg, "u")
            self.assertTrue(body.exists(), "the imported body must survive (dangling import = outage)")
            self.assertIn("410", body.read_text())
            self.assertFalse(sso.allowlist_file(cfg, "u").exists())


class TestDoctorSurvivesTheThingItDiagnoses(unittest.TestCase):
    """A hand-broken pin must be REPORTED, never raised through, and never read
    as health.

    `proxy_health`'s docstring promises exactly this — "a doctor that aborts on
    the very state it exists to describe leaves the operator with a traceback and
    an exit code from the wrong family" — and until this row nothing called
    `proxy_health` with an unreadable pin at all. Every other 99999 fixture in
    the suite calls a single row directly, so the section's own guard, the one
    that turns the fault into a line and stops the run, was the promise nobody
    checked.

    Worth recording what this row does NOT prove, because the first draft of it
    claimed otherwise: `_pin_served` and `_gate_on_pin` each carry their own
    `except ConfigError: return False`, and those arms are UNREACHABLE from here
    — the guard below catches the same read some three hundred lines earlier and
    returns. They are defensive, and contriving a state that reaches them would
    be a test of nothing. The mutation rows for this test therefore aim at the
    guard that actually runs."""

    def test_an_unreadable_pin_is_reported_rather_than_raised(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            cfg.sso_dir.mkdir(parents=True, exist_ok=True)
            (cfg.sso_dir / "caddy").mkdir(parents=True, exist_ok=True)
            sso.fleet_file(cfg).write_text(
                "VIDE_SSO_PARENT_DOMAIN=example.com\n"
                "VIDE_SSO_ISSUER_URL=https://accounts.google.com\n"
                "VIDE_SSO_PROXY_PORT=99999\n")
            # Not a guess that it raises: pin the premise first, so a future
            # change that makes 99999 acceptable turns this row into a rot
            # report rather than a silent pass.
            with self.assertRaises(ConfigError):
                sso.fleet_port(cfg)
            with bare_host(oauth2proxy), \
                 mock.patch.object(oauth2proxy, "bootstrap_observed",
                                   return_value=True):
                ok, lines = oauth2proxy.proxy_health(cfg, check_staleness=False)
        self.assertFalse(ok, "a box with an unreadable pin read as healthy")
        self.assertTrue(lines, "doctor printed nothing at all about it")


if __name__ == "__main__":
    unittest.main()
