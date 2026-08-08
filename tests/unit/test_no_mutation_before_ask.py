"""I8 — red-first: a --no-gui run that cannot complete for want of a REQUIRED
input must die BEFORE the first durable mutation.

This is the hermetic capture of the manual smoke §3 finding: a scripted SSO
install missing a required flag exits EX_USAGE (64) with the right message, but
only AFTER apt prereqs, the toolchain, a sudo-group 'vide' user and
/etc/vide/sso/fleet.env are already on the host.

Unlike test_flow_prompter._Flow, this harness leaves the EARLY mutation seams
LIVE (ensure_prereqs records real apt argv into the RecordingExecutor) — the
whole point is that `ex.actions == []` proves the sequencer mutated NOTHING, not
that a stub was never called. It is driven by the REAL PlainPrompter (a scripted
--no-gui invocation), never a stub prompter that could skip the resolution.

Today every missing-input cell is RED (an action is recorded before the raise);
the positive control proves the harness does record mutations when inputs are
complete. After the resolve/apply split, the missing-input cells go green while
the positive control stays green.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import RecordingExecutor, bare_host, make_config  # noqa: E402
from vide import install_flow  # noqa: E402
from vide.confirm import Confirmer  # noqa: E402
from vide.errors import UsageError, ConfigError  # noqa: E402
from vide.prompter import PlainPrompter  # noqa: E402
from vide.reporter import Reporter  # noqa: E402

CID = "cid.apps.googleusercontent.com"


class _LiveEarly:
    """run_install with only the OBSERVATION seams patched; the early mutation
    seams (ensure_prereqs, ensure_sudo, users.ensure_user) stay LIVE and record.
    The heavy DOWNSTREAM work (real toolchain download, code-server, the proxy
    binary) is recorded-but-not-executed so the test is host-free yet still
    counts every mutation that would precede the required-input ask."""

    def __init__(self, tmp: Path, **cfg_over) -> None:
        self.cfg = make_config(tmp, vide_user="alice", auth="sso", **cfg_over)
        self.ex = RecordingExecutor()
        self.rep = Reporter(stream=__import__("io").StringIO())
        self.conf = Confirmer(yes_argv=True, environ={}, reporter=self.rep)

    def run(self, prompter) -> int:
        fl = install_flow

        def marker(name):
            def _f(*a, **k):
                # record as a mutation without doing real work
                self.ex.run([f"<{name}>"])
                return "latest"
            return _f

        patches = [
            mock.patch.object(fl, "require_root"),
            mock.patch.object(fl.preflight, "platform_gate"),
            mock.patch.object(fl.preflight, "tools_gate"),
            # force ensure_prereqs down the apt path deterministically, host-free
            mock.patch.object(fl.system, "have_cmd", return_value=False),
            mock.patch.object(fl.system, "ldconfig_has", return_value=False),
            mock.patch.object(fl.system, "visudo_cmd", return_value="/usr/sbin/visudo"),
            mock.patch.object(fl.system, "user_exists", return_value=True),
            mock.patch.object(fl.registry, "instance_mode", return_value=None),
            mock.patch.object(fl.node, "nvm_resolve_bindir", return_value=None),
            mock.patch.object(fl.node, "pnpm_resolve_bin", return_value=None),
            # DOWNSTREAM heavy seams: record a marker, do no real work
            mock.patch.object(fl.node, "ensure_node_pnpm", side_effect=marker("node")),
            mock.patch.object(fl.codeserver, "ensure_code_server", side_effect=marker("code-server")),
            mock.patch.object(fl.oauth2proxy, "provisioned", return_value=False),
            mock.patch.object(fl.oauth2proxy, "converge_proxy", side_effect=marker("proxy")),
            # downstream SSO seams (the --sso-allow ask sits after all of these,
            # at install_flow.py:470): record markers, do no real work
            mock.patch.object(fl.sso, "claim_binding", side_effect=marker("binding")),
            mock.patch.object(fl.secrets, "ensure_sso_config", side_effect=marker("sso-config")),
            mock.patch.object(fl.sysd, "install_unit", side_effect=marker("unit")),
            mock.patch.object(fl.sysd, "enable_start", side_effect=marker("enable")),
            mock.patch.object(fl, "link_cli", side_effect=marker("link")),
            mock.patch.object(fl.sso, "allow", side_effect=marker("allow")),
            mock.patch.object(fl.transport, "probe_transport", side_effect=marker("probe")),
        ]
        started = []
        try:
            for p in patches:
                p.start()
                started.append(p)
            return fl.run_install(self.cfg, self.ex, self.rep, self.conf,
                                  prompter=prompter)
        finally:
            for p in reversed(started):
                p.stop()


class TestNoMutationBeforeRequiredInputs(unittest.TestCase):
    def _flow(self, tmp):
        return _LiveEarly(Path(tmp))

    def _plain(self, **kw):
        rep = Reporter(stream=__import__("io").StringIO())
        return PlainPrompter(rep, **kw)

    def test_missing_secret_mutates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self._flow(tmp)
            f.cfg = make_config(Path(tmp), vide_user="alice", auth="sso",
                                fqdn="u.example.test")
            pr = self._plain(sso_client_id=CID, sso_secret=None,
                             sso_allow="a@example.test")
            with self.assertRaises(UsageError) as cm:
                f.run(pr)
            self.assertIn("--sso-secrets-stdin", str(cm.exception))
            self.assertEqual(f.ex.actions, [],
                             "the host was mutated before the missing-secret refusal")

    def test_missing_fqdn_mutates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self._flow(tmp)
            f.cfg = make_config(Path(tmp), vide_user="alice", auth="sso", fqdn="")
            pr = self._plain(sso_client_id=CID, sso_secret="GOCSPX-x",
                             sso_allow="a@example.test")
            with self.assertRaises(UsageError) as cm:
                f.run(pr)
            self.assertIn("--fqdn", str(cm.exception))
            self.assertEqual(f.ex.actions, [],
                             "the host was mutated before the missing-fqdn refusal")

    def test_missing_allow_mutates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self._flow(tmp)
            f.cfg = make_config(Path(tmp), vide_user="alice", auth="sso",
                                fqdn="u.example.test")
            pr = self._plain(sso_client_id=CID, sso_secret="GOCSPX-x", sso_allow="")
            with self.assertRaises(UsageError) as cm:
                f.run(pr)
            self.assertIn("--sso-allow", str(cm.exception))
            self.assertEqual(f.ex.actions, [],
                             "the host was mutated before the missing-allow refusal")

    def test_malformed_fqdn_mutates_nothing(self):
        # code-quality's condition (D3): presence alone does not fix this — an
        # upper-case fqdn passes every presence check, then dies in the renderer's
        # lowercase-only _DNS_NAME. resolve now shape-checks it, so the refusal is
        # a ConfigError raised before the first mutation.
        with tempfile.TemporaryDirectory() as tmp:
            f = self._flow(tmp)
            # An upper-case FIRST label: the derived parent (example.test) is a
            # valid DNS name and the fqdn is under it, so ONLY the fqdn shape-check
            # can catch this — it isolates that gate from the parent/endswith checks.
            f.cfg = make_config(Path(tmp), vide_user="alice", auth="sso",
                                fqdn="U.example.test")
            pr = self._plain(sso_client_id=CID, sso_secret="GOCSPX-x",
                             sso_allow="a@example.test")
            with self.assertRaises(ConfigError):
                f.run(pr)
            self.assertEqual(f.ex.actions, [],
                             "the host was mutated before the malformed-fqdn refusal")

    def test_apply_mutates_positive_control(self):
        # anti-vacuous: with COMPLETE inputs the harness DOES record mutations,
        # so an empty-actions green above can never be reached by simply never
        # mutating. (This run proceeds past the asks; downstream heavy seams are
        # markers, so it records apt + node at least.)
        with tempfile.TemporaryDirectory() as tmp:
            f = self._flow(tmp)
            f.cfg = make_config(Path(tmp), vide_user="alice", auth="sso",
                                fqdn="u.example.test")
            pr = self._plain(sso_client_id=CID, sso_secret="GOCSPX-x",
                             sso_allow="a@example.test")
            try:
                f.run(pr)
            except Exception:
                pass  # we only care that mutations were recorded
            self.assertTrue(f.ex.actions,
                            "positive control recorded no mutation — the harness is vacuous")


class TestAuthzBeforeStart(unittest.TestCase):
    """D5: the allow-list (and its rendered Caddy body) is established BEFORE the
    auth:none code-server is enabled/started — an instance must never be
    startable while its whitelist is empty."""

    def test_allow_precedes_enable_start(self):
        fl = install_flow
        order: list[str] = []

        def note(name, ret=None):
            def _f(*a, **k):
                order.append(name)
                return ret
            return _f

        plan = fl.InstallPlan(
            target="u", action=fl.InstanceAction.CONVERGE, mode="sso",
            fqdn="u.example.test", parent_domain="example.test",
            whitelist_email="a@example.test")
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t), vide_user="u")
            ex = RecordingExecutor()
            rep = Reporter(stream=__import__("io").StringIO())
            binding = fl.registry.Binding.unix(Path("/run/vide/u/code-server.sock"))
            with mock.patch.object(fl.oauth2proxy, "converge_proxy",
                                   side_effect=note("converge_proxy", "block")), \
                 mock.patch.object(fl.oauth2proxy, "proxy_ready", return_value=True), \
                 mock.patch.object(fl.codeserver, "ensure_code_server", side_effect=note("code", "v")), \
                 mock.patch.object(fl.sso, "claim_binding", side_effect=note("binding", binding)), \
                 mock.patch.object(fl.secrets, "ensure_sso_config", side_effect=note("sso_config")), \
                 mock.patch.object(fl.sso, "allow", side_effect=note("allow")), \
                 mock.patch.object(fl.sysd, "install_unit", side_effect=note("install_unit")), \
                 mock.patch.object(fl.sysd, "enable_start", side_effect=note("enable_start")), \
                 mock.patch.object(fl, "link_cli", side_effect=note("link")), \
                 mock.patch.object(fl.transport, "probe_transport", side_effect=note("probe")), \
                 mock.patch.object(fl.sso, "read_allowlist", return_value=["a@example.test"]):
                with bare_host(fl, fl.oauth2proxy):
                    fl._apply_sso(cfg, ex, rep, PlainPrompter(rep), plan)
        self.assertIn("allow", order)
        self.assertIn("enable_start", order)
        self.assertLess(order.index("allow"), order.index("enable_start"),
                        "the allow-list must be written before the gateway starts")
        # The plan carries sso_bootstrap=False — an ordinary converge of a box
        # that already has a proxy — and the shared proxy is converged anyway.
        # That is the fix for its unit and proxy.toml having been written once
        # and never again; gating it on "first install" is the defect.
        self.assertIn("converge_proxy", order)
        self.assertLess(order.index("converge_proxy"), order.index("enable_start"))

    def test_persist_parent_precedes_render(self):
        # The persist_parent_domain < _render_all invariant (D3): fleet.env must
        # be recorded before its first reader (sso.allow -> _render_all), so a run
        # that fails before the render never pins a half-derived domain.
        fl = install_flow
        order: list[str] = []

        def note(name, ret=None):
            def _f(*a, **k):
                order.append(name)
                return ret
            return _f

        plan = fl.InstallPlan(
            target="u", action=fl.InstanceAction.CONVERGE, mode="sso",
            fqdn="u.example.test", parent_domain="example.test",
            persist_parent=True, whitelist_email="a@example.test")
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t), vide_user="u")
            ex = RecordingExecutor()
            rep = Reporter(stream=__import__("io").StringIO())
            binding = fl.registry.Binding.unix(Path("/run/vide/u/code-server.sock"))
            with mock.patch.object(fl.oauth2proxy, "converge_proxy",
                                   side_effect=note("converge_proxy", "block")), \
                 mock.patch.object(fl.oauth2proxy, "proxy_ready", return_value=True), \
                 mock.patch.object(fl.sso, "persist_parent_domain", side_effect=note("persist")), \
                 mock.patch.object(fl.codeserver, "ensure_code_server", side_effect=note("code", "v")), \
                 mock.patch.object(fl.sso, "claim_binding", side_effect=note("binding", binding)), \
                 mock.patch.object(fl.secrets, "ensure_sso_config", side_effect=note("sso_config")), \
                 mock.patch.object(fl.sso, "allow", side_effect=note("render")), \
                 mock.patch.object(fl.sysd, "install_unit", side_effect=note("install_unit")), \
                 mock.patch.object(fl.sysd, "enable_start", side_effect=note("enable_start")), \
                 mock.patch.object(fl, "link_cli", side_effect=note("link")), \
                 mock.patch.object(fl.transport, "probe_transport", side_effect=note("probe")), \
                 mock.patch.object(fl.sso, "read_allowlist", return_value=["a@example.test"]):
                with bare_host(fl, fl.oauth2proxy):
                    fl._apply_sso(cfg, ex, rep, PlainPrompter(rep), plan)
        self.assertIn("persist", order)
        self.assertIn("render", order)
        self.assertLess(order.index("persist"), order.index("render"),
                        "fleet.env must be persisted before its first reader")


if __name__ == "__main__":
    unittest.main()
