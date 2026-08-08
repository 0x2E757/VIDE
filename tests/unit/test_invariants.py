"""The invariant pins — what jumped from grep-policed convention to structure,
and the tests that keep it there.

I1  dry-run boundary: domain modules cannot reach the system except through
    the injected Executor (mutations) and vide.system (observes).
I2  a full converge under dry-run mutates NOTHING (semantic backstop for I1's
    name-based AST ceiling).
I3  stderr logs / machine stdout.
I4  single config emitter.
I5  the dry-run banner is never silent.
I6  Config structurally carries no control lever.
I7  curses is confined to the tui/ adapter subpackage, which in turn imports
    no domain module and no Executor — the wizard can never grow mutation
    capability, and the plain path can never grow a curses dependency.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PKG = REPO / "src" / "vide"
sys.path.insert(0, str(REPO / "src"))
# `fakes` is imported at function level further down, so the path it needs must
# still be set here — a module that only half-assembles its own sys.path is
# runnable under run.py and broken under any harness that names one test.
sys.path.insert(0, str(REPO / "tests" / "unit"))

from vide.config import SCHEMA, Config, load_config  # noqa: E402

# The lane split. Infrastructure owns the syscalls; domain owns the logic.
DOMAIN = ("caddy.py", "codeserver.py", "node.py", "preflight.py", "prompter.py",
          "registry.py", "secrets.py", "sysd.py", "transport.py", "users.py")
FORBIDDEN_IMPORTS = {"subprocess", "os", "sys", "shutil", "tempfile", "socket",
                     "urllib", "http", "ctypes", "pty", "io", "curses"}
FORBIDDEN_CALLS = {"print", "input", "open", "exec", "eval"}


def _parse(name: str) -> ast.AST:
    return ast.parse((PKG / name).read_text(), filename=name)


def _all_modules() -> list[str]:
    """Package-relative names, RECURSIVE — a subpackage (tui/) must not
    silently escape the AST net the flat glob used to cast."""
    return sorted(str(p.relative_to(PKG)) for p in PKG.rglob("*.py"))


def _imports_of(name: str) -> set[str]:
    """Top-level root names this module imports (any nesting depth in the
    file, absolute imports only; relative imports return the target name)."""
    roots: set[str] = set()
    for node in ast.walk(_parse(name)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                roots.add((node.module or "").split(".")[0])
            else:
                # relative: `from . import x, y` / `from .mod import z`
                if node.module:
                    roots.add(node.module.split(".")[0])
                else:
                    for alias in node.names:
                        roots.add(alias.name.split(".")[0])
    return roots


class TestI1ImportBoundary(unittest.TestCase):
    """Name-based AST checking, not soundness — the same honestly-stated
    ceiling the bash greps had; the semantic backstop is TestI2."""

    def test_domain_modules_import_no_system_apis(self) -> None:
        for name in DOMAIN:
            for node in ast.walk(_parse(name)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        self.assertNotIn(root, FORBIDDEN_IMPORTS,
                                         f"{name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    root = (node.module or "").split(".")[0]
                    self.assertNotIn(root, FORBIDDEN_IMPORTS,
                                     f"{name} imports from {node.module}")

    def test_domain_modules_call_no_io_builtins(self) -> None:
        for name in DOMAIN:
            for node in ast.walk(_parse(name)):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                    self.assertNotIn(node.func.id, FORBIDDEN_CALLS,
                                     f"{name} calls {node.func.id}()")

    def test_dry_run_read_census(self) -> None:
        """The honest residue: sites in DOMAIN that still read executor
        dry-run state directly (secret paths and the missing-user home
        placeholder). Pinned by exact count + location so any new read is a
        deliberate edit here, not silent accretion — the Python descendant of
        the bash ALLOWLIST census, shrunk from ~15 tagged sites."""
        sites: list[str] = []
        for name in DOMAIN:
            for node in ast.walk(_parse(name)):
                if isinstance(node, ast.Attribute) and node.attr == "dry_run":
                    sites.append(name)
        # The sanctioned residue, in full: codeserver ×2 (version resolve must
        # not reach the network in a preview; upgrade's presence gate),
        # preflight ×5 (the warn-instead-of-die policy, one per gate), secrets
        # ×1 (the missing-user home placeholder), sysd ×1 (the converge-time
        # "a restart is owed" warning: under --dry-run the template was NOT
        # rewritten, so no restart is owed, and a preview that prints an action
        # item the operator cannot act on teaches them the preview says things
        # which are not true — the same argument MSG_PROXY_RESTART_PENDING's
        # site already makes). Down from ~15 bash tags.
        self.assertEqual(sorted(sites),
                         ["codeserver.py", "codeserver.py",
                          "preflight.py", "preflight.py", "preflight.py",
                          "preflight.py", "preflight.py", "secrets.py",
                          "sysd.py"],
                         f"dry_run read census changed: {sites} — a new direct read "
                         "must be argued here, not slipped in")


class TestI10OneReaderForTheFleetPins(unittest.TestCase):
    """The proxy port and the OIDC issuer are FLEET decisions, recorded in
    fleet.env at the first SSO install; `cfg` carries only what `.env` says on
    THIS run. Two readers of one value is how proxy.toml and the auth block the
    operator pasted came to name different ports — with Caddy's authz hop on the
    wrong side of the difference, where any local account can bind the port and
    answer 202 for every instance on the box.

    A census, not a ban, in the shape of the dry_run one above: a new reader is
    a deliberate edit HERE with a reason, rather than a helper someone forgot.
    This exists because the fix that introduced sso.fleet_port shipped with a
    comment claiming this test already existed. It did not."""

    ROWS = ("sso_proxy_port", "sso_issuer_url")

    def test_the_fleet_rows_are_read_in_one_place(self) -> None:
        sites: list[str] = []
        for name in _all_modules():
            for node in ast.walk(_parse(name)):
                if isinstance(node, ast.Attribute) and node.attr in self.ROWS:
                    sites.append(name)
        # The sanctioned residue, in full:
        #   install_flow ×1 — the operator's own input, shape-checked in resolve
        #     before any mutation. The one legitimate read of what .env says now.
        #   oauth2proxy ×2 — the backfill for a fleet provisioned before the pins
        #     existed. It is the RECORDING path, and it is the weakest of the
        #     three: it takes .env's values rather than the running proxy.toml's,
        #     so a box whose .env drifted since its install gets that drift
        #     pinned. Recorded as a known gap, not as a design.
        #   sso ×4 — fleet_port and fleet_issuer's fallbacks (first install, when
        #     there is nothing recorded yet), and persist_parent_domain's two.
        self.assertEqual(
            sorted(sites),
            ["install_flow.py", "oauth2proxy.py", "oauth2proxy.py",
             "sso.py", "sso.py", "sso.py", "sso.py"],
            f"fleet-pin read census changed: {sites} — a renderer or probe that "
            "reads .env directly desynchronises from proxy.toml, and the authz "
            "hop is on the losing side. Route it through sso.fleet_port / "
            "sso.fleet_issuer, or argue the exception here")


class TestI11HostStateIsReadInOnePlace(unittest.TestCase):
    """`systemctl` and `getent` READS belong in system.py, named.

    Not style. An inline `system.query(["systemctl", "is-active", …])` inside a
    domain module is a live-host read no test can stub, so the row that covers
    that code becomes a property of the machine running the tier rather than of
    this tree — and once `prove-teeth.sh` began requiring its named test to be
    green on the pristine tree, such a row stopped merely proving nothing and
    began hard-failing anywhere the daemon was absent. The recorded suite counts
    were, for a while, true only on a box that happened to host a live proxy.

    Mutations (`ex.run([...])`) are NOT covered here: they go through the
    Executor, which the doubles already record, and the dry-run censuses above
    own that axis."""

    TOOLS = ("systemctl", "getent")

    def test_systemd_and_identity_reads_live_in_system_py(self) -> None:
        sites: list[str] = []
        for name in _all_modules():
            if name == "system.py":
                continue
            for node in ast.walk(_parse(name)):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("query", "query_as")):
                    continue
                for arg in node.args:
                    if not isinstance(arg, (ast.List, ast.Tuple)) or not arg.elts:
                        continue
                    first = arg.elts[0]
                    if (isinstance(first, ast.Constant)
                            and first.value in self.TOOLS):
                        sites.append(f"{name}:{first.value}")
        # The sanctioned residue, in full:
        #   registry.py ×1 — the instance registry IS the systemd enumeration.
        #     Naming it in system.py would move the module's subject matter.
        #
        # cli.py's two sites are GONE as of the socket-freeze round. They were
        # sanctioned on the argument that they read per-instance state "for
        # display only", which stopped being true the moment doctor's liveness
        # verdict depended on the word: a fault decision taken from an unstubbable
        # read is exactly the coupling this census exists to refuse. Both now go
        # through system.unit_state. The lesson generalises — "display only" is a
        # property of today's caller, not of the read.
        #
        # BLIND SPOT, stated rather than left for someone to discover: this walks
        # LITERAL argv, so registry.py's two enumeration reads — which loop over
        # a tuple of argv lists and call query(argv) with a variable — are
        # invisible here, as is any read assembled at runtime. The census is a
        # tripwire on the easy way to reintroduce the coupling, not a proof that
        # no host read exists. It measured three sites where this comment first
        # claimed five, which is the useful direction for that error to run.
        self.assertEqual(
            sorted(sites),
            ["registry.py:systemctl"],
            f"host-read census changed: {sites} — a systemctl/getent READ in a "
            "domain module is a live-host dependency the unit tier cannot stub. "
            "Name it in system.py (unit_is_active, unit_is_failed, "
            "unit_enable_state, unit_main_pid, group_exists, group_entry), or "
            "argue the exception here")


class TestI12EveryHostReadDoctorMakesHasADouble(unittest.TestCase):
    """I11 says a host read must be NAMED in system.py. This says the named read
    must also be ANSWERABLE by the unit tier's double.

    They are different failures and the second one is quieter. `proxy_health`
    grew four new system readers in one round — listening_ports, the holder
    reader, unit_listen_streams, unit_n_restarts — every one of them correctly
    named in system.py, and `fakes.bare_host` grew none. So four unit classes
    shelled out to `ss` and `systemctl` on the machine running the tier while
    reading as perfectly hermetic, and their verdicts were properties of that
    machine. That has now happened three times (path_is_denied,
    proc_no_new_privs, and these four), which makes it structure rather than an
    oversight.

    Two functions, because they are the two that decide: doctor's verdict and
    whether the fleet's sole authorization gate restarts. Naming them here also
    makes a rename loud — _func raises rather than passing over an empty walk.

    BLIND SPOT, stated rather than left for someone to discover, in I11's idiom:
    this walks TWO FUNCTIONS, not two call graphs. A reader added inside
    _reservation_rows, _verify_proxy_came_back, install_proxy_socket_unit or
    _proxy_pings — all reachable from these two — is invisible here. There is no
    violation today (every reachable call is already a seam), and the walk is
    deliberately shallow rather than transitive because a transitive one would
    have to decide what counts as "reached" through the local imports this
    module uses. It is a tripwire on the easy way to reintroduce the coupling,
    not a proof that no host read exists.

    NO MUTATION ROW CAN COVER THIS CLASS: `prove` mutates src/ and `prove_unit`
    mutates units/; nothing in prove-teeth mutates tests/. The non-empty
    self-check below is its substitute, and it is not decoration — a census
    whose subject was renamed passes with zero sites, and this tree has already
    shipped exactly that once."""

    SUBJECTS = ("proxy_health", "upgrade_sso")

    def test_every_system_read_on_the_decision_paths_is_a_named_seam(self) -> None:
        from fakes import HOST_SEAMS
        found: list[str] = []
        for fn in self.SUBJECTS:
            for sub in ast.walk(_func("oauth2proxy.py", fn)):
                if (isinstance(sub, ast.Call)
                        and isinstance(sub.func, ast.Attribute)
                        and isinstance(sub.func.value, ast.Name)
                        and sub.func.value.id == "system"):
                    found.append(f"{fn}:{sub.func.attr}")
        # The anti-vacuity self-check, in the shape test_harness_guards uses:
        # if both subjects were renamed this walk would find nothing and every
        # assertion below would hold over the empty set.
        self.assertGreater(len(found), 0,
                           "this census has stopped looking at anything — "
                           f"neither of {self.SUBJECTS} makes a system.* call")
        missing = sorted({s for s in found if s.split(":", 1)[1] not in HOST_SEAMS})
        self.assertEqual(
            missing, [],
            f"a system reader on a decision path has no double: {missing}. Add "
            "it to fakes.HOST_SEAMS with the bare box's answer beside it — "
            "without one, every test that reaches this line reads the machine "
            "running the tier and its green is a property of that machine")


class TestI2DryRunMutatesNothing(unittest.TestCase):
    def test_full_install_sequence_leaves_no_trace(self) -> None:
        import tempfile
        from vide.confirm import Confirmer
        from vide.executor import Executor
        from vide.install_flow import run_install
        from vide.reporter import Reporter
        from fakes import make_config

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "sandbox").mkdir()
            osr = tmp / "os-release"
            osr.write_text('ID=debian\nPRETTY_NAME="Debian test"\n')
            # A deliberately nonexistent target: hermetic under ANY invoking
            # uid (root in a container has no $USER and must not steer the
            # sequence into the root-instance challenge). The dry-run path
            # for a missing user is exactly the bash preview behavior: warn,
            # keep previewing.
            cfg = make_config(tmp / "sandbox", dry_run=True,
                              os_release_file=osr, uname_m="x86_64",
                              vide_user="vide-i2-sandbox-user")
            errs = io.StringIO()
            rep = Reporter(stream=errs)
            ex = Executor(dry_run=True, reporter=rep, cfg=cfg)
            conf = Confirmer(yes_argv=False, environ={}, reporter=rep)

            def snapshot() -> list[tuple[str, int]]:
                out = []
                for p in sorted((tmp / "sandbox").rglob("*")):
                    out.append((str(p), p.stat().st_mode))
                return out

            before = snapshot()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = run_install(cfg, ex, rep, conf)
            self.assertEqual(rc, 0)
            self.assertEqual(before, snapshot(),
                             "a dry-run converge wrote into the sandbox")
            # Anti-vacuous: the preview must actually narrate mutations.
            self.assertIn("[dry-run]", errs.getvalue())
            # ...and the machine channel carries the snippet and NOTHING else
            # (stdout purity: `install.sh > snippet.conf` must stay clean —
            # the parity diff caught the bootstrap shim violating this once).
            stdout = out.getvalue()
            self.assertIn("reverse_proxy 127.0.0.1:", stdout)
            self.assertTrue(stdout.strip().startswith("# --- VIDE per-instance"),
                            f"stdout carries more than the snippet: {stdout[:120]!r}")


class TestI2VideBranchDryRunOnASudolessBox(unittest.TestCase):
    def test_vide_fallback_preview_survives_a_missing_sudo_package(self) -> None:
        """The smoke §1 box, hermetically: minimal images have no sudo
        package (visudo absent), and the pre-fix preview DIED there at
        install_sudoers. The I2 test above deliberately dodges the vide
        branch (sandbox user); this sibling walks it with the visudo seam
        mocked ABSENT — rc 0, nothing mutated, the ensure-sudo step and the
        deferred validation both narrated."""
        import tempfile
        from unittest import mock
        from vide import install_flow, users
        from vide.confirm import Confirmer
        from vide.executor import Executor
        from vide.reporter import Reporter
        from fakes import make_config

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "sandbox").mkdir()
            osr = tmp / "os-release"
            osr.write_text('ID=debian\nPRETTY_NAME="Debian test"\n')
            cfg = make_config(tmp / "sandbox", dry_run=True,
                              os_release_file=osr, uname_m="x86_64",
                              vide_user="vide")
            errs = io.StringIO()
            rep = Reporter(stream=errs)
            ex = Executor(dry_run=True, reporter=rep, cfg=cfg)
            conf = Confirmer(yes_argv=False, environ={}, reporter=rep)
            before = sorted(str(p) for p in (tmp / "sandbox").rglob("*"))
            # one patch covers both callers: install_flow.system IS
            # users.system (the same module object); visudo_cmd None alone
            # routes ensure_sudo into the install (its `and` short-circuits)
            # without distorting every other have_cmd probe
            with mock.patch.object(users.system, "visudo_cmd",
                                   return_value=None), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = install_flow.run_install(cfg, ex, rep, conf)
            self.assertEqual(rc, 0, "the preview died on a sudo-less box")
            self.assertEqual(before,
                             sorted(str(p) for p in (tmp / "sandbox").rglob("*")))
            log = errs.getvalue()
            self.assertIn("[dry-run] apt-get install -y sudo", log)
            self.assertIn("[dry-run] validate sudoers drop-in", log)


class TestI3StreamSplit(unittest.TestCase):
    def test_no_print_or_stdout_outside_sanctioned_modules(self) -> None:
        # tui/session.py joins the set for exactly one job: the post-endwin
        # replay + deferred secret/snippet delivery to the REAL stdio.
        sanctioned = {"cli.py", "install_flow.py", "reporter.py", "__main__.py",
                      "tui/session.py"}
        for name in _all_modules():
            if name in sanctioned:
                continue
            for node in ast.walk(_parse(name)):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotEqual(node.func.id, "print", f"{name} calls print()")
                if isinstance(node, ast.Attribute) and node.attr == "stdout":
                    if isinstance(node.value, ast.Name) and node.value.id == "sys":
                        self.fail(f"{name} touches sys.stdout")


class TestI4SingleEmitter(unittest.TestCase):
    def test_emit_shape_occurs_once_in_package(self) -> None:
        hits = []
        for py in PKG.glob("*.py"):
            if 'hashed-password: "' in py.read_text():
                hits.append(py.name)
        self.assertEqual(hits, ["secrets.py"])

    def test_ensure_and_rotate_share_the_emitter_body(self) -> None:
        import tempfile
        from unittest import mock
        from fakes import RecordingExecutor, make_config, quiet_reporter
        from vide import secrets as vs

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_config(tmp)
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "alice.env").write_text("VIDE_PORT=9797\n")
            fixed = {"gen_password": lambda: "PW",
                     "hash_password": lambda p: "$argon2id$HASH",
                     "gen_cookie_suffix": lambda u: "vide-alice-abc123"}
            bodies = []
            for entry in ("ensure", "rotate"):
                ex = RecordingExecutor()
                with mock.patch.multiple(vs, **{k: mock.Mock(side_effect=v)
                                                for k, v in fixed.items()}), \
                     mock.patch.object(vs.system, "probe_as", return_value=False), \
                     mock.patch.object(vs.system, "user_home",
                                       return_value=tmp / "home/alice"):
                    if entry == "ensure":
                        vs.ensure_config(cfg, ex, quiet_reporter(), "alice", 9797)
                    else:
                        vs.rotate_config(cfg, ex, quiet_reporter(), "alice")
                body = [c for k, c in ex.contents.items() if k.endswith("config.yaml")]
                self.assertEqual(len(body), 1, f"{entry} wrote {len(body)} configs")
                bodies.append(body[0])
            self.assertEqual(bodies[0], bodies[1],
                             "ensure_config and rotate_config diverged — the single "
                             "emitter has been forked")
            for field in ("bind-addr: 127.0.0.1:9797", "auth: password",
                          'hashed-password: "$argon2id$HASH"',
                          "cookie-suffix: vide-alice-abc123", "cert: false"):
                self.assertIn(field, bodies[0])


class TestI5DryRunBanner(unittest.TestCase):
    def test_inherited_dry_run_is_never_silent(self) -> None:
        # Hermetic: registry/toolchain queries are stubbed so this never
        # touches the live host's systemctl or /etc/vide (review r1 finding).
        import tempfile
        from unittest import mock
        from vide import cli
        buf = io.StringIO()
        env_backup = os.environ.get("VIDE_DRY_RUN")
        os.environ["VIDE_DRY_RUN"] = "1"
        try:
            with tempfile.TemporaryDirectory() as td, \
                 mock.patch.object(cli.registry, "list_instances", return_value=[]), \
                 mock.patch.object(cli.node, "toolchain_status_line",
                                   return_value="HEALTHY (stub)"), \
                 contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(buf):
                cli.main(["ls"], Path(td))
        finally:
            if env_backup is None:
                os.environ.pop("VIDE_DRY_RUN", None)
            else:
                os.environ["VIDE_DRY_RUN"] = env_backup
        self.assertIn("DRY-RUN MODE ACTIVE", buf.getvalue())


class TestI6ConfigCarriesNoControl(unittest.TestCase):
    def test_schema_has_no_control_lever(self) -> None:
        for s in SCHEMA:
            for token in ("YES", "ASSUME", "CONFIRM"):
                self.assertNotIn(token, s.env,
                                 f"{s.env}: control levers may not enter the config schema")

    def test_config_has_no_yes_attribute(self) -> None:
        self.assertNotIn("yes", Config.__slots__)
        self.assertNotIn("assume_yes", Config.__slots__)
        self.assertNotIn("confirm_root", Config.__slots__)

    def test_schema_carries_no_secret(self) -> None:
        # Secrets are neither config nor control — they are stdin/wizard-field
        # only. A VIDE_SSO_CLIENT_SECRET in .env (0644, world-readable) would be
        # a leak; the client_id is public but pinned out too to keep the rule
        # blunt and mechanical.
        for s in SCHEMA:
            low = s.field.lower()
            self.assertNotIn("secret", low, f"{s.field}: secrets are never a Setting")
            self.assertNotIn("client", low, f"{s.field}: client creds are never a Setting")

    def test_loader_ignores_assume_yes_env(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cfg = load_config(Path(td), environ={"VIDE_ASSUME_YES": "1", "VIDE_YES": "1"})
            self.assertFalse(hasattr(cfg, "yes"))

    def test_package_never_reads_assume_yes(self) -> None:
        for py in PKG.glob("*.py"):
            self.assertNotIn("VIDE_ASSUME_YES", py.read_text(),
                             f"{py.name} references the deleted env waiver")


class TestI7CursesConfinement(unittest.TestCase):
    """The TUI boundary, both directions. Same honest name-based-AST ceiling
    as I1; the behavioral backstop is the curses-masked import test in
    test_tui_gate.py."""

    def test_curses_imported_only_under_tui(self) -> None:
        for name in _all_modules():
            if name.startswith("tui/"):
                continue
            self.assertNotIn("curses", _imports_of(name),
                             f"{name} imports curses outside tui/")

    def test_tui_package_gate_has_no_toplevel_curses(self) -> None:
        """tui/__init__.py is imported to DECIDE whether curses is usable, so
        it may only import curses inside a function (guarded); the sibling
        modules load only after the probe passed."""
        init = "tui/__init__.py"
        if not (PKG / init).exists():
            return  # pre-tui tree: vacuously green, armed the moment it lands
        for node in ast.iter_child_nodes(_parse(init)):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                         else [node.module or ""])
                for n in names:
                    self.assertNotEqual(n.split(".")[0], "curses",
                                        "tui/__init__.py imports curses at module level")

    def test_tui_imports_no_domain_and_no_executor(self) -> None:
        """The wizard is presentation: it renders questions and relays
        answers. Mutation capability (Executor), domain logic, and Config all
        stay on the other side of the Prompter port."""
        allowed_vide = {"errors", "prompter"}
        for name in _all_modules():
            if not name.startswith("tui/"):
                continue
            for root in _imports_of(name):
                self.assertNotEqual(root, "vide",
                                    f"{name}: use relative imports inside the "
                                    "package (keeps this scan honest)")
                if root == "tui" or (PKG / "tui" / f"{root}.py").exists():
                    continue  # intra-package
                if (PKG / f"{root}.py").exists():
                    self.assertIn(root, allowed_vide,
                                  f"{name} imports vide.{root} — tui/ may only "
                                  "import errors + prompter")


def _func(name: str, func: str) -> ast.FunctionDef:
    for node in ast.walk(_parse(name)):
        if isinstance(node, ast.FunctionDef) and node.name == func:
            return node
    raise AssertionError(f"{func} not found in {name}")


def _asker_askpoints() -> set[str]:
    """The ask-point method names declared on the Asker Protocol — the single
    enumerable registry the drift check reads."""
    cls = next(n for n in ast.walk(_parse("prompter.py"))
               if isinstance(n, ast.ClassDef) and n.name == "Asker")
    return {n.name for n in cls.body
            if isinstance(n, ast.FunctionDef)} - {"can_reask"}


class TestI8ResolveCannotMutate(unittest.TestCase):
    """I8: the plan phase is structurally denied an Executor. resolve_plan and
    _resolve_sso take no `ex` parameter and never touch `ex.`, so a refusal
    there (a missing required flag) provably cannot have mutated the host first.
    The behavioural backstop is test_no_mutation_before_ask (ex.actions == [])."""

    def test_resolve_functions_have_no_executor(self) -> None:
        for fn in ("resolve_plan", "_resolve_sso"):
            node = _func("install_flow.py", fn)
            args = node.args.args + node.args.kwonlyargs
            self.assertNotIn("ex", [a.arg for a in args],
                             f"{fn} takes an `ex` parameter — resolve must not mutate")
            for a in args:
                if isinstance(a.annotation, ast.Name):
                    self.assertNotEqual(a.annotation.id, "Executor",
                                        f"{fn}({a.arg}) is annotated Executor")
            for sub in ast.walk(node):
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                    self.assertNotEqual(sub.value.id, "ex",
                                        f"{fn} accesses ex.{sub.attr} — resolve must not mutate")


class TestI9ApplyCannotAsk(unittest.TestCase):
    """I9: the apply phase solicits nothing — no Asker ask-point is CALLED in
    apply_plan/_apply_sso. This is what keeps a future ask-point from drifting
    back below the mutation boundary (the exact defect this slice fixes). Checks
    Call nodes only: `plan.sso_credentials`/`plan.whitelist_email` are plan
    fields that legitimately share a name with an ask-point but are never called."""

    def test_apply_functions_call_no_askpoint(self) -> None:
        askpoints = _asker_askpoints()
        self.assertIn("choose_fqdn", askpoints)   # the set is non-empty
        for fn in ("apply_plan", "_apply_sso"):
            node = _func("install_flow.py", fn)
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    self.assertNotIn(sub.func.attr, askpoints,
                                     f"{fn} calls the ask-point .{sub.func.attr}() — "
                                     "apply must not solicit")

    def test_cli_imports_tui_lazily(self) -> None:
        """The plain path (and the frozen arbiter's whole world) must work on
        a box whose Python lacks _curses: only a function-level import inside
        the gated branch may pull the subpackage in."""
        for node in ast.iter_child_nodes(_parse("cli.py")):
            if isinstance(node, ast.ImportFrom):
                self.assertNotEqual((node.module or ""), "tui",
                                    "cli.py imports tui at module level")
                if node.module is None:
                    for alias in node.names:
                        self.assertNotEqual(alias.name, "tui",
                                            "cli.py imports tui at module level")

    def test_install_flow_never_imports_tui(self) -> None:
        self.assertNotIn("tui", _imports_of("install_flow.py"),
                         "the sequencer must keep working where the wizard "
                         "cannot open — install_flow may not know tui exists")


class TestEntrypointPathScrub(unittest.TestCase):
    def test_main_scrubs_package_dir_off_sys_path(self) -> None:
        """Direct-file execution puts src/vide/ itself on sys.path, where
        `import secrets` resolves to vide/secrets.py and shadows the stdlib.
        The scrub in __main__.py is load-bearing; this pins it."""
        text = (PKG / "__main__.py").read_text()
        self.assertIn("sys.path[:]", text)
        self.assertIn("resolve()", text)


if __name__ == "__main__":
    unittest.main()
