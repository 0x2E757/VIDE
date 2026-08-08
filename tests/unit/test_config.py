"""Config resolution: precedence, empty-falls-through, derived URLs, parser."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from vide.config import load_config, parse_env_file  # noqa: E402
from vide.errors import ConfigError  # noqa: E402


class TestABadNumberIsASentenceNotATraceback(unittest.TestCase):
    """Eight `.env` rows cast with a bare int/float, and ValueError was mapped to
    nothing — so one typo did not produce a refusal naming the row, it produced a
    Python traceback out of EVERY verb, on the exit code of an unhandled exception
    rather than the one the contract promises for a config error.

    `vide doctor --quiet` is the documented cron hook, so that typo converted the
    box's monitoring into a stack trace mailed on every cycle."""

    def _load(self, **kw):
        with tempfile.TemporaryDirectory() as td:
            return load_config(Path(td), **kw)

    def test_a_typo_names_the_row_and_where_it_came_from(self) -> None:
        for src, kw in (("the environment", {"environ": {"VIDE_PORT_BASE": "97 97"}}),
                        ("the command line", {"argv_env": {"VIDE_PORT_BASE": "97 97"},
                                              "environ": {}})):
            with self.subTest(src=src), self.assertRaises(ConfigError) as cm:
                self._load(**kw)
            msg = str(cm.exception)
            self.assertIn("VIDE_PORT_BASE", msg)
            self.assertIn(src, msg)
            # …and NEVER the value: `.env` also holds the installer URLs, and a
            # config error must not become a way to get a neighbouring secret
            # printed into a log by mistyping the key next to it.
            self.assertNotIn("97 97", msg)

    def test_a_dotenv_typo_says_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".env").write_text("VIDE_DL_RETRY_DELAY=soon\n")
            with self.assertRaises(ConfigError) as cm:
                load_config(Path(td), environ={})
        self.assertIn(".env", str(cm.exception))
        self.assertIn("VIDE_DL_RETRY_DELAY", str(cm.exception))

    def test_a_good_value_still_resolves(self) -> None:
        # The opposite sign: a guard that refuses everything and one that refuses
        # nothing are the same defect.
        self.assertEqual(9100, self._load(environ={"VIDE_PORT_BASE": "9100"}).port_base)


class TestPrecedence(unittest.TestCase):
    def _load(self, *, argv=None, env=None, dotenv=""):
        self.td = tempfile.TemporaryDirectory()
        repo = Path(self.td.name)
        if dotenv:
            (repo / ".env").write_text(dotenv)
        return load_config(repo, argv_env=argv, environ=env or {})

    def test_default_when_nothing_set(self) -> None:
        self.assertEqual(self._load().port_base, 9797)

    def test_dotenv_beats_default(self) -> None:
        self.assertEqual(self._load(dotenv="VIDE_PORT_BASE=9000\n").port_base, 9000)

    def test_env_beats_dotenv(self) -> None:
        cfg = self._load(env={"VIDE_PORT_BASE": "9100"}, dotenv="VIDE_PORT_BASE=9000\n")
        self.assertEqual(cfg.port_base, 9100)

    def test_argv_beats_env(self) -> None:
        cfg = self._load(argv={"VIDE_PORT_BASE": "9200"}, env={"VIDE_PORT_BASE": "9100"})
        self.assertEqual(cfg.port_base, 9200)

    def test_empty_falls_through_like_bash_colon_equals(self) -> None:
        # bash `: "${VIDE_X:=default}"` treats empty as unset; `VIDE_USER=`
        # behaves as unset via [[ -n ]].
        cfg = self._load(env={"VIDE_PORT_BASE": ""}, dotenv="VIDE_PORT_BASE=9000\n")
        self.assertEqual(cfg.port_base, 9000)

    def test_immutable(self) -> None:
        cfg = self._load()
        with self.assertRaises(AttributeError):
            cfg.port_base = 1  # type: ignore[misc]


class TestDotenvInjection(unittest.TestCase):
    """The environ=None path injects `.env` rows into os.environ so children
    inherit them (an operator's https_proxy must reach urllib). Two pins:
    the mechanism works, and it NEVER carries the ROOT waiver — the Confirmer
    reads VIDE_CONFIRM_ROOT from os.environ, so injecting that row would let
    a persisted `.env` line waive the typed-ROOT ceremony for every future
    run (the documented process-env-only invariant, module docstring)."""

    def _load_with_real_environ(self, dotenv: str):
        import os
        from unittest import mock
        with tempfile.TemporaryDirectory() as t:
            repo = Path(t)
            (repo / ".env").write_text(dotenv)
            with mock.patch.dict(os.environ, {}, clear=False):
                for k in ("VIDE_CONFIRM_ROOT", "VIDE_TEST_INJECTED"):
                    os.environ.pop(k, None)
                load_config(repo)  # environ=None -> the injection path
                return {k: os.environ.get(k)
                        for k in ("VIDE_CONFIRM_ROOT", "VIDE_TEST_INJECTED")}

    def test_dotenv_rows_reach_children_via_environ(self) -> None:
        got = self._load_with_real_environ("VIDE_TEST_INJECTED=yes\n")
        self.assertEqual(got["VIDE_TEST_INJECTED"], "yes")

    def test_the_root_waiver_is_never_injected(self) -> None:
        got = self._load_with_real_environ(
            "VIDE_TEST_INJECTED=yes\nVIDE_CONFIRM_ROOT=ROOT\n")
        self.assertIsNone(got["VIDE_CONFIRM_ROOT"],
                          "a persisted .env row would waive the typed-ROOT "
                          "ceremony for every future run on the box")
        self.assertEqual(got["VIDE_TEST_INJECTED"], "yes",
                         "the injection mechanism itself must survive")


class TestAnnotationsMatchSchema(unittest.TestCase):
    def test_static_annotations_cannot_drift_from_the_schema(self) -> None:
        """Config's annotation block exists for static checkers only; the
        schema stays the single source of values. This pin is what keeps the
        two from drifting — add a Setting, forget the annotation (or vice
        versa), and this goes red."""
        from vide.config import SCHEMA, Config
        annotated = set(Config.__annotations__)
        schema_fields = {s.field for s in SCHEMA} | {"repo_dir"}
        self.assertEqual(annotated, schema_fields)


class TestDerivedUrls(unittest.TestCase):
    def test_nvm_url_interpolates_resolved_version(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = load_config(Path(td), environ={"VIDE_NVM_VERSION": "v9.9.9"})
            self.assertIn("/v9.9.9/", cfg.nvm_installer_url)

    def test_explicit_nvm_url_wins_over_derivation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = load_config(Path(td), environ={
                "VIDE_NVM_INSTALLER_URL": "https://mirror.example/nvm.sh",
                "VIDE_NVM_VERSION": "v9.9.9"})
            self.assertEqual(cfg.nvm_installer_url, "https://mirror.example/nvm.sh")

    def test_dl_tunables(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = load_config(Path(td), environ={"VIDE_DL_RETRIES": "5"})
            self.assertEqual(cfg.dl_retries, 5)
            self.assertEqual(cfg.dl_retry_delay, 2.0)  # default intact


class TestEnvFileParser(unittest.TestCase):
    def test_parser_tolerates_the_usual_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text(
                "# comment\n"
                "\n"
                "VIDE_USER=alice\n"
                "export VIDE_FQDN=v.example.com\n"
                'VIDE_NVM_VERSION="v1.2.3"\n'
                "BROKEN LINE NO EQUALS\n"
                "VIDE_PORT_BASE='9000'\n")
            parsed = parse_env_file(p)
            self.assertEqual(parsed["VIDE_USER"], "alice")
            self.assertEqual(parsed["VIDE_FQDN"], "v.example.com")
            self.assertEqual(parsed["VIDE_NVM_VERSION"], "v1.2.3")
            self.assertEqual(parsed["VIDE_PORT_BASE"], "9000")
            self.assertNotIn("BROKEN LINE NO EQUALS", parsed)

    def test_missing_file_is_empty(self) -> None:
        self.assertEqual(parse_env_file(Path("/nonexistent/.env")), {})

    def test_no_shell_expansion(self) -> None:
        # Documented divergence: the parser is not a shell.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text("VIDE_USER=$SUDO_USER\n")
            self.assertEqual(parse_env_file(p)["VIDE_USER"], "$SUDO_USER")


if __name__ == "__main__":
    unittest.main()
