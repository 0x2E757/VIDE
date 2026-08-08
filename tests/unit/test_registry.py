"""Registry: the template-unit regression (the bug that silently disabled
doctor's user-view check) and system-derived enumeration."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import make_config  # noqa: E402
from vide import registry  # noqa: E402

# The trap: the 'code-server@*.service' glob ALSO matches the bare template.
UNIT_FILES = ("code-server@.service                        enabled enabled\n"
              "code-server@alice.service                   enabled enabled\n")
UNITS_ALL = ("  code-server@alice.service loaded active running code-server for alice\n"
             "● code-server@bob.service   loaded failed failed  code-server for bob\n")


def _fake_query(argv, **kw):
    out = ""
    if "list-unit-files" in argv:
        out = UNIT_FILES
    elif "list-units" in argv:
        out = UNITS_ALL
    return subprocess.CompletedProcess(list(argv), 0, stdout=out, stderr="")


class TestListInstances(unittest.TestCase):
    def test_bare_template_unit_is_not_an_instance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            with mock.patch.object(registry.system, "query", side_effect=_fake_query):
                got = registry.list_instances(cfg)
        self.assertEqual(got, ["alice", "bob"])
        self.assertNotIn("", got, "an empty instance name would sort FIRST and "
                                  "feed doctor an empty user, silently skipping "
                                  "the user-view traversal check")

    def test_first_instance_is_never_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            with mock.patch.object(registry.system, "query", side_effect=_fake_query):
                got = registry.list_instances(cfg)
        self.assertTrue(got and got[0])

    def test_failed_unit_glyph_is_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            with mock.patch.object(registry.system, "query", side_effect=_fake_query):
                self.assertIn("bob", registry.list_instances(cfg))

    def test_state_dir_records_merge_in(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "carol.env").write_text("VIDE_PORT=9900\n")
            with mock.patch.object(registry.system, "query", side_effect=_fake_query):
                got = registry.list_instances(cfg)
        self.assertEqual(got, ["alice", "bob", "carol"])

    def test_systemctl_failure_degrades_to_state_dir_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = make_config(Path(td))
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "dora.env").write_text("VIDE_PORT=9901\n")
            fail = subprocess.CompletedProcess([], 1, stdout="", stderr="no systemd")
            with mock.patch.object(registry.system, "query", return_value=fail):
                self.assertEqual(registry.list_instances(cfg), ["dora"])


if __name__ == "__main__":
    unittest.main()
