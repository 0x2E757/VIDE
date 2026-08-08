"""Golden pins for every arbiter-grepped literal. The arbiter's greps and seds
are byte-anchored; these tests exist so a "cleaner" rewording fails HERE, in
milliseconds, instead of twenty minutes into a container run looking like an
authentication failure.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from vide import contract  # noqa: E402
from vide.errors import Ex  # noqa: E402


class TestPasswordLines(unittest.TestCase):
    """in-container.sh captures with grep -F 'SHOWN ONCE' | sed 's/.*): //p'
    and redacts with s/\\(SHOWN ONCE[^)]*)\\): .*/ — so each line must carry
    'SHOWN ONCE' inside a parenthetical, then '): ', then the bare password
    ending the line."""

    ARBITER_CAPTURE = re.compile(r"SHOWN ONCE[^)]*\): (.+)$")

    def _check(self, template: str) -> None:
        line = template.format(user="alice", pw="sEcReT+b64/pw==")
        m = self.ARBITER_CAPTURE.search(line)
        self.assertIsNotNone(m, f"arbiter capture regex misses: {line!r}")
        self.assertEqual(m.group(1), "sEcReT+b64/pw==",
                         "the password must be the LAST thing on the line")

    def test_install_password_line(self) -> None:
        self._check(contract.MSG_PASSWORD)
        self.assertEqual(
            contract.MSG_PASSWORD,
            "code-server password for '{user}' (SHOWN ONCE, only the hash is stored): {pw}")

    def test_rotate_password_line(self) -> None:
        self._check(contract.MSG_PASSWORD_ROTATED)
        self.assertEqual(contract.MSG_PASSWORD_ROTATED,
                         "NEW code-server password for '{user}' (SHOWN ONCE): {pw}")

    def test_login_password_line(self) -> None:
        self._check(contract.MSG_LOGIN_PASSWORD)


class TestOtherContracts(unittest.TestCase):
    def test_port_record_shape(self) -> None:
        # in-container.sh: sed -n 's/^VIDE_PORT=//p'; the unit reads it back
        # after a rollback flip — the shape is shared state.
        self.assertEqual(contract.PORT_RECORD.format(port=9797), "VIDE_PORT=9797\n")

    def test_doctor_perm_line(self) -> None:
        line = contract.MSG_USER_VIEW_PERM.format(user="ittest")
        self.assertIn("PERM", line)  # the arbiter's literal grep token
        self.assertEqual(
            line, "  user-view (ittest): PERM — node NOT resolvable by user (traversal?)")

    def test_cookie_suffix_prefix(self) -> None:
        s = contract.COOKIE_SUFFIX.format(user="ittest", rand="a1b2c3")
        self.assertTrue(s.startswith("vide-ittest-"))

    def test_snippet_proxy_line(self) -> None:
        self.assertEqual(contract.SNIPPET_PROXY_LINE.format(port=9797),
                         "reverse_proxy 127.0.0.1:9797")

    def test_exit_codes_are_the_documented_table(self) -> None:
        # The enum's VALUES are the contract (README + arbiter assert 64/69/77).
        self.assertEqual((Ex.USAGE, Ex.DATAERR, Ex.UNAVAILABLE, Ex.SOFTWARE,
                          Ex.STATE, Ex.NOPERM, Ex.CONFIG),
                         (64, 65, 69, 70, 75, 77, 78))


if __name__ == "__main__":
    unittest.main()
