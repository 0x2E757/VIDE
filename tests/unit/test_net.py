"""The download durability classifier — ported verbatim from the stubbed-curl
tests, driven through an injected fake opener. Plus the urllib-specific
hardening curl gave for free (https-only, redirect downgrade refusal)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import FakeDlConfig, FakeHTTPResponse, FakeOpener, http_error, quiet_reporter  # noqa: E402
from vide import net  # noqa: E402
from vide.errors import UnavailableError  # noqa: E402


class TestDownloadClassifier(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.dest = Path(self.td.name) / "out"
        self.cfg = FakeDlConfig()
        self.rep = quiet_reporter()

    def _dl(self, opener: FakeOpener) -> None:
        net.download("https://x.test/i.sh", self.dest, "VIDE_NVM_INSTALLER_URL",
                     cfg=self.cfg, rep=self.rep, opener=opener)

    def test_success_does_not_retry(self) -> None:
        op = FakeOpener([FakeHTTPResponse(b"#!/bin/sh\n")])
        self._dl(op)
        self.assertEqual(op.calls, 1)
        self.assertEqual(self.dest.read_bytes(), b"#!/bin/sh\n")

    def test_404_fails_fast_naming_the_override_var(self) -> None:
        op = FakeOpener([http_error(404)])
        with self.assertRaises(UnavailableError) as cm:
            self._dl(op)
        self.assertEqual(op.calls, 1, "4xx is permanent; retrying it is waste")
        self.assertIn("VIDE_NVM_INSTALLER_URL", str(cm.exception))

    def test_5xx_retries_exactly_n_then_fails(self) -> None:
        op = FakeOpener([http_error(503)] * 3)
        with self.assertRaises(UnavailableError):
            self._dl(op)
        self.assertEqual(op.calls, 3)

    def test_empty_200_body_is_transient_and_never_success(self) -> None:
        # A broken proxy can close cleanly with 200 and no payload; trusting it
        # would execute a zero-byte installer (the rc=99 integer-guard class).
        op = FakeOpener([FakeHTTPResponse(b"")] * 3)
        with self.assertRaises(UnavailableError):
            self._dl(op)
        self.assertEqual(op.calls, 3)

    def test_recovers_after_transient_and_stops(self) -> None:
        op = FakeOpener([http_error(503), FakeHTTPResponse(b"payload")])
        self._dl(op)
        self.assertEqual(op.calls, 2)
        self.assertEqual(self.dest.read_bytes(), b"payload")

    def test_408_and_429_are_transient(self) -> None:
        op = FakeOpener([http_error(429), http_error(408), FakeHTTPResponse(b"p")])
        self._dl(op)
        self.assertEqual(op.calls, 3)

    def test_refuses_non_https_url(self) -> None:
        with self.assertRaises(UnavailableError):
            net.download("http://x.test/i.sh", self.dest, None,
                         cfg=self.cfg, rep=self.rep, opener=FakeOpener([]))


class _MidStreamFailure:
    """A response that yields one chunk and then resets — the half-delivered
    body a flaky mirror or dropped connection produces."""

    def __init__(self, first: bytes = b"partial-bytes") -> None:
        self._first = first
        self._sent = False

    def read(self, n: int = -1) -> bytes:
        if not self._sent:
            self._sent = True
            return self._first
        raise ConnectionResetError("connection reset mid-body")

    def geturl(self) -> str:
        return ""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestDownloadAtomicity(unittest.TestCase):
    """A failed download must never leave a truncated file at dest: a later
    run (or an operator) would mistake it for the real artifact. The body
    streams into a .part sibling and is renamed into place only complete."""

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.dest = Path(self.td.name) / "out"
        self.cfg = FakeDlConfig()
        self.rep = quiet_reporter()

    def _dl(self, opener: FakeOpener) -> None:
        net.download("https://x.test/i.sh", self.dest, "VIDE_NVM_INSTALLER_URL",
                     cfg=self.cfg, rep=self.rep, opener=opener)

    def test_midbody_failure_leaves_nothing_at_dest(self) -> None:
        op = FakeOpener([_MidStreamFailure()] * 3)
        with self.assertRaises(UnavailableError):
            self._dl(op)
        self.assertEqual(op.calls, 3, "a reset mid-body is transient — retried")
        self.assertFalse(self.dest.exists(), "a truncated body reached dest")
        self.assertEqual(list(Path(self.td.name).iterdir()), [],
                         "the .part working file must not outlive the failure")

    def test_recovery_after_midbody_failure_delivers_the_full_body(self) -> None:
        op = FakeOpener([_MidStreamFailure(), FakeHTTPResponse(b"whole payload")])
        self._dl(op)
        self.assertEqual(self.dest.read_bytes(), b"whole payload",
                         "the retry must not inherit the aborted attempt's bytes")
        self.assertEqual([p.name for p in Path(self.td.name).iterdir()], ["out"],
                         "no .part litter after success")

    def test_empty_body_leaves_nothing_at_dest(self) -> None:
        op = FakeOpener([FakeHTTPResponse(b"")] * 3)
        with self.assertRaises(UnavailableError):
            self._dl(op)
        self.assertFalse(self.dest.exists(),
                         "a zero-byte body must never materialize at dest")
        self.assertEqual(list(Path(self.td.name).iterdir()), [])


class TestUserAgent(unittest.TestCase):
    def test_opener_never_sends_the_python_urllib_ua(self) -> None:
        # Cloudflare 403s `Python-urllib/*` on code-server.dev (verified);
        # curl never hit this because it ships its own UA.
        op = net._opener()
        uas = [v for k, v in op.addheaders if k.lower() == "user-agent"]
        self.assertEqual(len(uas), 1)
        self.assertNotIn("Python-urllib", uas[0])
        self.assertIn("vide", uas[0])


class TestRedirectDowngrade(unittest.TestCase):
    def test_https_to_http_redirect_is_refused(self) -> None:
        # curl --proto '=https' forbade this; urllib's default handler follows
        # it silently. Nothing in the arbiter tests it — this test is the only
        # thing standing between the port and a silent TLS downgrade.
        h = net._HttpsOnlyRedirect()
        with self.assertRaises(UnavailableError):
            h.redirect_request(None, None, 302, "Found", {}, "http://evil.test/x")


class TestLatestTagResolver(unittest.TestCase):
    def _resolve(self, effective_url: str) -> str:
        cfg = FakeDlConfig()
        op = FakeOpener([FakeHTTPResponse(b"", url=effective_url)])
        return net.resolve_latest_version(cfg, opener=op)

    def test_extracts_semver_from_tag_redirect(self) -> None:
        self.assertEqual(
            self._resolve("https://github.com/coder/code-server/releases/tag/v4.99.1"),
            "4.99.1")

    def test_unexpected_redirect_yields_empty_not_garbage(self) -> None:
        self.assertEqual(self._resolve("https://github.com/login"), "")

    def test_any_failure_yields_empty(self) -> None:
        # Resolution must NEVER block provisioning (durability directive).
        cfg = FakeDlConfig()
        op = FakeOpener([http_error(500)])
        self.assertEqual(net.resolve_latest_version(cfg, opener=op), "")

    def test_a_non_https_url_is_refused_before_any_request(self) -> None:
        # download() refuses http:// and this resolver used to not, while
        # docs/threat-model.md states the refusal absolutely. Both release URLs
        # are .env rows, so the gap was reachable by configuration alone.
        #
        # ASSERT ON op.calls, NOT ON THE RETURN VALUE. '' is what a 500, a
        # timeout and a garbage redirect all produce, so a row that only checked
        # the return value would pass just as well against a version that
        # fetched the URL in cleartext first and then failed.
        cfg = FakeDlConfig()
        op = FakeOpener([FakeHTTPResponse(b"", url="http://evil.test/releases/tag/v9.9.9")])
        self.assertEqual(
            net.resolve_latest_version(cfg, opener=op,
                                       url="http://evil.test/releases/latest"), "")
        self.assertEqual(op.calls, 0, "a non-https release URL was actually fetched")

    def test_the_refusal_also_covers_the_url_that_comes_from_config(self) -> None:
        # The explicit `url=` is oauth2-proxy's path; code-server's comes from
        # cfg. A guard placed after the `url or cfg...` fallback covers both, and
        # this row is what says so — the two arrive at `target` differently.
        cfg = FakeDlConfig()
        cfg.code_server_releases_latest_url = "http://evil.test/releases/latest"
        op = FakeOpener([FakeHTTPResponse(b"", url="http://evil.test/releases/tag/v9.9.9")])
        self.assertEqual(net.resolve_latest_version(cfg, opener=op), "")
        self.assertEqual(op.calls, 0, "a non-https release URL from cfg was fetched")


if __name__ == "__main__":
    unittest.main()
