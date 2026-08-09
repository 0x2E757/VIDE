"""Rendered-artifact pins: the proxy TOML shape (presence + the load-bearing
ABSENCE of the seven forbidden keys), the per-instance Caddy body, and the
structural guarantee that no code path can inject a forbidden key."""
from __future__ import annotations

import re
import string
import sys
import tempfile
import unittest
from pathlib import Path

# Self-sufficient on purpose: a bare `from fakes import …` made this module
# importable ONLY through run.py, and prove-teeth.sh invokes `python3 -m unittest
# <id>` directly — so every mutation proof naming this file "went red" on
# ModuleNotFoundError instead of on the mutation. A test module that cannot be
# run standalone is a trap for any harness that names one test.
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import make_config  # noqa: E402
from vide import caddy, oauth2proxy  # noqa: E402


# `trusted_ips` is the sharpest member and was the last one added: it sits one
# word from `trusted_proxy_ips`, which IS rendered, and does the opposite thing —
# it BYPASSES authentication for the listed CIDRs. Every request reaches the
# proxy from Caddy at 127.0.0.1, so trusted_ips=["127.0.0.1/32"] would open every
# SSO instance to the whole internet. Safe to list next to the rendered
# `trusted_proxy_ips` because the check below anchors at the START of the line:
# "trusted_proxy_ips = …" does not start with "trusted_ips ".
FORBIDDEN = ("cookie_refresh", "skip_auth_routes", "skip_auth_regex", "api_routes",
             "insecure_oidc_allow_unverified_email", "scope",
             "trusted_ips", "skip_auth_preflight", "skip_jwt_bearer_tokens")

# Every {..} Caddy is MEANT to fill in a respond body. Measured 2026-07-29
# against a real Caddy: it substitutes the placeholders it recognises and serves
# every other brace verbatim, balanced or not — which is what makes a <style>
# block legal here at all. So the danger is no longer "a brace", it is a brace
# that ACCIDENTALLY names a real placeholder ({host}, {path}, {uri} …), because
# that one gets silently replaced with request data.
INTENDED_PLACEHOLDERS = {
    "{http.request.header.X-Auth-Request-Email}",
    "{http.request.host}",
}


def brace_spans(body: str) -> list[str]:
    """Innermost {..} runs, which is what Caddy's placeholder scanner sees."""
    return re.findall(r"\{[^{}]*\}", body)


def assert_no_accidental_placeholder(case: unittest.TestCase, body: str) -> None:
    for span in brace_spans(body):
        if span in INTENDED_PLACEHOLDERS:
            continue
        # A CSS declaration always carries a colon; a placeholder name never
        # does. That is the whole discriminator, and it is why the stylesheet
        # can sit in the same token as the identity placeholder.
        case.assertIn(":", span,
                      f"{span} reads as a Caddy placeholder — it will be "
                      f"replaced with request data at serve time")


class TestProxyTomlShape(unittest.TestCase):
    def _toml(self) -> str:
        with tempfile.TemporaryDirectory() as t:
            cfg = make_config(Path(t))
            return oauth2proxy.render_proxy_toml(cfg, "example.com")

    def test_presence_pins(self) -> None:
        toml = self._toml()
        for lit in (
            'provider = "oidc"',
            "reverse_proxy = true",
            'trusted_proxy_ips = ["127.0.0.1/32"]',
            'cookie_expire = "720h"',
            "session_cookie_minimal = true",
            'prompt = "select_account"',
            "skip_provider_button = true",
            "set_xauthrequest = true",
            'cookie_domains = [".example.com"]',
            'whitelist_domains = [".example.com"]',
        ):
            self.assertIn(lit, toml, f"missing: {lit}")

    def test_forbidden_keys_never_rendered_as_keys(self) -> None:
        # cookie_refresh + session_cookie_minimal is a startup crash-loop;
        # skip_auth_routes was the CVE bypass; email_domains=* would make the
        # whitelist decorative. None may appear as an assignment.
        toml = self._toml()
        for key in FORBIDDEN:
            for line in toml.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                self.assertFalse(stripped.startswith(f"{key} ") or stripped.startswith(f"{key}="),
                                 f"forbidden key rendered: {key}")

    def test_email_domains_never_wildcard(self) -> None:
        toml = self._toml()
        self.assertNotIn('email_domains = ["*"]', toml)
        self.assertNotIn('email_domains = "*"', toml)

    def test_placeholder_set_is_closed(self) -> None:
        # The template is one frozen literal with exactly the placeholders the
        # renderer interpolates — there is no options dict a caller could grow.
        # (We assert the rendered form has no stray '{...}' braces left over.)
        toml = self._toml()
        leftover = [tup[1] for tup in string.Formatter().parse(toml) if tup[1] is not None]
        self.assertEqual(leftover, [], f"unfilled placeholders: {leftover}")


class TestCaddyBody(unittest.TestCase):
    def test_csv_no_whitespace_and_plus_encoded(self) -> None:
        body = caddy.render_forward_auth_body(
            "u", ["b@x.com", "user+tag@x.com", "a@x.com"], "example.com",
            "/run/vide/u/code-server.sock", 4180)
        self.assertIn("allowed_emails=a@x.com,b@x.com,user%2Btag@x.com", body)
        self.assertNotIn("user+tag@x.com", body)

    def test_empty_set_is_deny_sentinel_never_bare(self) -> None:
        body = caddy.render_forward_auth_body(
            "u", [], "example.com", "/run/vide/u/code-server.sock", 4180)
        self.assertIn("allowed_emails=deny@vide.invalid", body)
        self.assertNotIn("allowed_emails=\n", body)
        self.assertNotIn("allowed_emails= ", body)

    def test_handle_response_matches_401_only(self) -> None:
        body = caddy.render_forward_auth_body(
            "u", ["a@x.com"], "example.com", "/run/vide/u/code-server.sock", 4180)
        self.assertIn("@unauthenticated status 401", body)
        # a 403 must never be swallowed into the redirect matcher
        self.assertNotIn("status 403", body)

    def test_tombstone_is_410_never_deleted(self) -> None:
        self.assertIn("respond", caddy.render_tombstone("u"))
        self.assertIn("410", caddy.render_tombstone("u"))

    def test_tcp_snippet_byte_identical_to_legacy(self) -> None:
        # The password-mode snippet must not drift — the frozen arbiter greps it.
        from vide.registry import Binding
        tcp = caddy.emit_snippet("alice", Binding.tcp(9797), "a.example.com")
        self.assertTrue(tcp.startswith(
            "# --- VIDE per-instance Caddy site block (user: alice) ---"))
        self.assertIn("reverse_proxy 127.0.0.1:9797", tcp)

    def test_the_sso_shell_does_not_point_at_the_body_for_the_block(self) -> None:
        """FOUND WHILE WALKING THE MANUAL GATE, 2026-08-08, in the artifact the
        operator pastes. The one-time-setup note used to read "the shared
        auth-subdomain block must exist — see <sso_dir>/caddy/auth.caddy", and
        that was true while auth.caddy WAS the block. It is the body now: no site
        header, no braces of its own. An operator following the pointer and
        pasting what they find gets a config Caddy rejects outright — which is
        the very failure the import change was supposed to end, surviving in the
        sentence that describes it."""
        from vide.registry import Binding
        shell = caddy.emit_snippet("alice", Binding.unix("/run/vide/alice/cs.sock"),
                                   "alice.example.com", sso_dir="/etc/vide/sso",
                                   parent_domain="example.com")
        setup = shell[shell.index("ONE-TIME SETUP"):]
        self.assertIn("vide info alice", setup)
        self.assertIn("NOT /etc/vide/sso/caddy/auth.caddy", setup)


class TestVidePage(unittest.TestCase):
    """/vide on the INSTANCE host: who am I, and how do I sign out. Unlike the
    auth-host root it renders from BEHIND forward_auth, so it may name an
    identity — which is exactly why its ordering is the load-bearing part."""

    def _body(self, emails=("a@x.com",)) -> str:
        return caddy.render_forward_auth_body(
            "alice", list(emails), "example.com",
            "/run/vide/alice/code-server.sock", 4180)

    def _line(self, needle: str) -> str:
        for line in self._body().splitlines():
            if line.strip().startswith(needle):
                return line.strip()
        self.fail(f"no {needle!r} line in the rendered body")

    def test_auth_runs_before_the_page_can_render(self) -> None:
        # THE assertion. Outside a `route`, Caddy's global directive order puts
        # `handle` ahead of forward_auth, and /vide would answer an identity to
        # anyone who asked. Pin both the wrapper and the written order.
        body = self._body()
        self.assertTrue(body.startswith("route {"),
                        "the authz body must be a route: directive order IS the "
                        "authentication boundary here")
        self.assertLess(body.index("forward_auth"), body.index("handle /vide*"),
                        "forward_auth must precede the page inside the route")
        # …and the inbound header dies BEFORE the proxy is asked. copy_headers
        # overwrites it from the auth response, but only if the proxy sets one;
        # without the strip, a 202 that sets none leaves the CLIENT's header
        # standing and the page names whoever asked to be named.
        self.assertIn("request_header -X-Auth-Request-Email", body,
                      "the inbound identity header is never dropped")
        self.assertLess(body.index("request_header -X-Auth-Request-Email"),
                        body.index("forward_auth"),
                        "stripping AFTER the check would undo copy_headers")

    def test_the_page_is_reached_by_a_reserved_prefix(self) -> None:
        self.assertIn("handle /vide* {", self._body())

    def test_it_names_the_identity_caddy_will_fill_in(self) -> None:
        line = self._line("respond")
        # a LIVE placeholder, not a baked value: the body is written once per
        # allow-list change, the identity is per request
        self.assertIn("{http.request.header.X-Auth-Request-Email}", line)
        self.assertIn("{http.request.host}", line)

    def test_it_offers_the_signout_and_says_it_is_fleet_wide(self) -> None:
        line = self._line("respond")
        self.assertIn("https://auth.example.com/oauth2/sign_out", line)
        self.assertIn("EVERY VIDE instance", line)

    def test_the_signout_link_comes_back_with_a_marker(self) -> None:
        # Without the rd, sign_out lands on the auth root, whose copy is written
        # for someone who has just signed IN — the first live sign-out after
        # shipping that page read "if you have just signed in you are done",
        # followed by a link to the sign-out it had just used.
        line = self._line("respond")
        self.assertIn("/oauth2/sign_out?rd=", line)
        # a URL inside a query parameter must be encoded, or the landing page's
        # own query is parsed as part of the outer one
        self.assertIn("%3A%2F%2F", line)
        self.assertNotIn("sign_out?rd=https://", line)

    def test_the_page_cannot_break_the_operators_caddyfile(self) -> None:
        # Same trap as the auth block: a double quote ends the token early and
        # takes every site in the operator's config with it.
        line = self._line("respond")
        body = line[len("respond "):].rsplit(" ", 1)[0]
        self.assertTrue(body.startswith('"') and body.endswith('"'))
        self.assertNotIn('"', body[1:-1])

    def test_the_editor_still_gets_everything_else(self) -> None:
        body = self._body()
        self.assertIn("reverse_proxy unix//run/vide/alice/code-server.sock", body)
        self.assertIn("flush_interval -1", body)

    def test_stream_close_delay_stays_out_of_the_262_dialect(self) -> None:
        # The password snippet's pin, repeated for the SSO body — with a sharper
        # edge: this file is converge-owned, so an operator on Caddy >= 2.7
        # cannot even add the directive back by hand. If it ever returns here,
        # it returns for the whole fleet on whatever caddy the box runs, and
        # 2.6.2 (stock Debian/Ubuntu apt) refuses to start over it.
        for line in self._body().splitlines():
            if "stream_close_delay" in line:
                self.assertTrue(line.lstrip().startswith("#"),
                                f"stream_close_delay left the comment: {line!r}")


class TestAuthBlockRoot(unittest.TestCase):
    """The bare root of the auth host. oauth2-proxy serves only /oauth2/*, so it
    404s `/` — and `/` is precisely where a post-rotate-sso re-login lands (the
    proxy's error page offers a Sign in button with no `rd`). Walked for real on
    2026-07-27: the operator's login had SUCCEEDED and the page said 404."""

    def _block(self) -> str:
        return caddy.emit_auth_body("example.com", 4180)

    def _page(self, filename: str) -> str:
        """A page the body no longer inlines. Two of the four moved out to files
        under <sso_dir>/caddy/pages/ when the auth host became an import, so an
        answer is now delivered EITHER as a `respond` line or as a file served by
        a rewrite+file_server pair. Every content assertion below is about the
        page rather than the delivery, so the helpers hand back the markup and
        the tests did not have to learn the difference — except where the
        difference is the point, which is the status test."""
        pages = caddy.auth_pages("example.com")
        self.assertIn(filename, pages,
                      f"{filename} is not among the rendered pages, so the "
                      f"file_server route in the body serves a 404")
        return pages[filename]

    def _serves_file(self, opener: str, filename: str) -> None:
        """The body answers `opener` by serving `filename`. Asserted as a PAIR:
        a rewrite with no file_server writes nothing, and a file_server with no
        rewrite serves the directory — either alone is the 404 this class
        exists to prevent."""
        seen = self._lines_under(opener)
        self.assertIn(f"rewrite * /{filename}", seen,
                      f"{opener!r} does not rewrite to {filename}")
        self.assertIn("file_server", seen,
                      f"{opener!r} rewrites to {filename} but serves nothing")

    def _responds_under(self, opener: str) -> list[str]:
        """EVERY respond line inside the block `opener` opens, in order, tracked
        by brace depth. Selected by its block, never by position: the auth host
        answers three different events now, and a positional helper silently
        re-aims at the wrong copy the moment a fourth is added above it (which is
        exactly what happened when sign-out got its own page).

        Depth, not a `startswith('handle')` stop: the root's two answers are
        NESTED now — `handle_response` is a handle* line that OPENS a child block
        rather than starting a sibling, so the old scan mistook it for the end of
        the block and found nothing at all. Safe because every respond body is
        one line with balanced braces, which
        test_the_answers_cannot_break_the_operators_caddyfile pins."""
        out = [s for s in self._lines_under(opener) if s.startswith("respond ")]
        if not out:
            self.fail(f"no respond under {opener!r} — the auth block answers "
                      f"nothing there, which is a 404 for whoever lands on it")
        return out

    def _lines_under(self, opener: str) -> list[str]:
        """Every stripped line inside the block `opener` opens, by brace depth.
        Split out of _responds_under when two of the answers stopped being
        `respond` lines: the scan is the same, only the filter differs."""
        out: list[str] = []
        depth, started = 0, False
        for line in self._block().splitlines():
            s = line.strip()
            if not started:
                if s.startswith(opener):
                    started, depth = True, s.count("{") - s.count("}")
                continue
            out.append(s)
            depth += s.count("{") - s.count("}")
            if depth <= 0:
                break
        if not started:
            self.fail(f"no block opened by {opener!r} in the auth body")
        return out

    def _respond_in(self, opener: str) -> str:
        responds = self._responds_under(opener)
        self.assertEqual(len(responds), 1, f"{opener!r} must answer exactly once")
        return responds[0]

    def _root_responds(self) -> tuple[str, str]:
        """The root's two answers as (anonymous, named), as MARKUP rather than as
        config lines — which is what every content assertion below wants.

        THEY ARE NO LONGER DELIVERED THE SAME WAY and the class had to stop
        assuming they were. The anonymous one is a static page, so it moved to a
        file and reaches the visitor through rewrite+file_server; the named one
        interpolates X-Auth-Request-Email, which `file_server` cannot expand, so
        it stays an inline `respond`. The pairing is still asserted here — both
        must exist, and only the named one may name the header — because "the
        root answers both callers" is this class's whole claim and is unchanged.
        Order stays load-bearing: the anonymous answer runs inside
        handle_response, the named one is the fall-through after a 202."""
        self._serves_file("handle / {", "sign-in.html")
        anon = self._page("sign-in.html")
        named = self._respond_in("handle / {")
        self.assertNotIn("X-Auth-Request-Email", anon)
        self.assertIn("X-Auth-Request-Email", named)
        return anon, named

    def _respond_line(self) -> str:
        """The ANONYMOUS root answer — the one a scanner reaches."""
        return self._root_responds()[0]

    def test_the_root_is_answered_not_left_to_the_proxy(self) -> None:
        block = self._block()
        self.assertIn("handle / {", block)
        # ONE ANSWER PER DELIVERY, and the claim is the same for both: the root
        # must ANSWER, never redirect — VIDE cannot know which instance this
        # browser was heading for, and that holds for the session-holder too,
        # whose redirect would be a loop back through the proxy.
        #
        # The named answer is still a respond and still carries its status
        # explicitly. The anonymous one is now a served file, where 200 is what
        # file_server writes when it finds the file — so the assertion that
        # replaces `endswith(" 200")` is that the file it rewrites to is one
        # auth_pages actually renders. A rewrite to a page nobody writes is the
        # 404 this test exists to prevent, wearing a valid config's clothes.
        self._serves_file("handle / {", "sign-in.html")
        self.assertTrue(self._page("sign-in.html").strip())
        self.assertTrue(self._respond_in("handle / {").endswith(" 200"))

    def test_the_answer_carries_the_two_facts_a_stranded_operator_needs(self) -> None:
        line = self._respond_line()
        # where to go next, and how to undo a wrong-account login. The copy says
        # 'your-subdomain' without angle brackets on purpose: the page is HTML
        # now, and <...> would have to be escaped to survive as text.
        self.assertIn("your-subdomain.example.com", line)
        self.assertIn("https://auth.example.com/oauth2/sign_out", line)

    def test_the_page_is_dressed_and_carries_the_mark(self) -> None:
        # BOTH answers wear the treatment: the named one is not a second design.
        for line in self._root_responds():
            self.assertIn("<svg", line)                       # the mark
            self.assertIn("rel='icon'", line)                 # and a favicon
            self.assertIn("color-scheme:light dark", line)    # both themes
            # The bracketed treatment: rules above and below, never a box. This
            # is also what puts a rule under the account row, matching /vide.
            self.assertIn("border-top:1px solid", line)
            self.assertIn("border-bottom:1px solid", line)
            # The mark is the teal one everywhere it appears — inheriting the
            # ink made the same mark read as two different marks. It is FILLED
            # now, so the colour rides on `fill` and the assertion moved with it;
            # `currentColor` stays forbidden for the same reason as before, and
            # in the same attribute it would actually appear in.
            self.assertIn("fill='#2F7A70'", line)
            self.assertNotIn("currentColor", line)
            # A stylesheet, which this brief long believed impossible. It earns
            # its place by carrying the one thing an attribute cannot express.
            self.assertIn("<style>", line)
            self.assertIn("a:hover{", line)
            # The product name rides with the label, so a page read after a
            # redirect says whose session it is describing.
            self.assertIn("VIDE &middot; ", line)

    def test_the_answer_never_asserts_a_session_it_did_not_check(self) -> None:
        # The anonymous answer runs BEFORE any auth: a scanner sees it too (five
        # found the names within 40 minutes of CT publication). It may describe
        # what to do, never claim who you are — and above all it must not carry
        # the email placeholder, because on that branch forward_auth has NOT run
        # and copy_headers has therefore overwritten nothing.
        anon, named = self._root_responds()
        low = anon.lower()
        for lie in ("you are signed in", "you are logged in", "welcome back"):
            self.assertNotIn(lie, low)
        self.assertNotIn("http.request.header", anon)
        # The named one is the opposite case and must actually name the account.
        self.assertIn("{http.request.header.X-Auth-Request-Email}", named)
        self.assertIn(">account<", named)

    def test_the_named_answer_is_the_same_page_plus_one_section(self) -> None:
        # NOT a second design. Someone who signs in must not find a different
        # page than the one they were just reading, and one source for the copy
        # is what keeps the pending pre-auth copy decision a SINGLE decision.
        anon, named = self._root_responds()
        for shared in ("VIDE SSO login endpoint for example.com",
                       "sign-in only", "just signed in",
                       "sign out of every instance on this box"):
            self.assertIn(shared, anon, "the anonymous copy moved")
            self.assertIn(shared, named,
                          "the named answer stopped carrying the root's own copy "
                          "— it has drifted into a page of its own")
        # The account sits ABOVE the shared block, behind a rule of its own:
        # _page draws one border-bottom, the added section draws the second.
        self.assertEqual(anon.count("border-bottom:1px solid"), 1)
        self.assertEqual(named.count("border-bottom:1px solid"), 2,
                         "_page's rule plus exactly one section rule")
        self.assertLess(named.index(">account<"),
                        named.index("VIDE SSO login endpoint"),
                        "the account section belongs above the block, not below")

    def test_the_named_answer_is_unreachable_without_a_202(self) -> None:
        # The whole safety of naming an account here rests on ORDER: the strip,
        # then the check, then the page. Assert the emitted sequence rather than
        # trusting the block to have been written in it.
        block = self._block()
        root = block[block.index("handle / {"):]
        # Assert presence before position, so dropping the strip fails as a
        # readable assertion rather than erroring out of .index().
        self.assertIn("request_header -X-Auth-Request-Email", root,
                      "without the strip, a client-supplied header survives a "
                      "202 that sets none, and the page names an account the "
                      "proxy never vouched for")
        strip = root.index("request_header -X-Auth-Request-Email")
        check = root.index("forward_auth 127.0.0.1:")
        named = root.index("{http.request.header.X-Auth-Request-Email}")
        self.assertLess(strip, check, "an inbound header must be dropped BEFORE "
                                      "the proxy is asked, or a client-supplied "
                                      "one survives a 202 that sets no header")
        self.assertLess(check, named, "the page must render AFTER the check")
        self.assertIn("route {", root[:strip], "outside a route, Caddy's own "
                      "directive order runs respond before forward_auth and the "
                      "named page renders for anyone who asks")

    def test_every_non_success_falls_back_to_the_anonymous_answer(self) -> None:
        # forward_auth's default for an unhandled non-2xx is to copy the PROXY's
        # response to the client, which would put oauth2-proxy's own error page on
        # the fleet's most public URL. Matching only 401 leaves 403 (a valid
        # session for a revoked address) doing exactly that.
        block = self._block()
        matcher = next(ln.strip() for ln in block.splitlines()
                       if ln.strip().startswith("@anon "))
        for cls in ("1xx", "3xx", "4xx", "5xx"):
            self.assertIn(cls, matcher,
                          f"{cls} would fall through to the proxy's own response")
        self.assertNotIn("2xx", matcher, "2xx is the success path, not a fallback")

    def test_the_answers_cannot_break_the_operators_caddyfile(self) -> None:
        # This text is pasted into a config that fronts every site the operator
        # runs, so it must survive as ONE token. The double quote is the fatal
        # character — it ends the token and takes the whole config with it.
        anon, named = self._root_responds()
        # ONLY THE INLINE ONE IS STILL A TOKEN IN THAT CONFIG. The anonymous page
        # is a file now, so a double quote in it is just a double quote in some
        # HTML — it cannot end anything, and asserting otherwise would be this
        # class testing its own history.
        #
        # The placeholder checks below DO still run on it, and for a different
        # reason than they used to. `file_server` does not run Caddy's replacer,
        # so `{...}` in that file is never expanded — which is exactly why a
        # stray one matters: it would be shown to the visitor verbatim, as a
        # literal `{http.request.header...}` on the fleet's login page. Formerly
        # dangerous, now merely wrong in public.
        body = named[len("respond "):].rsplit(" ", 1)[0]
        self.assertTrue(body.startswith('"') and body.endswith('"'))
        self.assertNotIn('"', body[1:-1])
        # Braces are NOT fatal — that was measured, not assumed, and it is why
        # these pages have a stylesheet. What is fatal is a brace that happens
        # to name a real placeholder.
        assert_no_accidental_placeholder(self, anon)
        assert_no_accidental_placeholder(self, named)
        # The identity placeholder belongs to exactly one of the two answers.
        self.assertEqual(anon.count("{http.request."), 0)
        self.assertEqual(named.count("{http.request."), 1)
        # And no .format() slot may survive: every brace run left in the emitted
        # text is either an intended placeholder or CSS, never `{domain}`.
        for span in brace_spans(anon) + brace_spans(named):
            self.assertNotIn("domain", span)
            self.assertNotIn("signout", span)

    def test_a_signed_out_visitor_is_not_told_they_signed_in(self) -> None:
        # The root is the landing spot for two OPPOSITE events; sign_out with no
        # `rd` redirects here too. Each gets its own copy, matched narrowly.
        block = self._block()
        self.assertIn("query vide=signed-out", block)
        self.assertIn("handle @signed_out {", block)
        # STILL FOUR ANSWERS, DELIVERED TWO WAYS. The count used to be four
        # `respond` lines; two of those events are served from files now, so
        # counting responds alone would silently pass while an answer went
        # missing — the exact failure this assertion exists to catch. Count the
        # answers, not the mechanism: two responds plus two rewrite targets.
        responds = sum(1 for ln in block.splitlines()
                       if ln.strip().startswith("respond "))
        served = sum(1 for ln in block.splitlines()
                     if ln.strip().startswith("rewrite * /"))
        self.assertEqual(responds, 2, "the named root answer and the gate-down "
                                      "page are the two that cannot be files")
        self.assertEqual(served, 2, "the signed-out and anonymous pages are the "
                                    "two that can")
        self.assertEqual(responds + served, 4,
                         "one answer per event — signed out, the root's "
                         "anonymous and named pair, and the error route "
                         "for a gate that cannot be reached — no more")
        # Each served page must exist, or the route is a 404 with a valid config.
        self._serves_file("handle @signed_out {", "signed-out.html")
        self._serves_file("handle / {", "sign-in.html")
        # THE FOURTH IS A GENUINELY DIFFERENT EVENT, not a duplicate of the third.
        # A dial failure is not a response: reverse_proxy returns an error up the
        # middleware chain rather than writing anything, so no response matcher —
        # including the @anon 5xx class above — can ever see it, and with no error
        # routes Caddy writes a bare status and NO BODY. "The shared proxy is
        # down" therefore served an EMPTY 502 on the fleet's most public URL, for
        # as long as this block has existed, while a comment beside it claimed
        # that case was handled deliberately.
        self.assertIn("handle_errors {", block)
        # Bare handle_errors: the `handle_errors <status...>` form is Caddy 2.8+,
        # and Debian 12 / Ubuntu 24.04 ship 2.6.2 — a status argument would fail
        # the operator's ENTIRE Caddy config, every site, VIDE's or not.
        self.assertNotRegex(block, r"handle_errors\s+\d")
        # The status is ECHOED, never literal: a hard-coded 200 would tell
        # monitoring the fleet's auth host is healthy while its gate is down, and
        # it is not always 502 — a response_header_timeout yields 504.
        err = self._respond_in("handle_errors {")
        self.assertTrue(err.rstrip().endswith("{err.status_code}"), err)
        # The sign-out page is served from a file now, so the claim is about the
        # PAGE rather than about a respond line — the two opposite events must
        # still not borrow each other's words.
        self._serves_file("handle @signed_out {", "signed-out.html")
        signed_out = self._page("signed-out.html")
        self.assertIn("Signed out of EVERY VIDE instance", signed_out)
        self.assertNotIn("just signed in", signed_out)
        self.assertIn("just signed in", self._respond_line())

    def test_the_signed_out_matcher_cannot_fire_on_a_stray_visit(self) -> None:
        # It must need BOTH the root path and the marker: a bare visit, or the
        # marker on some other path, must not claim a sign-out happened.
        block = self._block()
        matcher = block[block.index("@signed_out {"):block.index("handle @signed_out")]
        self.assertIn("path /", matcher)
        self.assertIn("query vide=signed-out", matcher)

    def test_everything_else_still_reaches_the_proxy(self) -> None:
        # /oauth2/start, /oauth2/callback, /oauth2/sign_out, /ping — the fix must
        # not narrow the auth host to its own landing page.
        block = self._block()
        self.assertIn("reverse_proxy 127.0.0.1:4180", block)
        self.assertNotIn("handle /oauth2", block)

    def test_it_stays_one_pasteable_unit(self) -> None:
        # both live tiers extract the block with `sed -n '/^# --- VIDE/,$p'`, and
        # the thing they extract is now the BLOCK rather than this body — the
        # body is imported, never pasted, so it is the wrong subject for this
        # claim and asserting it here would pin a marker nothing reads.
        block = caddy.emit_auth_block("example.com")
        self.assertTrue(block.startswith("# --- VIDE shared SSO auth endpoint"))
        # And it really is one small unit: a site header and an import, with the
        # port nowhere in it. That last part is what makes re-pasting harmless.
        self.assertIn("import ", block)
        self.assertEqual(caddy.hops(block), set())
        self.assertLess(len(block.splitlines()), 15, block)


if __name__ == "__main__":
    unittest.main()
