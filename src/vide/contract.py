"""Arbiter-grepped literals — every string the black-box suite keys on.

tests/integration/in-container.sh captures, redacts and asserts against these
EXACT byte shapes. A "cleaner" rewording of any of them fails the acceptance
gate in a way that looks like an auth or provisioning failure. Each constant
names its consumer. tests/unit/test_contract_strings.py pins them golden.
"""
from __future__ import annotations

# Only for the favicon's data URI, which is derived from the mark rather than
# re-typed. stdlib, so this file still imports nothing of VIDE's own.
from urllib.parse import quote as _quote

# ARBITER CONTRACT (in-container.sh: grep -F 'SHOWN ONCE' | sed 's/.*): //p'):
# the parenthetical must contain 'SHOWN ONCE', then '): ', then the bare
# password ENDING the line. The redaction sed keys on the same shape.
MSG_PASSWORD = "code-server password for '{user}' (SHOWN ONCE, only the hash is stored): {pw}"
MSG_PASSWORD_ROTATED = "NEW code-server password for '{user}' (SHOWN ONCE): {pw}"
MSG_LOGIN_PASSWORD = "login/sudo password for '{user}' (SHOWN ONCE, NOT stored — record it now): {pw}"

# ARBITER CONTRACT (in-container.sh §2: sed -n 's/^VIDE_PORT=//p'): the port
# record's exact line shape; it is also the unit's EnvironmentFile, so the
# format is deployed contract and cannot change without a migration.
PORT_RECORD = "VIDE_PORT={port}\n"

# ARBITER CONTRACT (in-container.sh §9: grep 'PERM' on doctor output): the
# user-view traversal failure line. The 'PERM' token is load-bearing.
MSG_USER_VIEW_PERM = "  user-view ({user}): PERM — node NOT resolvable by user (traversal?)"
MSG_USER_VIEW_OK = "  user-view ({user}): node resolvable"

# ARBITER CONTRACT (in-container.sh §7: grep 'cookie-suffix: vide-<user>-'):
# per-instance cookie namespace prefix.
COOKIE_SUFFIX = "vide-{user}-{rand}"

# ARBITER CONTRACT (in-container.sh §2: expect_contains on install stdout):
# the snippet must carry 'reverse_proxy 127.0.0.1:{port}' and the FQDN.
# The full template lives in caddy.py; this is the load-bearing core line.
SNIPPET_PROXY_LINE = "reverse_proxy 127.0.0.1:{port}"

# ---------------------------------------------------------------------------
# SSO-MODE CONTRACT (tests/sso-mode/in-container.sh greps these). Same rule as
# above: the gate keys on the EXACT bytes, so a reword is a gate failure that
# looks like an authz failure.
# ---------------------------------------------------------------------------

# The sso twin of PORT_RECORD. Absence of VIDE_MODE means password — every
# record written before this slice stays valid, unmodified. VIDE_FQDN is
# persisted so a bare converge (`vide install --user u`) need not re-supply it,
# and `vide info` emits a real snippet.
SOCKET_RECORD = "VIDE_MODE=sso\nVIDE_SOCKET={socket}\nVIDE_FQDN={fqdn}\n"

# `ls`'s PORT column for a socket instance. Deliberately NOT "?" — that token
# means "record missing/broken", and overloading it would make a healthy SSO
# instance indistinguishable from a torn password record.
LS_BIND_SOCKET = "unix"

# status/info's mode-conditional binding line.
MSG_BIND_UNIX = "  bind:   unix:{socket}"

# The load-bearing core of the SSO snippet: the operator pastes a shell whose
# whole body is this import, so VIDE can rewrite the authz body (allow/revoke)
# without ever touching the operator's Caddyfile again.
SNIPPET_IMPORT_LINE = "import {sso_dir}/caddy/{user}.caddy"

# An EMPTY allowed_emails query allows EVERY authenticated user (upstream:
# checkAllowedEmails returns true on an empty set). An instance whose whitelist
# is empty must therefore render an address no IdP can ever assert — .invalid is
# RFC-2606 reserved, and Google's verified-email gate makes it doubly
# unreachable. Never written to the union authn file: query-only.
SSO_DENY_SENTINEL = "deny@vide.invalid"

# One sentence, three touchpoints (summary facts, snippet comment, `vide info`).
# sign_out clears the ONE shared cookie — it signs the user out of EVERY SSO
# instance on the box, and the copy must say so.
SIGNOUT_URL = "https://auth.{domain}/oauth2/sign_out"
MSG_SIGNOUT = ("wrong Google account? {url} — signs out EVERY SSO instance "
               "on this box (one shared cookie)")

# rotate-sso voids everything encrypted with the old cookie secret: the session
# cookies (the entire point) and ALSO the transient CSRF cookie of any login
# flow that browser had in flight. So the operator's own next attempt — from the
# browser that was signed in a moment ago — can be refused once, by upstream's
# "CSRF token mismatch, potential attack" page. Alarming, untrue, and shown to
# the person who has just decided they are under attack. Say it BEFORE they see
# it: a plain reload succeeds. (Walked 2026-07-27 on real Google; the hermetic
# tiers missed it because they retry with a FRESH cookie jar and a human does not.)
MSG_ROTATE_RETRY = ("expect ONE refusal per already-signed-in browser: upstream "
                    "answers 403 'CSRF token mismatch, potential attack' when the "
                    "pre-rotation login cookie is presented. That is the stale "
                    "cookie, NOT an attacker — reload the instance URL once more, "
                    "or clear it at {url}")

# The per-instance identity page, served at /vide on the INSTANCE host (not the
# auth host) from BEHIND forward_auth — so unlike MSG_AUTH_ROOT it may state who
# you are, because by the time it renders the proxy has said 202 for this exact
# instance's allow-list. Reaching it needs no cross-origin hop and no cookie
# question: it is the same origin as the editor.
#
# The email is interpolated by CADDY at request time from the header the
# forward_auth already copies, so the {http.request.*} braces must survive
# .format() as literal Caddy placeholders — hence the doubling. Reflecting it as
# HTML is safe because sso.normalize_email refuses markup metacharacters at the
# only door that writes an allow-list, and a 202 means this email matched that
# list exactly. Single quotes throughout: a double quote would end the Caddyfile
# token and take the operator's whole config with it.
# ---- the shared dress for all three pages -----------------------------------
# The Caddyfile `respond` token is the whole design brief, and ONE character in
# it is fatal: a double quote ends the token and takes the operator's entire
# config with it. That rule is absolute.
#
# CORRECTED 2026-07-29. This brief used to add "and no curly brace, which rules
# out a <style> block". That was wrong, and it cost the pages hover, classes and
# media queries for two days. Measured against a real Caddy, at BOTH adapt and
# serve time:
#   * `p{color:red}` is served back byte-for-byte; so is `{{x}}`;
#   * unbalanced braces (`a{b`, `a}b`) still `caddy validate` clean;
#   * `{http.request.host}` in the SAME body still substitutes correctly.
# Caddy substitutes the placeholders it RECOGNISES and leaves every other brace
# verbatim. So a stylesheet is legal here. The real rule is narrower: never emit
# a {name} that could collide with a genuine placeholder — CSS never does, since
# a declaration always carries a colon.
# Two techniques still matter and are not obsolete:
#   * dark mode, via color-scheme + light-dark();
#   * a full-bleed ground, via position:fixed, because the body's default 8px
#     margin cannot be zeroed by an attribute.
# Keep every value single-quoted, and keep angle brackets out of the COPY (they
# would need escaping and read worse than a plain 'your-subdomain' does).
_INK = "light-dark(#12181B,#E2E8E7)"
_SOFT = "light-dark(#5A686B,#8FA0A1)"
_BG = "light-dark(#F4F6F5,#0D1315)"
_LINE = "light-dark(#D6DDDB,#26312F)"
_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

# The mark's geometry, in ONE place. Three renderings consume it — the inline
# mark below, the percent-encoded favicon below that, and the standalone SVG
# branding.py writes into the code-server tree — and a mark that drifts between
# them stops being a mark. Add a consumer by reading these, never by re-typing
# the curves.
MARK_VIEWBOX = "0 0 64 64"

# FILLED, NOT STROKED, and the mark is ONE path rather than three. The shield and
# the V are two subpaths of a single `d`, and `fill-rule="evenodd"` makes the
# second one a HOLE in the first. That is what keeps the identity a single shape
# in a single colour: no second fill to keep in sync, nothing that depends on
# what is behind it, and no stroke width to get wrong at 16px — which is where
# the previous stroked mark was weakest, since a 5.5 line closes up long before
# a filled shape does.
#
# The subpaths must stay in ONE string. Split them into two entries and each
# gets its own <path>, evenodd has nothing to subtract, and the V fills in solid
# — a mark that looks almost right, which is the worst kind of wrong here.
MARK_FILL_RULE = "evenodd"
# THE ART FILLS THE BOX. It did not: the shield sat in x 12..52, y 10..55 of a
# 64-square, i.e. 62% x 70% of it, so a 16px favicon drew a 10 x 11 mark and gave
# back the rest as margin nobody asked for. Rescaled to touch y=0 and y=64.
#
# The 3.6 units left at each side are the SHAPE, not padding: the shield is 40
# wide by 45 tall, and a taller-than-wide figure cannot reach all four edges of a
# square without being stretched. Filling the long axis is the largest it can be
# drawn without distortion — 14.2 x 16.0 at favicon size, against 10.0 x 11.2
# before. Widening the shield to a square would fix the last 5.6% and would be a
# change to the mark itself, not to its framing.
MARK_PATHS = (
    "M32 0 L60.4 11.4 V34.1 C60.4 51.2 46.2 59.7 32 64 "
    "C17.8 59.7 3.6 51.2 3.6 34.1 V11.4 Z "
    "M16.4 19.9 L32 46.9 L47.6 19.9 L36.3 19.9 L32 28.4 L27.7 19.9 Z",
)
# The one colour in the identity: a mid teal that holds up on both a light and
# a dark browser tab. Standalone renderings MUST name it — `currentColor` has
# nothing to inherit from outside a document and resolves to black, which
# disappears on a dark tab.
MARK_COLOR = "#2F7A70"

# The mark: a shield with the V cut out of it, drawn once here and scaled by
# attribute. It is the only graphic on any of the three pages.
# It carries MARK_COLOR rather than currentColor: the favicon has always been the
# teal one, and inheriting the ink here made the same mark read as two different
# marks depending on where you looked at it.
_MARK = (f"<svg viewBox='{MARK_VIEWBOX}' width='20' height='20' "
         f"fill='{MARK_COLOR}' fill-rule='{MARK_FILL_RULE}' stroke='none'>"
         + "".join(f"<path d='{d}'/>" for d in MARK_PATHS) + "</svg>")


def standalone_mark_svg() -> str:
    """The mark as a FILE, for consumers outside the Caddyfile — today the
    code-server favicon. Double quotes are fine here (this never goes near a
    `respond` token) and the colour is explicit, per MARK_COLOR."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="' + MARK_VIEWBOX + '" '
        'fill="' + MARK_COLOR + '" fill-rule="' + MARK_FILL_RULE + '" stroke="none">'
        + "".join(f'<path d="{d}"/>' for d in MARK_PATHS)
        + "</svg>\n")


# The same mark as a favicon — DERIVED, not re-typed. It used to be a hand-written
# percent-encoded literal sitting two screens below a comment demanding the
# opposite ("add a consumer by reading these, never by re-typing the curves"),
# which made it the one consumer able to keep drawing the old mark in silence.
# Two rows in test_branding existed to catch that drift; deriving it removes the
# thing they were catching.
#
# quote(..., safe="") is also what keeps this legal inside a Caddy `respond`
# token, and now BY CONSTRUCTION rather than by inspection: every quote, angle
# bracket and brace comes out percent-encoded, so nothing can close the href and
# no literal brace survives for Caddy to read as a placeholder.
_FAVICON = ("<link rel='icon' href='data:image/svg+xml,"
            + _quote(standalone_mark_svg().strip(), safe="") + "'>")

# The one stylesheet, and the only thing on these pages that needs to be a rule
# rather than an attribute: :hover cannot be expressed inline at all. Links carry
# the mark's teal so the identity's single colour is also its only interactive
# signal. The hover DARKENS on a light ground, as asked — but LIFTS on a dark
# one, because darkening a mid teal against #0D1315 drops it to roughly 2.5:1 and
# the state change stops being visible, which is the opposite of what a hover is
# for. Both directions are one value away if that judgement is wrong.
# Braces DOUBLED, like MSG_VIDE_PAGE's placeholders and for the same reason: the
# finished page goes through .format() in caddy.py, which reads a lone { as a
# field and dies on the CSS. This is the trap the moment a stylesheet became
# possible — the constraint that bites is Python's, not Caddy's.
_STYLE = ("<style>"
          "a{{color:" + MARK_COLOR + "}}"
          "a:hover{{color:light-dark(#1F544D,#7ACFC1)}}"
          "</style>")


def _page(label: str, block: str, note: str, links: str) -> str:
    """One page in the shared treatment: the mark and a small label, then a
    block bracketed by two rules — never boxed, never centred — then a line of
    prose and the links. The rules sit OUTSIDE the block only: inside it the
    rows are left alone, so the same shape carries a page with three facts and a
    page with none, which matters because two of the three have no facts at all.

    "never centred" is about the BLOCK's own alignment — its rows stay ragged
    left. The composition as a whole sits centred in the viewport, which is a
    separate axis and a later decision (2026-07-29); T2 is unaffected by it.
    """
    return (
        "<!doctype html><meta charset='utf-8'><title>VIDE</title>"
        + _FAVICON + _STYLE +
        f"<div style='color-scheme:light dark;position:fixed;inset:0;overflow:auto;"
        f"display:flex;"
        f"background:{_BG};color:{_INK};font-family:{_MONO};font-size:13.5px'>"
        # `margin:auto` and NOT align-items/justify-content, which would be the
        # obvious pair. That ground is a scroll container (overflow:auto), and
        # centring a flex item by alignment makes overflow above it UNREACHABLE:
        # the free space goes negative and the top leaves the box with no way to
        # scroll back. Auto margins resolve to zero against negative free space,
        # so they centre when there is room and get out of the way when there is
        # not. Width is unchanged either way — the item is still shrink-to-fit
        # capped by max-width, which every current page pushes to the cap.
        f"<div style='margin:auto;padding:2.75rem 2rem;max-width:36rem'>"
        f"<div style='display:flex;align-items:center;gap:.7rem;margin-bottom:1.75rem'>"
        # The product name rides WITH the label rather than standing apart: these
        # pages are read one at a time, often after a redirect, and "SESSION"
        # alone never says whose session.
        f"{_MARK}<span style='font-size:.7rem;letter-spacing:.16em;text-transform:uppercase;"
        f"color:{_SOFT}'>VIDE &middot; {label}</span></div>"
        f"<div style='border-top:1px solid {_LINE};border-bottom:1px solid {_LINE};"
        f"padding:1.1rem 0;line-height:2'>{block}</div>"
        f"<div style='margin-top:1.5rem;color:{_SOFT};line-height:1.7'>{note}</div>"
        # The signed-out page has nowhere to send anyone — it is the end of the
        # journey, not a step in it — so it passes no links and must not emit an
        # empty element carrying a margin.
        + (f"<div style='margin-top:.6rem'>{links}</div>" if links else "") +
        "</div></div>")


def _row(key: str, value: str) -> str:
    return (f"<div><span style='display:inline-block;width:8.5em;color:{_SOFT}'>"
            f"{key}</span>{value}</div>")


MSG_VIDE_PAGE = _page(
    "session",
    _row("account", "{{http.request.header.X-Auth-Request-Email}}")
    + _row("instance", "{{http.request.host}}")
    + _row("system user", "{user}"),
    "Signing out ends your session on EVERY VIDE instance on this box, not just "
    "this one. There is one shared cookie.",
    "<a href='{signout}'>sign out everywhere</a>"
    f"<span style='color:{_SOFT}'> &middot; </span>"
    "<a href='/'>back to the editor</a>")

# oauth2-proxy serves ONLY /oauth2/* — it has no upstream of its own, so a bare
# GET on the auth host answers 404. That is not a corner: after rotate-sso the
# proxy's own error page offers a Sign in button carrying no `rd`, so a
# SUCCESSFUL re-login lands exactly there and the operator reads "404 page not
# found" as a broken fleet. The emitted auth block answers this one path itself.
# Must interpolate to a string with NO braces left: a stray {..} in a Caddyfile
# token is a placeholder, not text.
# Factored out because the signed-in variant below is THE SAME PAGE with one
# section added on top — not a second design. Keeping one source for the copy is
# what guarantees that: a change here reaches both, and neither can drift into
# saying something the other does not.
_AUTH_ROOT_BLOCK = (
    "<div>VIDE SSO login endpoint for {domain}</div>"
    f"<div style='color:{_SOFT}'>sign-in only &mdash; no IDE is served on this host</div>")
_AUTH_ROOT_NOTE = ("If you have just signed in you are done: open your instance URL "
                   "again (https://your-subdomain.{domain}).")
_AUTH_ROOT_LINKS = ("<a href='{signout}'>sign out of every "
                    "instance on this box</a>")

MSG_AUTH_ROOT = _page("sign-in", _AUTH_ROOT_BLOCK, _AUTH_ROOT_NOTE, _AUTH_ROOT_LINKS)

# The SAME root, for a visitor whose cookie the proxy has just validated. The
# root cannot simply be GATED — sign_out lands here too, and that visitor has
# just destroyed the very session a gate would demand, so gating would bounce
# them into the login they just left. It BRANCHES instead: forward_auth says 202
# and this renders, says anything else and MSG_AUTH_ROOT does. The account row
# is therefore unreachable without a check, and the anonymous copy never has to
# carry it — which is why adding identity here does NOT widen the pre-auth
# surface: the anonymous page an unauthenticated visitor can reach is unchanged.
#
# Same doubling rule as MSG_VIDE_PAGE, and the same safety argument, which holds
# one step further out: here /oauth2/auth is called with NO allowed_emails, so a
# 202 means the email matched the UNION file rather than one instance's list.
# That union is built from the same allow-lists, every write door to which runs
# sso.normalize_email — so the corpus reflected is normalized either way.
#
# It is the ROOT PAGE PLUS ONE SECTION, deliberately: same label, same copy, same
# links, with the account stacked ABOVE the existing block behind its own rule.
# A visitor who signs in must not find a different page than the one they were
# just looking at, and keeping the copy identical is also what keeps the pending
# pre-auth copy decision a single decision instead of two.
MSG_AUTH_ROOT_SIGNED_IN = _page(
    "sign-in",
    # The inner rule is what makes this read as a section of its own. _page draws
    # the outer pair; this one only has to close the bottom of the new section,
    # and its padding has to match _page's own 1.1rem or the two sections sit at
    # different heights.
    f"<div style='border-bottom:1px solid {_LINE};padding-bottom:1.1rem;"
    f"margin-bottom:1.1rem'>"
    + _row("account", "{{http.request.header.X-Auth-Request-Email}}")
    + "</div>" + _AUTH_ROOT_BLOCK,
    _AUTH_ROOT_NOTE, _AUTH_ROOT_LINKS)

# The auth root is the landing spot for TWO opposite events, because sign_out
# with no `rd` also redirects here. Walked live 2026-07-27 within minutes of
# shipping MSG_AUTH_ROOT: after signing out the operator was told "if you have
# just signed in you are done", followed by a link to the sign-out he had just
# used. So VIDE's own sign-out links carry an `rd` back here with a marker, and
# this is what that marker renders. Degrades safely: if the proxy ever refuses
# the rd (whitelist_domains), the visitor lands on MSG_AUTH_ROOT instead — the
# old wording, not an error.
MSG_AUTH_SIGNED_OUT = _page(
    "signed out",
    "<div>Signed out of EVERY VIDE instance on {domain}</div>"
    f"<div style='color:{_SOFT}'>one shared session cookie &mdash; so this was fleet-wide</div>",
    "To sign in again, open your instance URL (https://your-subdomain.{domain}) "
    "and complete the Google login. Closing this tab is safe.",
    "")

# THE ONE AUTH PAGE NOT BUILT BY _page, and the exception is the point rather
# than an oversight. Its siblings moved out of the Caddy body into files under
# <sso_dir>/caddy/pages/; this one cannot, because it is served from
# `handle_errors` and must carry {err.status_code} — which needs `respond`, and
# `respond` takes a string, not a file. So it is the only page still inlined in
# a config an operator reads under pressure, and _page's shared chrome (an SVG
# favicon data-URI plus a screenful of CSS, ~2 KB per page) is precisely what
# made that config unreadable. Plain markup, no chrome, no placeholders beyond
# the domain. The page nobody should ever see is the right one to leave bare.
#
# NO DOUBLE QUOTES ANYWHERE IN HERE: it is interpolated into a double-quoted
# Caddy `respond` argument, and one of them would end the string early and fail
# the operator's whole config. Single quotes only, same rule as its siblings.
MSG_AUTH_GATE_DOWN = (
    "<!doctype html><meta charset='utf-8'><title>VIDE</title>"
    "<div style='color-scheme:light dark;font-family:ui-monospace,SFMono-Regular,"
    "Menlo,Consolas,monospace;font-size:13.5px;max-width:36rem;margin:4rem auto;"
    "padding:0 1.5rem;line-height:1.7'>"
    "<div style='letter-spacing:.16em;text-transform:uppercase;font-size:.7rem;"
    "opacity:.6'>VIDE &middot; sign-in unavailable</div>"
    "<p>The VIDE SSO login endpoint for {domain} is reachable, but the "
    "authentication gate behind it is not answering. Nobody can sign in until it "
    "is back; sessions already established are unaffected.</p>"
    "<p style='opacity:.6'>If this box is yours: "
    "<code>systemctl status vide-oauth2-proxy.socket vide-oauth2-proxy.service</code></p>"
    "</div>")

# code-server deletes its own socket after reconnection-grace-time once the last
# client disconnects (upstream #7084): the unit stays active while every request
# 502s. doctor must NAME that state, or it is an unattributable outage.
# The auth BODY is VIDE's to re-land — render_auth_host rewrites it and reloads
# Caddy — but doctor still reports only the half it can see (the file VIDE last
# wrote vs what this build emits) and must NOT claim the live config is stale:
# Caddy holds its config in memory, VIDE cannot read the operator's Caddyfile,
# and saying otherwise would be a guess dressed as a diagnosis. Advisory, never
# a failure.
# THE DRIFT THAT SURVIVES ANYWAY, AND WHY IT NEEDS ITS OWN MESSAGE. A converge
# can be REFUSED the write — see MSG_AUTH_BODY_REPOINT_REFUSED below — and on
# that box the file stays behind what this build emits with the ordinary remedy
# (`upgrade-sso`) being exactly the write that was just declined. Naming the
# verb there would prescribe the outage the refusal exists to prevent: the
# reservation is not on the pin, so the hop a freshly rendered body would dial
# is one nothing holds, and the whole login flow (`/oauth2/start`,
# `/oauth2/callback` — emit_auth_body sends those to the same upstream) would go
# to whichever local account binds that address first, under the operator's real
# TLS name. The drift SIGNAL is kept; what changes is which remedy may be named.
# PREFIXED, because it is printed as a doctor ROW as well as through a warn
# channel, and an unprefixed constant printed flush-left in the middle of a
# section whose every other line is two-space indented reads as a different kind
# of output. MSG_PROXY_PORT_NOT_BOUND is the precedent. The label is deliberately
# NOT `PIN MOVED`: that token belongs to the neighbouring `proxy port:` row and
# two rows sharing one alarm word is how this section confused them before.
MSG_AUTH_BODY_REPOINT_REFUSED = (
    "REFUSING to re-render {path}: it would aim the fleet's login host at "
    "127.0.0.1:{port}, and this box's gate is not demonstrably serving that "
    "address — the body on disk dials {held}. Since that file became an import "
    "rather than a block you paste, re-rendering it REPOINTS the authorization "
    "sub-request for every instance, so it carries the same permit the "
    "per-instance bodies do: the gate must be proven on the destination first. "
    "Nothing was written and the login host still works. This is the ordinary "
    "reading of a half-finished port move — finish it (the reservation moves "
    "first, then this file follows), or put the pin back to {held}.")

# MSG_AUTH_BLOCK_DRIFT and MSG_AUTH_BLOCK_PIN_MOVED stood here and are gone with
# the state they described. Both were written for an operator holding a verbatim
# copy VIDE could not rewrite: one asked them to re-paste, the other told them
# NOT to, and choosing between the two was the whole job of a function, a doctor
# row and two warn emitters. The body is a VIDE-owned import now — nobody pastes
# it, so neither sentence has anyone to address. What replaced them is
# MSG_AUTH_BLOCK_MOVED, which names a verb VIDE runs, and
# MSG_AUTH_BODY_REPOINT_REFUSED for the one box where that verb declines.

MSG_SOCKET_REAPED = ("  socket ({user}): MISSING while the unit is active — code-server "
                     "reaped it after the idle grace period; heal: systemctl restart "
                     "code-server@{user}")
MSG_SOCKET_PERM = ("  socket ({user}): PERM — {socket} is {mode} {owner}, expected 0660 "
                   "{user}:vide-proxy (the socket's perms are the tripwire on the "
                   "passwordless authz policy; its DIRECTORY is what enforces it "
                   "— see the row above)")
MSG_SOCKET_OK = "  socket ({user}): {socket} 0660 {user}:vide-proxy"
# lstat, so this fires on the ENTRY: something that is not a socket is sitting at
# the path Caddy dials. Kept distinct from MSG_SOCKET_PERM because that one reads
# as permission drift, and this is the only line the diagnostic side will ever
# print that means someone swapped the address.
MSG_SOCKET_SWAPPED = ("  socket ({user}): SWAPPED — {socket} exists but is NOT a socket "
                      "(mode {mode}, owner {owner}). Caddy dials this path on every "
                      "connection; whatever is at the other end is what your TLS "
                      "hostname serves. Investigate before restarting — a restart "
                      "wipes the evidence. Then restart the instance FIRST and caddy "
                      "SECOND — that order is the fix, not tidiness: caddy pools "
                      "connections per upstream address, so putting the socket back "
                      "does NOT stop it answering from the old far end, and restarting "
                      "caddy before the socket is back only re-pools the attacker's. "
                      "This line goes green while caddy is still serving them, so "
                      "confirm containment with a request rather than with doctor. "
                      "See docs/threat-model.md")
# The freeze is per-ACTIVATION state, and a converge never restarts instances —
# so after an upgrade every already-running SSO instance is still unfrozen, and
# nothing else would say so. Observed rather than recorded, for the reason
# system.proc_no_new_privs argues: a "restart pending" marker goes stale the
# moment an operator restarts by hand, which teaches people to stop reading it.
MSG_SOCKET_DIR_UNFROZEN = (
    "  socket dir ({user}): UNFROZEN — {dir} is {found}, expected 2750 root:vide-proxy. "
    "While the instance user owns this directory they can replace the socket with a "
    "symlink and point your Caddy at any socket on the box; heal: sudo systemctl "
    "restart code-server@{user}, THEN sudo systemctl restart caddy — in that order, "
    "because caddy pools connections per upstream address and restarting it first "
    "would only re-pool whatever the path points at now. If several instances are "
    "listed, do them ONE AT A TIME and confirm each with sudo vide doctor: the unit "
    "FAILS the start when it cannot freeze the directory, and restarting the whole "
    "fleet at once is the one case no tier has reproduced")
# The other half of the same lstat. Not a fault: an unreadable parent means this
# caller cannot look, which is a different thing from the directory being wrong,
# and reporting it as UNFROZEN would send an operator to restart a healthy box.
MSG_SOCKET_DIR_UNOBSERVABLE = ("  socket dir ({user}): not observable — {dir} cannot be "
                               "read by this account; re-run with sudo")
# And the third state. UNFROZEN's sentence is about who owns the directory, which
# says nothing at all about one that is not there — systemd creates it at every
# start, so its absence under a running unit is a different failure with a
# different cause, and telling the operator about ownership sends them looking in
# the wrong place.
MSG_SOCKET_DIR_MISSING = (
    "  socket dir ({user}): MISSING — {dir} does not exist while the unit is active. "
    "systemd creates it at every start (RuntimeDirectory=), so something removed it "
    "afterwards; the instance cannot be reached until it is recreated: sudo systemctl "
    "restart code-server@{user}")
# The frozen directory is 2750 root:vide-proxy, so a non-root caller — including
# the instance user, who COULD stat this before the freeze — gets EACCES. Read as
# "missing" that becomes MSG_SOCKET_REAPED, which is false and sends the operator
# to restart a healthy instance. An unobservable property is not a fault, so this
# line never moves the exit code.
MSG_SOCKET_UNOBSERVABLE = ("  socket ({user}): not observable without root (the socket's "
                           "directory is root-owned by design); re-run with sudo")
MSG_IDE_UNOBSERVABLE = ("  IDE (code-server): not observable without root — the socket's "
                        "directory is root-owned by design; re-run with sudo")
MSG_CADDY_GROUP_STALE = ("  caddy: member of vide-proxy but the LIVE process is not — "
                         "supplementary groups are read at start; restart caddy")
# `reset-failed` is named because it is not optional: once the unit's start limit
# is burned a plain `systemctl start` is REFUSED — and so is a re-converge, which
# is what doctor's own Repair footer used to send people to. That refusal is where
# an operator following a runbook stops. It appeared nowhere in the product before
# — only in a test harness. The numbers live in the unit, not here: a limit spelled
# in two places is a limit that will disagree with itself.
# The instance-template twin of MSG_PROXY_RESTART_PENDING, and it needs one thing
# that one does not: since the freeze, the template can FAIL a start, so the first
# restart should be one instance, watched — not a reboot deciding for you.
MSG_TEMPLATE_RESTART_PENDING = (
    "the shared code-server template changed, but no instance was restarted — a "
    "converge never restarts one, because installing user B must not drop A, C and "
    "D. Each instance picks it up at its NEXT restart, which unattended means all "
    "of them at the next reboot. Apply it deliberately instead: restart ONE "
    "instance (sudo systemctl restart code-server@<user>), confirm with sudo vide "
    "doctor, then the rest. Nothing records which instances are still on the old "
    "template — systemd does not keep the unit text a running instance started "
    "from — so track the restarts yourself.")
MSG_INSTANCE_DOWN = (
    "  {user}: DOWN — the unit is enabled but systemd reports it {state}. Under SSO "
    "this is also how a refused socket freeze presents; the ExecStartPost refusal "
    "says which. Read it: journalctl -u code-server@{user} -n 50 — then: sudo "
    "systemctl reset-failed code-server@{user} && sudo systemctl start "
    "code-server@{user}. The reset-failed is not optional once the start limit is "
    "burned: a plain start is REFUSED, and so is `sudo ./install.sh`")
# Separate from MSG_INSTANCE_DOWN on purpose. That line asserts "the unit is
# enabled", which this arm deliberately never read — it fires when systemd
# answered nothing at all — and its reset-failed/start remedy is addressed to the
# very manager that is not answering. Saying the wrong remedy confidently is worse
# than saying none.
MSG_INSTANCE_UNKNOWN = (
    "  {user}: UNKNOWN — systemd did not answer for this instance, so its state is "
    "not a fact this diagnostic has. A recorded instance whose unit cannot be "
    "described means the manager, not the instance, is the thing to look at: "
    "systemctl is-system-running ; journalctl -p err -n 50")

# A converge re-asserts the shared proxy's unit and config but never restarts it:
# installing user B must not be able to drop the auth gate for A, C and D. So the
# operator is TOLD, and given the one idempotent lever that applies it.
# The word BYPASS is in here on purpose. Every other red line in this section is
# an outage; this one is the opposite, and an operator skimming for "is anything
# down" would file it with the rest. Containment first, diagnosis second — the
# ladder is ordered so the top of it fails the fleet CLOSED.
MSG_PROXY_PORT_SQUATTED = (
    "  proxy /ping: BYPASS — something is answering 127.0.0.1:{port} while the "
    "shared proxy is NOT holding it. That port is the fleet's only authorization "
    "hop, so whatever holds it decides who reaches every `auth: none` IDE on this "
    "box, and it is answering to anyone who knows a hostname. "
    "1. Contain: sudo systemctl stop caddy — this denies the fleet and fails "
    "closed, at the cost of every live WebSocket, AND it is the only complete way "
    "to drop the poisoned connection pool (a reload leaves whatever is in flight "
    "on the far end it already chose). "
    "2. Identify, with BOTH forms: sudo ss -Htlnp \"sport = :{port}\" says who is "
    "LISTENING, and sudo ss -Htnp \"sport = :{port}\" — no -l — says who holds "
    "ESTABLISHED connections. The second is not optional: an attacker that hands "
    "the listening socket back while staying alive is invisible to the first and "
    "still answering every request Caddy already had open. Read the pid= field, "
    "never the QUOTED NAME beside it: that name is whatever the process passed to "
    "prctl(PR_SET_NAME), so it can be made to read anything, including `pid=1`. "
    "3. REMOVE IT — kill the process both commands named, and make sure it cannot "
    "come back (a user unit, a cron entry, a shell loop). Nothing below works "
    "until the port is actually free: every reclaim step fails EADDRINUSE while "
    "the squatter still holds it, which reads like a broken unit rather than an "
    "attacker still in place. "
    "4. Reclaim, socket first: sudo systemctl reset-failed {socket_unit} {unit} "
    "&& sudo systemctl start {socket_unit} && sudo systemctl start {unit}. Naming "
    "the socket explicitly is what makes a bind failure attributable instead of "
    "surfacing as a dependency error on the service. "
    "5. Prove the reservation, which no HTTP probe can do: sudo vide doctor must "
    "now report the port as reserved. VIDE reads the listening socket's OWNING "
    "UID from /proc/net/tcp — a kernel-formatted number in its own column — so "
    "this step is a check, not a reading of prose. If you want to see it "
    "yourself, use a command whose pid comes from procfs rather than from a "
    "process-chosen string: sudo lsof -nP -iTCP:{port} -sTCP:LISTEN, or sudo "
    "fuser -n tcp {port}. Do NOT settle this by looking for `pid=1` in "
    "ss -Htlnp output — see step 2. An answer on /ping proves something answers; "
    "only the owning uid proves the address is reserved. "
    "6. sudo systemctl start caddy — LAST, after the real proxy answers, so the "
    "fresh pool dials an address the proxy is already on. "
    "Until you have done 6, `vide doctor` can go green while caddy is still "
    "answering from the old far end — confirm containment with a request, not "
    "with doctor.")
# The pre-incident sibling of MSG_PROXY_PORT_SQUATTED, and the higher-value row of
# the two: that one fires after the harvest has begun, this one fires before it.
# Before the socket unit existed this state was not merely undetected, it was
# UNDETECTABLE — there was nothing to check, because nothing ever reserved the
# port. It is near-unreachable on a converged box, and that rarity is the point:
# do not read it as dead code, and do not read its existence as "the hole is still
# open". It is the alarm for the four ways root can hand the address back.
MSG_PROXY_PORT_UNRESERVED = (
    "  proxy port: UNRESERVED — {socket_unit} is {state}, so nothing holds "
    "127.0.0.1:{port} and any local account can bind it: no VIDE instance, no "
    "role, no sudo. Whoever does answers the authorization sub-request for every "
    "SSO instance on this box and receives the fleet cookie on every request. "
    "Nothing has taken it yet — that is the only thing separating this line from "
    "the one above it. Restore it: sudo systemctl reset-failed {socket_unit} && "
    "sudo systemctl enable --now {socket_unit}. If it refuses to bind, something "
    "already holds the port — follow the containment ladder on the proxy /ping "
    "line instead. Note that masking or stopping this unit does not switch the "
    "SSO gate off; it gives the address away.")
# The KERNEL-VERIFIED sibling of the two above, and the only one of the three
# that rests on something no process can dress up. MSG_PROXY_PORT_UNRESERVED says
# "nothing holds it yet"; this says "something does, and it is neither systemd
# nor the proxy". Keeping them apart matters because the UNRESERVED body
# literally reads "Nothing has taken it yet", which is the opposite of this
# state — one message cannot carry both without lying in one of them.
# BYPASS is deliberately absent here too: the containment ladder owns that token,
# and proxy_health raises the ladder unconditionally whenever this row fires, so
# the pointer below is never a dead end.
MSG_PROXY_PORT_TAKEN = (
    "  proxy port: TAKEN — the socket listening on 127.0.0.1:{port} is owned by "
    "uid {uids}, which is neither 0 (systemd's reservation) nor {proxy_user}'s "
    "(the shared proxy holding the address itself, before the reservation "
    "lands). Something else is on the fleet's only authorization hop right now, "
    "and it decides who reaches every `auth: none` IDE on this box. Read from "
    "/proc/net/tcp, whose uid column the kernel formats — unlike the process "
    "name in `ss -Htlnp`, it is not chosen by the process being reported. Follow "
    "the containment ladder on the proxy /ping line.")
# The word BYPASS above is deliberately ABSENT. It is the alarm token — the thing
# an operator skims for and a monitoring grep keys on — and it belongs to
# MSG_PROXY_PORT_SQUATTED alone. Spending it in a neighbouring message's prose
# does not add urgency here, it costs the token its meaning there. Two unit rows
# asserting "no BYPASS in an ordinary outage" caught exactly that when this
# message was first drafted with it.
# The reservation is installed but NOT IN EFFECT, which is the state an operator
# is most likely to misread as done. A converge deliberately never restarts the
# shared proxy, so on an existing fleet the running process is still bound to the
# port directly and the socket unit cannot take it until that process stops.
#
# ITS FIRST CLAUSE IS A CHECKABLE FACT, SO IT HAS A PRECONDITION: it may be
# formatted only when something is actually on the pin. On a box whose pin was
# hand-edited the proxy holds the OLD address, "still holds 127.0.0.1:{port}" is
# false, and — worse — both remedies it names would MOVE the fleet's
# authorization hop rather than land a reservation on it. That case is
# MSG_PROXY_RESERVATION_OFF_PIN below. A constant whose truth depends on a
# caller-side guard says so where the constant lives.
MSG_PROXY_RESERVATION_PENDING = (
    "  proxy port: NOT YET RESERVED — {socket_unit} is installed and enabled, but "
    "the running proxy still holds 127.0.0.1:{port} itself, so the reservation "
    "takes effect only after the gate restarts. Until then this box behaves "
    "exactly as it did before: any local account can bind that port whenever the "
    "proxy is not on it. Apply when you are ready: sudo vide upgrade-sso (or a "
    "reboot). A converge does not do it for you — restarting the shared proxy for "
    "someone else's install is what VIDE refuses to do.")
# The twin of the row above, chosen when NOTHING is on the pin. Same key set,
# deliberately: the two are selected by one conditional and formatted once, so a
# key added to one and not the other would raise KeyError from inside a warning
# path — a crash in the diagnostic, on the box the message exists for.
MSG_PROXY_RESERVATION_OFF_PIN = (
    "  proxy port: NOT ON THE PIN — {socket_unit} is installed and enabled, and "
    "nothing at all is listening on 127.0.0.1:{port} right now. The gate is "
    "serving some other address, so the fleet's pin has moved away from the "
    "address this box is actually on. Do NOT reach for sudo vide upgrade-sso or a "
    "reboot here: on this box they do not land a reservation, they MOVE the "
    "fleet's authorization hop — and every instance body, plus the block you "
    "pasted into your own Caddyfile, still names the old one. Read `vide doctor` "
    "first: the THE PIN MOVED and DRIFT rows name both addresses and the cheap "
    "way out, which is backwards.")
# Hoisted out of the doctor row it was written for, because a second reader now
# prints it from a converge. Hoisting is right HERE and was wrong for
# RESERVATION_PENDING above, and the difference is the whole rule: the two
# readers of NOT BOUND observe the same three facts and prescribe the same
# command; the two readers of RESERVATION_PENDING do not.
MSG_PROXY_PORT_NOT_BOUND = (
    "  proxy port: NOT BOUND — {socket_unit} is active and configured for "
    "127.0.0.1:{port}, but nothing is listening there. A daemon-reload does NOT "
    "rebind a socket unit: it releases the old address and binds nothing until "
    "the unit is restarted. The fleet's authorization port is open right now: "
    "sudo systemctl restart {socket_unit} {unit}")
# The refusal install_proxy_socket_unit prints instead of moving the fleet's
# reservation address. NOT the BYPASS token and not an alarm word: nothing has
# been taken, nothing was written, and the box is exactly as it was one command
# ago. Shaped after MSG_MODE_IMMUTABLE — "this value is not a knob; here is the
# path that does change it".
MSG_PROXY_PIN_MOVE_REFUSED = (
    "the fleet's authorization port is pinned to 127.0.0.1:{port}, but "
    "{socket_unit} on this box reserves {address}. REFUSING to re-render the "
    "reservation onto the new address: writing it would release {address} — "
    "which the block in your own Caddyfile still names, and which any local "
    "account could then bind — and a daemon-reload binds nothing in its place, "
    "so the fleet's gate would be down and its address unowned at the same "
    "moment. Nothing was written; the rest of this run continues, so the proxy "
    "binary, the unit hardening and proxy.toml still land.\n"
    "  Cheapest way out, and it costs nothing: put VIDE_SSO_PROXY_PORT back to "
    "the address {socket_unit} names — {address} — in {fleet_file}. No re-paste, "
    "no outage, no restart.\n"
    "  CHECK WHICH ADDRESS THAT IS BEFORE YOU RESTORE THE PIN. If it is the one "
    "the block in your Caddyfile names, the line above is the whole fix. If the "
    "UNIT is what was edited — a hand edit, a .socket.d drop-in, a restore from "
    "a backup taken mid-move — then restoring the pin RATIFIES that edit: the "
    "fleet's authorization address becomes whatever was typed into a unit file, "
    "and every artifact VIDE renders, including the block you paste, follows it "
    "there. To hand the address back to the pin instead, remove the reservation "
    "and let VIDE re-create it: sudo rm {unit_path} && sudo systemctl "
    "daemon-reload && sudo vide upgrade-sso. That IS the move — it releases "
    "{address} — so it is the outage you schedule, not a way to clear this line "
    "quietly.\n"
    "  If you mean to move it, the move is a scheduled fleet outage and it is "
    "yours to schedule — see docs/sso.md. Do NOT `systemctl restart "
    "{socket_unit}` to clear this: that rebinds the address the unit is already "
    "configured for, so it changes nothing and this line comes back.")
# The refusal sso._render_all raises instead of repointing every instance's
# authorization sub-request. Reached only when the bodies and the pin already
# disagree, so it never fires on a healthy or a first-install box.
# The manager could not be read at all, which is NOT the same state as a
# reservation naming another address — and the move refusal's text is checkably
# false here: it would assert a reservation exists and tell the operator to put
# the pin back to an address it just admitted it could not report. Same refusal,
# its own words.
MSG_PROXY_RESERVATION_UNREADABLE = (
    "could not read what {socket_unit} on this box is configured to listen on — "
    "`systemctl` answered nothing at all. REFUSING to re-render the reservation "
    "for 127.0.0.1:{port} while that is unknown: if a reservation IS loaded on "
    "another address, writing this one would release the address your Caddyfile "
    "still names and bind nothing in its place. Nothing was written; the rest of "
    "this run continues.\n"
    "  This is a fault in the box, not in the fleet's configuration. Check the "
    "manager and re-run: systemctl status {socket_unit} ; systemctl daemon-reload")
# The box where the operator removed the reservation's unit file and has not
# reloaded: systemd still has it loaded and still holds the address, so the move
# refusal above declines to write over it — and then the service's own
# `Requires=` cannot resolve, because that names a fragment which is gone. Its
# own sentence, because every other message here would send the operator at the
# PIN, and the pin is not what is wrong.
MSG_PROXY_RESERVATION_FRAGMENT_GONE = (
    "{unit} could not be started: it Requires={socket_unit}, whose unit file "
    "{unit_path} has been REMOVED while systemd still has the unit loaded and "
    "still holding the address. Nothing was written and the rest of this run "
    "continued, but the gate will not come back on its own and the next reboot "
    "has no reservation to make.\n"
    "  Pick the direction you meant. To KEEP the reservation where it is, put "
    "the unit file back and re-run this command — VIDE re-creates it whenever "
    "the pin and the loaded address agree. To COMPLETE the removal, which "
    "releases the address and is therefore the outage you schedule: sudo "
    "systemctl daemon-reload && sudo vide upgrade-sso.")
MSG_PROXY_HOP_MOVE_REFUSED = (
    "the fleet is pinned to 127.0.0.1:{port}, but the authorization records this "
    "box already wrote — the per-instance bodies and <sso_dir>/caddy/auth.caddy — "
    "send their forward_auth to {named}. REFUSING to repoint them: "
    "nothing has been shown to be holding 127.0.0.1:{port}, so this would point "
    "every SSO instance here — and the fleet cookie with them — at an address "
    "any local account can bind, and then reload Caddy to make it live. A grant "
    "or a revocation must never move the fleet's authorization hop.\n"
    "  Put VIDE_SSO_PROXY_PORT back to the {named} port in {fleet_file} and this "
    "clears with no restart and no outage — but check first WHICH side moved: if "
    "the reservation unit was hand-edited rather than the pin, restoring the pin "
    "ratifies that edit and the fleet follows the unit file. To hand the address "
    "back to the pin instead, remove the reservation and let VIDE re-create it: "
    "sudo rm {unit_path} && sudo systemctl daemon-reload && sudo vide "
    "upgrade-sso — which IS the move, and so is the outage you schedule. "
    "To move it deliberately, see docs/sso.md — nothing to delete by hand there: "
    "a converge rewrites <sso_dir>/caddy/auth.caddy in place and reloads Caddy.\n"
    "  What did still happen: the authenticated-emails union was written before "
    "this refusal, so a revoke has already evicted any address that is now on no "
    "instance fleet-wide. What did not: this instance's own authorization body "
    "was not re-rendered, so an address still allowed on another instance has "
    "not been evicted from THIS one yet.")
# The N-1 directory `prune` keeps is the rollback lever, and until this message
# existed it was named nowhere an operator could find it — not in a verb, not in a
# doc, not in a warning. A lever nobody knows about is not a lever.
MSG_PROXY_DID_NOT_RETURN = (
    "the shared proxy did NOT come back after the restart, so the fleet's only "
    "authentication gate is down and every SSO instance is unreachable. Nothing "
    "was pruned — the previous version is still on disk. Read the cause: "
    "journalctl -u {unit} -n 50 — then roll back by pointing `current` at the "
    "other version under {dir} and restarting:\n"
    "  ls {dir}\n"
    "  sudo ln -sfn {dir}/<previous> {dir}/current\n"
    "  sudo systemctl reset-failed {unit} && sudo systemctl start {unit}\n"
    "The port itself is still held by systemd throughout — the socket unit owns "
    "it, not the proxy — so nothing can take the fleet's authorization address "
    "while you work. Note the proxy no longer rests in `failed` after repeated "
    "failures: it retries forever, so read `systemctl show -p NRestarts --value "
    "{unit}` rather than waiting for it to give up.")
MSG_PROXY_RESTART_PENDING = (
    "the shared proxy's unit/config changed, but the RUNNING process still has "
    "the old one — a converge never restarts it (a failed restart would take the "
    "whole fleet's auth gate down). Apply when you are ready: sudo vide "
    "upgrade-sso. In-flight requests briefly fail; nobody is signed out, because "
    "the cookie secret is untouched.")
# Caddy's admin API is unauthenticated on 127.0.0.1:2019 by default and `POST
# /load` replaces the running config — so any local account can add a site that
# reverse-proxies an instance socket with no forward_auth and reach an
# auth: none IDE. The remedy is NOT `admin off`: allow/revoke reload Caddy
# through that same API. VIDE cannot fix the operator's Caddyfile, so it says so
# and stops there.
MSG_CADDY_ADMIN_OPEN = (
    "  caddy admin: answering UNAUTHENTICATED on 127.0.0.1:{port} — any local "
    "account can load a site that reaches an instance socket with no "
    "forward_auth, and SSO instances have no password behind it. Move it to a "
    "permissioned socket in YOUR Caddyfile — see docs/sso.md; the packaged unit "
    "runs as User=caddy and /run is root-owned, so the socket needs a "
    "RuntimeDirectory=caddy drop-in or Caddy will fail to start — and one "
    "`systemctl restart caddy` to land it, because RuntimeDirectory= is created "
    "at unit START and a reload would dial the socket before it exists. "
    "Do NOT use `admin off` — vide allow/revoke reload caddy through this API.")
# A converge leaves the persisted auth block ALONE once it exists: it is the
# copy the operator pasted from, and rewriting it would make the drift detector
# compare equal forever — disabling a working control while leaving it in place.
# It used to say "re-paste it and reload caddy", because the operator held the
# only writable copy. They no longer do: the body is VIDE's file, imported by the
# three lines in their Caddyfile, and the remedy is a verb rather than a chore.
MSG_AUTH_BLOCK_MOVED = (
    "  auth host: {path} is behind what this build emits — the login host is "
    "serving an older body. Your Caddyfile needs no edit; it imports this file. "
    "Land it with: sudo vide upgrade-sso")
MSG_PROXY_NEVER_BOOTSTRAPPED = (
    "  proxy state: never observed answering /ping on this box — SSO provisioning "
    "did not finish. Re-run: sudo ./install.sh --auth sso")
MSG_PROXY_NOT_READY = (
    "the shared proxy did not answer /ping within {seconds}s — which now means "
    "'not yet', not 'gave up': the unit retries indefinitely, so this is where WE "
    "stopped watching. `systemctl start` returns before the proxy contacts the "
    "IdP (Type=exec), so the usual cause is OIDC discovery failing against "
    "{issuer} — check DNS and egress. The second possibility is new: the port is "
    "held by {socket_unit} and the service never started from it at all, which "
    "looks identical from a probe. `systemctl status {socket_unit} {unit}` "
    "separates them. Nothing was lost either way, and the converge is idempotent.")

# The stdin protocol for --sso-secrets-stdin (KEY=VALUE to EOF, same grammar as
# the at-rest EnvironmentFile). Errors name the KEY, never the value.
SSO_STDIN_CLIENT_ID = "VIDE_SSO_CLIENT_ID"
SSO_STDIN_CLIENT_SECRET = "VIDE_SSO_CLIENT_SECRET"

# rotate-sso is fleet-wide: strictly larger blast radius than `rotate <user>`.
ROTATE_SSO_PROMPT = ("Rotate the shared SSO cookie secret? This signs out ALL users on "
                     "ALL SSO instances of this box.")
REVOKE_LAST_PROMPT = ("Remove the LAST allowed email from '{user}'? The instance becomes "
                      "unreachable via SSO (deny-all) until the next `vide allow`.")

# Mode is immutable: a converge that would switch it must die naming the path.
MSG_MODE_IMMUTABLE = ("instance '{user}' is {recorded}-mode and the auth mode is immutable — "
                      "switch by reinstalling: vide destroy {user} && "
                      "vide install --user {user} --auth {requested}")
MSG_ROTATE_ON_SSO = ("'{user}' is an SSO instance — it has no per-instance password. The SSO "
                     "cookie secret is fleet-wide: vide rotate-sso (signs out ALL users on "
                     "ALL instances).")
