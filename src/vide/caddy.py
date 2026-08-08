"""Per-instance Caddy site-block codegen. Pure string function so install-time
print and `vide info` share one source of truth. VIDE never edits the
operator's Caddy; this only renders text (to STDOUT — the machine channel).

CONTRACT: callers MUST pass the actual persisted binding, never a default, or
the emitted block will 502. The arbiter greps stdout for the
`reverse_proxy 127.0.0.1:<port>` line and the FQDN; the sso gate greps for the
`import .../<user>.caddy` line and the auth-subdomain block.
"""
from __future__ import annotations

import re

from . import contract

# Query-safe set: keep @ . _ - and alphanumerics literal (the fact sheet marks
# @ and . safe); percent-encode everything else. Crucially this turns '+' into
# %2B — Go's query parser decodes a literal '+' to a space, which would make a
# '+tag' address silently never match. Done by hand: caddy.py is a DOMAIN module
# and may not import urllib (the import-boundary invariant).
_QUERY_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@._-")


def _pct_encode(s: str) -> str:
    return "".join(c if c in _QUERY_SAFE else f"%{ord(c):02X}" for c in s)


#: The upstream this module renders into every artifact it writes — the address
#: the fleet's authorization sub-request is actually sent to.
_HOP = re.compile(r"127\.0\.0\.1:(\d+)")


def hops(text: str) -> set[int]:
    """Every 127.0.0.1 port a VIDE-rendered Caddy artifact dials.

    IT LIVES HERE BECAUSE THE MODULE THAT RENDERS THE FORMAT IS THE MODULE
    ALLOWED TO PARSE IT. Three subjects read it back — a per-instance authz body,
    the persisted auth.caddy, and the block `vide info` prints — and two parsers
    of one format is how a guard passes while doctor alarms about the same file.

    A SET, AND THAT IS NOT A STYLE CHOICE. emit_auth_body renders the hop TWICE
    (the forward_auth on the root handler and the reverse_proxy that carries the
    whole login flow), so an exactly-one-or-None reader answers None for
    auth.caddy — and any guard built on it would silently never fire, which is
    the shape of every defect this section has already paid for.

    THE PASTED BLOCK NOW CARRIES NO HOP AT ALL, and that is the point of it: since
    the auth host's body became an import, `emit_auth_block` renders a site header
    and one `import` line, so this returns the EMPTY SET for it. That reads as
    "nothing to compare" by the rule below, which is the correct answer — the
    operator's Caddyfile no longer names the port, so it can no longer disagree
    with the pin. The port is read from auth.caddy, which VIDE owns and writes.

    EMPTY MEANS "NOTHING TO COMPARE", NEVER "IT DISAGREES". A tombstone carries
    no upstream at all (render_tombstone emits a bare `respond`), and a file this
    build did not write may carry none either. A destroyed instance must not be
    able to refuse a `vide allow` on a live one, so the caller reads an empty set
    as absence and never as a conflict."""
    return {int(m) for m in _HOP.findall(text)}


def emit_snippet(user: str, binding, fqdn: str = "", *, sso_dir: str = "/etc/vide/sso",
                 parent_domain: str = "") -> str:
    """Dispatch on the binding. The tcp branch is byte-identical to the
    password-mode snippet (frozen-arbiter no-diff). The unix branch emits the
    operator-pasted SHELL — a site block whose whole body is an `import` of a
    VIDE-owned file, so allow/revoke rewrite authz without the operator ever
    re-pasting."""
    if getattr(binding, "kind", "tcp") == "unix":
        return _emit_sso_shell(user, fqdn, sso_dir, parent_domain)
    port = binding.port if hasattr(binding, "port") else binding
    return _emit_tcp_snippet(user, port, fqdn)


def _emit_tcp_snippet(user: str, port: int, fqdn: str = "") -> str:
    site = fqdn or "<SUBDOMAIN>"
    return f"""# --- VIDE per-instance Caddy site block (user: {user}) ---
# code-server for '{user}' is bound to loopback 127.0.0.1:{port}.
# Replace <SUBDOMAIN> with the FQDN you route to this instance (if not already
# filled in), then paste into your Caddy config. VIDE does NOT manage this file.
#
# SECURE CONTEXT (mandatory): serve this subdomain over valid end-to-end HTTPS.
# Outside a secure context code-server silently disables clipboard, webviews and
# service workers. Do NOT use Cloudflare "Flexible" TLS (HTTPS at the edge, plain
# HTTP to origin): it passes the browser check but leaves edge->origin cleartext.
{site} {{
    reverse_proxy 127.0.0.1:{port} {{
        # HOST PASS-THROUGH: Caddy forwards the inbound Host by default. Do NOT
        # add `header_up Host ...`; rewriting Host to 127.0.0.1 makes the editor
        # render but never connect ("Invalid Host/Origin").
        #
        # stream_close_delay keeps long-lived WebSockets (integrated terminal +
        # extension host) alive across a `caddy reload`. Without it Caddy closes
        # every streaming WebSocket on each config reload — including reloads
        # triggered by UNRELATED sites in a shared Caddy — so terminals drop with
        # no error the user can attribute, whenever the operator/automation reloads.
        stream_close_delay 30m
        # flush_interval -1 disables response buffering so interactive terminal
        # output is flushed immediately.
        flush_interval -1
    }}
}}
# CLOUDFLARE caveat: if this subdomain is orange-clouded (proxied), Cloudflare
# closes idle WebSockets after 100s (Free/Pro). code-server has no guaranteed
# sub-100s ping, so idle terminals may drop. Recommended: grey-cloud (DNS-only)
# this record. See docs/reverse-proxy.md.
"""


def _emit_sso_shell(user: str, fqdn: str, sso_dir: str, parent_domain: str) -> str:
    """The one-time-pasted operator site block. Its whole body is an import of
    the VIDE-owned authz file — pasted ONCE, never again: allow/revoke rewrite
    the imported file and reload caddy, never touch this block."""
    site = fqdn or f"<SUBDOMAIN>.{parent_domain or '<DOMAIN>'}"
    import_line = contract.SNIPPET_IMPORT_LINE.format(sso_dir=sso_dir, user=user)
    signout = contract.SIGNOUT_URL.format(domain=parent_domain or "<DOMAIN>")
    return f"""# --- VIDE per-instance Caddy site block (user: {user}, SSO) ---
# code-server for '{user}' is bound to a UNIX SOCKET and gated by Google SSO
# through the shared oauth2-proxy. Paste this block ONCE. Its body is a single
# `import` of a VIDE-owned file; `vide allow`/`vide revoke` rewrite that file
# and reload caddy — you never edit this block again.
#
# ONE-TIME SETUP (also printed at first SSO install):
#   1. the shared auth-subdomain block (auth.{parent_domain or '<DOMAIN>'}) must exist in
#      YOUR Caddyfile — three lines, printed at first SSO install and re-printed
#      by `sudo vide info {user}`. It is NOT {sso_dir}/caddy/auth.caddy:
#      that file is the body those three lines import, and it is VIDE's to write.
#   2. the caddy user must be in the 'vide-proxy' group AND caddy restarted once
#      (group membership is read at process start).
#
# SECURE CONTEXT (mandatory): serve over valid end-to-end HTTPS. {signout}
{site} {{
    {import_line}
}}
"""


AUTH_PAGES_DIRNAME = "pages"


def auth_pages(parent_domain: str) -> dict[str, str]:
    """The auth host's two STATIC pages, as files instead of inline `respond`
    strings.

    WHY THEY LEFT THE CONFIG. Each rendered page is ~2 KB of styled HTML on a
    SINGLE line, and there were four of them: the body an operator opened during
    an incident was 8.6 KB of markup wrapped around 36 lines of routing. Routing
    is the part with security consequences and it was the part you could not see.

    ONLY THE TWO THAT NEED NOTHING AT REQUEST TIME. `file_server` writes bytes
    and does not run Caddy's replacer, so a page carrying a placeholder cannot
    come from a file unless the `templates` directive is added — and adding a
    template engine to the fleet's root of trust to save one string is a trade
    this module declines. The signed-in page interpolates
    X-Auth-Request-Email and therefore stays an inline `respond`; so does the
    gate-down page, which must carry {err.status_code}.

    Keys are file names under <sso_dir>/caddy/pages/."""
    domain = parent_domain or "<DOMAIN>"
    signout = contract.SIGNOUT_URL.format(domain=domain)
    return {
        "sign-in.html": contract.MSG_AUTH_ROOT.format(domain=domain, signout=signout),
        "signed-out.html": contract.MSG_AUTH_SIGNED_OUT.format(domain=domain),
    }


def emit_auth_block(parent_domain: str, *, sso_dir: str = "/etc/vide/sso") -> str:
    """WHAT THE OPERATOR PASTES: a site header and one import, symmetric with the
    per-instance block, which has worked this way all along.

    IT USED TO BE THE WHOLE BODY, PASTED VERBATIM — 99 lines — and the argument
    for that was real but did not survive being stated next to its neighbour: a
    dangling import would fail the operator's WHOLE Caddy config, so the auth host
    was kept out of one. The per-instance block already carries exactly that risk,
    and has since it was written. Only the login flow was being protected by the
    asymmetry; the allow-list, which `allow`/`revoke` rewrite under the operator's
    feet through an import, never was.

    WHAT IS GIVEN UP, PLAINLY: a verbatim paste means VIDE cannot change the
    fleet's login flow without the operator seeing the diff and re-pasting. An
    import means a converge can. That is a real transfer of authority over the
    root of trust, made deliberately, and it is why converge_proxy must RELOAD
    Caddy after rewriting the body — a refreshed file that nothing re-reads is a
    silent no-op, which would be the worse failure.

    NOTE THE SIGNATURE LOST proxy_port. Deliberate: the port is no longer in
    anything the operator holds, and dropping the parameter makes every call site
    a compile-time visit rather than a silently-still-correct one."""
    domain = parent_domain or "<DOMAIN>"
    return f"""# --- VIDE shared SSO auth endpoint (paste ONCE for the whole box) ---
# All SSO instances redirect their unauthenticated requests here; oauth2-proxy
# handles the Google login and the /oauth2/* endpoints. One registered redirect
# URI (https://auth.{domain}/oauth2/callback) covers every instance.
#
# The body is a VIDE-owned file, exactly like the per-instance blocks: `sudo vide
# upgrade-sso` re-renders it and reloads Caddy, so you never re-paste this block.
auth.{domain} {{
    import {sso_dir}/caddy/auth.caddy
}}
"""


def emit_auth_body(parent_domain: str, proxy_port: int, *,
                   sso_dir: str = "/etc/vide/sso") -> str:
    """The auth host's body — everything inside the braces of the block above,
    written to <sso_dir>/caddy/auth.caddy and imported from there.

    Everything EXCEPT the bare root reaches the one oauth2-proxy; the root is
    answered here because the proxy 404s it — see MSG_AUTH_ROOT."""
    domain = parent_domain or "<DOMAIN>"
    signout = contract.SIGNOUT_URL.format(domain=domain)
    in_body = contract.MSG_AUTH_ROOT_SIGNED_IN.format(domain=domain, signout=signout)
    down_body = contract.MSG_AUTH_GATE_DOWN.format(domain=domain)
    pages = f"{sso_dir}/caddy/{AUTH_PAGES_DIRNAME}"
    return f"""# VIDE owns this file. Do not edit it — `vide upgrade-sso` rewrites it.
# It is the BODY of the auth.{domain} site block in your Caddyfile, which
# imports it, so it carries NO braces of its own. The two static pages live
# beside it under {AUTH_PAGES_DIRNAME}/.
    # Sign-out lands here too (VIDE's own links carry the marker below), and it
    # is the OPPOSITE event from the one the root copy describes. Matched first
    # and narrowly — path AND marker — so a stray visit never claims a sign-out
    # happened. Written before `handle /` because handle blocks are mutually
    # exclusive and the first match wins.
    @signed_out {{
        path /
        query vide=signed-out
    }}
    handle @signed_out {{
        # `route` to pin the order literally: outside one Caddy sorts by its own
        # directive table, and a file_server that runs before its rewrite serves
        # the directory rather than the page. file_server sets Content-Type from
        # the extension, so the explicit header this replaced is gone with it.
        route {{
            root * {pages}
            rewrite * /signed-out.html
            file_server
        }}
    }}
    # The bare root is the ONE path oauth2-proxy does not serve, and the one a
    # post-rotate-sso re-login lands on (its error page's Sign in button carries
    # no `rd`). Left to the proxy it answers "404 page not found" to an operator
    # who has just successfully logged in. Answer it here instead — twice, because
    # whoever lands here usually HAS a session and the useful thing to tell them
    # is which account it is. `route` for the same reason as the instance block:
    # outside one, Caddy's own directive order puts respond before forward_auth
    # and the named page would render for anyone who asked.
    #
    # THE TWO ANSWERS ARE NOT THE SAME SHAPE, and the asymmetry is forced rather
    # than chosen. The anonymous one is a static file; the signed-in one below is
    # still an inline `respond` because it interpolates X-Auth-Request-Email, and
    # `file_server` writes bytes without running Caddy's replacer. Serving it from
    # a file would need the `templates` directive — a template engine on the
    # fleet's root of trust, to save one string. Declined.
    handle / {{
        route {{
            # Defence in depth, and the only reason the named respond below is
            # safe to write at all: copy_headers overwrites this header from the
            # AUTH RESPONSE, but only when the proxy actually sets it. Strip the
            # inbound one first and a client-supplied X-Auth-Request-Email can
            # never survive into the page, even if the proxy 202s without it.
            request_header -X-Auth-Request-Email
            forward_auth 127.0.0.1:{proxy_port} {{
                transport http {{
                    # See render_forward_auth_body for the full reasoning. Short
                    # version: the gate is socket-activated, so the dial always
                    # succeeds and every other timeout on this hop defaults to no
                    # bound — without this line the fleet's login host hangs
                    # forever whenever the proxy is down.
                    response_header_timeout 10s
                }}
                # No allowed_emails: this host authorizes nobody, it only asks
                # whether the fleet cookie is valid. 202 means the union file
                # matched, which is the whole claim the page makes.
                uri /oauth2/auth
                copy_headers X-Auth-Request-Email
                # Match every NON-success class rather than enumerating failures.
                # Two reasons: the proxy's code for a revoked-but-valid session is
                # its business and may change across versions, and forward_auth's
                # default for an unhandled non-2xx is to copy the PROXY's own
                # response to the client — so a 403 would put oauth2-proxy's error
                # page on the fleet's most public URL. 5xx is deliberate too: a
                # proxy that is UP and answering 5xx still lands the visitor on a
                # page that tells them where they are. `not status 2xx` does not
                # parse — response matchers take classes, not negation.
                #
                # THIS 5xx AND handle_errors' 5xx NOW SHOW DIFFERENT PAGES, where
                # they used to show one. This arm means the gate answered badly;
                # handle_errors means it could not be dialled at all, which is the
                # sharper fact and now says so in its own words. Reading a report
                # of "the auth host showed X" therefore tells you which of the two
                # happened — it did not before.
                @anon status 1xx 3xx 4xx 5xx
                handle_response @anon {{
                    route {{
                        root * {pages}
                        rewrite * /sign-in.html
                        file_server
                    }}
                }}
            }}
            header Content-Type "text/html; charset=utf-8"
            respond "{in_body}" 200
        }}
    }}
    handle {{
        # /oauth2/start and /oauth2/callback — the whole login flow — come
        # through here, so it needs the same bound as the forward_auth hop above.
        reverse_proxy 127.0.0.1:{proxy_port} {{
            transport http {{
                response_header_timeout 10s
            }}
        }}
    }}
    # A DIAL FAILURE IS NOT A RESPONSE, so no response matcher can see it.
    # reverse_proxy returns caddyhttp.Error(502) up the middleware chain rather
    # than writing anything, and with no error routes configured Caddy writes the
    # bare status and NO BODY at all. Until this block existed, "the shared proxy
    # is down" served an empty 502 on the fleet's most public URL — and the
    # comment above, which called the 5xx class deliberate for exactly that case,
    # described something that had never once happened. The @anon 5xx class is
    # still right for the OTHER case (the proxy is up and answering 5xx); this is
    # the half it structurally cannot reach.
    #
    # IT ALSO USED TO SHOW THE SIGN-IN PAGE HERE, which was the closest thing
    # available when both halves shared one body. They no longer do: a visitor who
    # cannot be authenticated because nothing is listening is told that, rather
    # than being offered a sign-in they cannot complete.
    #
    # BARE handle_errors, no status arguments: the `handle_errors <status...>`
    # form is Caddy 2.8+, and Debian 12 and Ubuntu 24.04 still ship 2.6.2. A
    # status argument would fail the operator's ENTIRE Caddy config — every site,
    # VIDE's or not — which is the one outcome this file exists to avoid.
    handle_errors {{
        header Content-Type "text/html; charset=utf-8"
        # {{err.status_code}}, never a literal 200: respond runs its status
        # through the replacer, and a 200 here would tell monitoring that the
        # fleet's auth host is healthy while its gate is down. It is also not
        # always 502 — a response_header_timeout above yields 504.
        #
        # THE ONE PAGE THAT COULD NOT BECOME A FILE, and the reason it is plainer
        # than its siblings. Carrying the real status needs `respond`;
        # `file_server`'s own status option is Caddy 2.7+ and the floor here is
        # 2.6.2. So this body is inlined, and it is deliberately NOT built by
        # contract._page — the shared chrome is ~2 KB of SVG and CSS per page,
        # and inlining that is exactly what made this file unreadable. The page
        # nobody should ever see is the right one to leave unstyled.
        respond "{down_body}" {{err.status_code}}
    }}
"""


def render_forward_auth_body(user: str, emails: list[str], parent_domain: str,
                             socket: str, proxy_port: int) -> str:
    """The VIDE-owned imported authz body. `allowed_emails` is a per-request
    check at the proxy — the per-instance whitelist. Security shape pins:
      * empty set -> the deny sentinel, NEVER a bare allowed_emails= (which is
        fail-open upstream: an empty set allows every authenticated user);
      * '+' -> %2B (Go's query parser turns a literal '+' into a space);
      * comma-joined with NO whitespace (' b@y' is unmatchable);
      * handle_response matches 401 ONLY — a 403 (valid session, not on THIS
        list) must pass through, because redirecting it to login loops forever.
    """
    query = _allowed_emails_query(emails)
    signout = contract.SIGNOUT_URL.format(domain=parent_domain)
    page = contract.MSG_VIDE_PAGE.format(
        user=user, signout=_signout_with_return(parent_domain))
    # `route` is load-bearing, not tidiness: outside one, Caddy sorts directives
    # by its own global order, and `handle` sorts BEFORE this forward_auth. The
    # /vide page would then render — with an identity read off an unverified
    # header — for anyone who asked. Inside `route`, execution follows the order
    # written here, so nothing below runs until the proxy has answered 202.
    return f"""route {{
    # `copy_headers` overwrites this from the AUTH RESPONSE — but only when the
    # proxy actually sets it. Strip the inbound one first so a client-supplied
    # X-Auth-Request-Email can never reach the page, even if a future proxy
    # version or config 202s without setting the header. Not an authz hole today
    # (a forger needs a valid session and only misleads themselves, on their own
    # page), which is exactly why it must be pinned now rather than discovered
    # later: the day the proxy stops setting it, nothing else would notice.
    request_header -X-Auth-Request-Email
    forward_auth 127.0.0.1:{proxy_port} {{
        transport http {{
            # THE GATE IS SOCKET-ACTIVATED, SO THE DIAL CAN NO LONGER FAIL.
            # systemd holds this address from boot and hands the descriptor to
            # oauth2-proxy, which is what stops any local account binding the
            # fleet's authorization port. The side effect lands here: connect(2)
            # now SUCCEEDS even when nothing is accepting — the kernel completes
            # the handshake into the accept queue — so dial_timeout (3s) never
            # fires, and every other timeout on this hop defaults to NO BOUND.
            # Without this line a request to any SSO instance hangs forever while
            # the gate is down, where it used to fail in milliseconds; one Caddy
            # goroutine and one queued connection per request, and a spinner
            # instead of an error.
            #
            # 10s is not a service budget. The sub-request is a local cookie
            # decrypt with NO outbound call (cookie_refresh is structurally
            # absent from proxy.toml, so the proxy never contacts the IdP
            # per-request), so the value is chosen to keep the queue-and-drain
            # benefit across an ordinary upgrade-sso/rotate-sso restart while
            # bounding a dead gate to a readable error.
            #
            # Do NOT add lb_try_duration: a retry only re-queues behind the same
            # dead service.
            response_header_timeout 10s
        }}
        uri /oauth2/auth?allowed_emails={query}
        copy_headers X-Auth-Request-Email
        @unauthenticated status 401
        handle_response @unauthenticated {{
            redir * https://auth.{parent_domain}/oauth2/start?rd={{scheme}}://{{host}}{{uri}} 302
        }}
        # 403 (valid session, not on THIS instance's list) deliberately passes
        # through — redirecting it to /oauth2/start would loop forever.
        # {contract.MSG_SIGNOUT.format(url=signout)}
    }}
    # VIDE's own path on the instance host, reserved as a prefix so a second
    # page never has to rename this one and break a bookmark. code-server serves
    # nothing under /vide; claiming it means it never can.
    handle /vide* {{
        header Content-Type "text/html; charset=utf-8"
        respond "{page}" 200
    }}
    handle {{
        reverse_proxy unix/{socket} {{
            stream_close_delay 30m
            flush_interval -1
        }}
    }}
}}
"""


def render_tombstone(user: str) -> str:
    """Written by `vide destroy` of an SSO instance. NEVER delete the imported
    file: a dangling `import` fails the operator's whole Caddy config load and
    takes every site down."""
    return (f"# VIDE instance '{user}' destroyed. Remove the pasted {user} site block\n"
            f"# from your Caddyfile, reload caddy, then delete this file.\n"
            'respond "VIDE instance removed" 410\n')


def _signout_with_return(parent_domain: str) -> str:
    """The sign-out URL VIDE's own links use: it comes back to the auth root
    carrying a marker, so the landing page can say "signed out" instead of the
    sign-IN copy. Found the hard way — the first live sign-out after shipping
    that page was told "if you have just signed in you are done", followed by a
    link to the sign-out it had just used.

    The rd value is a URL inside a query parameter, so it is fully
    percent-encoded. Fails SAFE: oauth2-proxy validates rd against
    whitelist_domains and, if it ever refuses, redirects to the bare root — the
    neutral page, not an error.
    """
    rd = _pct_encode(f"https://auth.{parent_domain}/?vide=signed-out")
    return f"{contract.SIGNOUT_URL.format(domain=parent_domain)}?rd={rd}"


def _allowed_emails_query(emails: list[str]) -> str:
    if not emails:
        return contract.SSO_DENY_SENTINEL
    return ",".join(_pct_encode(e) for e in sorted(emails))
