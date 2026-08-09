# Reverse proxy & exposure (operator's responsibility)

VIDE never listens on a public interface. In **password mode** each code-server
instance binds to loopback only (`127.0.0.1:<port>`); in **SSO mode** it binds
to a unix socket gated by the shared oauth2-proxy. Either way VIDE stops there:
making an instance reachable — TLS, DNS, Cloudflare, the firewall, and (in
password mode) the **IP-whitelist** — is entirely your own Caddy's job. VIDE
cannot see or verify any of it. This file is the contract for wiring that seam
correctly; get it wrong and the *editor* breaks (usually silently) even though
the landing page loads.

Get an instance's ready-to-paste block any time:

```
vide info <user>
```

## What VIDE gives you / what it does not

| VIDE owns | You own |
|-----------|---------|
| loopback bind on a persisted port (password mode) or a unix socket (SSO mode) | reverse proxy (Caddy) |
| a generated per-instance password (hashed), or the SSO email allow-list | TLS certificate / HTTPS |
| the Caddy snippet (below) | DNS / subdomain |
| `/healthz` for probing | the **IP-whitelist** (password mode's real perimeter) |

The subdomain name is **not a secret**: it is published in Certificate-
Transparency logs the moment a cert is issued. In password mode your whitelist
is the perimeter; in SSO mode the perimeter is the Google login plus the
per-instance email allow-list (`vide allow` / `vide revoke`).

## The four invariants

1. **`flush_interval -1` baked in; `stream_close_delay` deliberately not.**
   A bare `reverse_proxy 127.0.0.1:<port>` buffers responses, so interactive
   terminal output stalls — the generated snippet bakes `flush_interval -1` in.
   The other survival directive stays out. Caddy closes every streaming
   WebSocket on each `caddy reload` — including reloads triggered by
   **unrelated sites** in a shared Caddy config — and `stream_close_delay` is
   what prevents that; but it exists only from Caddy 2.7.0, and what VIDE
   renders stays inside the 2.6.2 dialect a stock Debian/Ubuntu
   `apt-get install caddy` provides, where one unknown subdirective fails your
   *entire* config at startup (measured on a live box, 2026-08-09). So expect
   terminals and the extension host to drop whenever Caddy reloads, with no
   error the user can attribute; ACME cert renewal swaps certs without tearing
   down streams, so it is reloads — not renewals — that bite. In password mode
   the pasted block is yours: on Caddy >= 2.7, add `stream_close_delay 30m`
   beside `flush_interval` and reloads stop dropping streams. In SSO mode the
   body is VIDE-owned and re-rendered by converges, so a hand-added directive
   does not survive — and `vide allow`/`revoke` reload Caddy themselves, so
   under SSO a whitelist change drops the fleet's live terminals.

2. **Secure context (valid end-to-end HTTPS) is mandatory.**
   Outside a secure context code-server silently disables clipboard, webviews,
   and service workers — a browser rule it cannot work around. Serve the
   subdomain over valid HTTPS the whole way. **Do not** use Cloudflare
   *Flexible* TLS (HTTPS at the edge, plain HTTP to origin): it satisfies the
   browser's secure-context check but leaves the edge→origin hop in cleartext.
   Use Cloudflare *Full (strict)*, or let this Caddy terminate its own cert.

3. **Host pass-through — do not rewrite Host.**
   code-server validates the WebSocket Origin/Host. Caddy forwards the inbound
   Host by default, which is what you want. **Do not** add
   `header_up Host 127.0.0.1` (a habit from other backends): it makes the editor
   render but never connect ("Invalid Host/Origin").

4. **Cloudflare 100 s idle timeout.**
   If the subdomain is orange-clouded (proxied), Cloudflare closes idle
   WebSockets after 100 s on Free/Pro. code-server has no guaranteed sub-100 s
   ping, so idle terminals drop every ~1m40s. **Recommended:** grey-cloud
   (DNS-only) the code-server record. Trade-off: you lose Cloudflare's edge WAF/
   rate-limiting for that subdomain — coordinate with your whitelisting.

## `--proxy-domain` is optional (off by default)

The main editor works behind a subdomain with Host pass-through alone. code-
server's `--proxy-domain` only enables the in-editor *port-preview* feature
(`{{port}}.<domain>`), which additionally needs wildcard DNS **and** a wildcard
TLS cert you provision. VIDE does not set it. Add it yourself only if you want
port previews.

## Example block (what `vide info` emits, with the real port filled in)

```caddy
vide.example.com {
    reverse_proxy 127.0.0.1:9797 {
        # Do NOT add `header_up Host ...` (breaks the WebSocket handshake).
        # On Caddy >= 2.7 you may add `stream_close_delay 30m` here (see
        # invariant 1); the rendered snippet itself stays 2.6.2-valid.
        flush_interval -1
    }
}
```

## SSO mode: what changes at the seam

The four invariants above hold unchanged (the generated body bakes
`flush_interval -1` in), but the pasted block is different — and pasted
**once**:

- The per-instance site block's whole body is a single `import` of a VIDE-owned
  file under `<sso_dir>/caddy/`. `vide allow`/`vide revoke` rewrite that
  imported file and reload Caddy themselves; you never edit the block again.
- One extra shared block, `auth.<parent-domain>`, fronts the single
  oauth2-proxy for the whole box. One registered redirect URI covers every
  instance. It is built exactly like the per-instance blocks — a site header and
  a single `import` of `<sso_dir>/caddy/auth.caddy`, three lines in total:

  ```caddy
  auth.example.com {
      import /etc/vide/sso/caddy/auth.caddy
  }
  ```

  **You paste it once, ever.** The body behind the import is VIDE's file, not
  yours: `sudo vide upgrade-sso` re-renders it and reloads Caddy, so a release
  that changes the login flow reaches your box without a re-paste. Do not
  hand-edit `auth.caddy` — the next converge overwrites it. The file is
  `0644 root:root`; it is the directory holding it, `<sso_dir>/caddy`, that is
  `0750 root:vide-proxy`, so only root and Caddy can reach the body at all.
  `sudo vide info <user>` re-prints the three lines if you are rebuilding a
  Caddyfile from scratch.

  What that costs you, stated plainly: an `import` means VIDE can change the
  fleet's root of trust without you seeing the diff. A verbatim paste would not
  have — but the per-instance blocks already work this way, and `vide allow`/
  `revoke` already rewrite your allow-list under your feet through the same
  mechanism. Only the login flow was ever protected by the asymmetry.

  The body — not the block — carries a `handle /` that answers the bare root
  itself, because oauth2-proxy serves only `/oauth2/*` and would 404 the one
  path a post-`rotate-sso` re-login lands on.
- The upstream is a unix socket, not a loopback port, and the caddy user must
  be in the `vide-proxy` group (with Caddy restarted once — group membership is
  read at process start).
- Each instance answers **`https://<instance>/vide`** itself: which Google
  account this browser was authorized as, and a fleet-wide sign-out link. It
  sits behind the same `forward_auth`, on the same origin as the editor, so it
  needs no cross-domain hop — and it cannot answer anyone the proxy has not
  already approved *for this instance*. The `/vide*` prefix is reserved for
  VIDE; code-server serves nothing under it.

  The imported body is a `route` for exactly this reason. Outside one, Caddy
  applies its own global directive order, which runs `handle` **before**
  `forward_auth` — and the page would then hand out an identity taken from an
  unverified header. If you ever hand-edit that file, keep the `route`.
- **Choose the parent domain with the cookie scope in mind — before the first
  SSO install.** The session cookie is issued for `.<parent-domain>`, so every
  host under it receives the cookie on every request, including sites of yours
  unrelated to VIDE. You cannot narrow this per host: the cookie has to span the
  domain for the fleet's single sign-on to work at all. What you *can* do is put
  the fleet in its own zone — instances at `*.vide.<domain>` with parent
  `vide.<domain>` — which confines the cookie to `.vide.<domain>` and leaves the
  rest of `<domain>` clean. It costs one extra label in each hostname. Decide it
  up front: the parent domain is fixed per box once the first SSO instance is
  installed, and changing it later means a new redirect URI at Google, new DNS,
  and re-issuing the fleet's Caddy blocks.

## Verifying the seam

VIDE runs a best-effort probe at install time, and **what it covers depends on the
mode** — the difference matters, because in one of them nothing about your
perimeter has been checked at all:

- **Password mode:** loopback `/healthz`, plus a public HTTPS and
  WebSocket-`101`-upgrade check against `--fqdn` when you pass one. That second
  half really does exercise your TLS, DNS and proxy.
- **SSO mode:** loopback `/healthz` over the instance's unix socket, and **no
  public probe of any kind.** An unauthenticated request to the public hostname
  302s to the login, so a following-redirects "200" would only prove Google served
  a login page, and the WebSocket-upgrade probe cannot pass the auth gate at all.
  VIDE says so at install time rather than printing a reassuring line it has not
  earned. **The first real verification of an SSO perimeter is a browser login you
  perform yourself.**

To test the survival directive manually: open a terminal in the editor, run
`caddy reload`, and confirm the terminal survives. To reproduce the Cloudflare timeout: leave a
terminal idle > 100 s while orange-clouded, watch it drop, then grey-cloud and
confirm it survives.
