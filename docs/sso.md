# SSO mode — passwordless Google login, and what it costs

Read this before choosing `--auth sso`. It is not "password mode without the
password": the trust model changes shape, and several of the consequences are
fleet-wide rather than per-instance.

## The shape

- The instance binds a **unix socket**, not a TCP port. There is no port to
  reach, and no `ssh -L` route.
- The socket's `0660 <user>:vide-proxy` permissions decide **which process** may
  connect: only Caddy, joined to `vide-proxy`. They do not decide **who may
  command that process** — see "Move Caddy's admin API" below, which is a
  prerequisite for this mode and not a hardening extra.
- code-server itself is configured `auth: none`. **There is no second gate behind
  a mistake in your Caddy.** Password mode has two independent gates (the
  IP-whitelist and a password); SSO has one path, and every check on it lives
  outside code-server.
- One box-shared `oauth2-proxy` serves every SSO instance. **Authentication** is
  fleet-shared; **authorization** is per instance, enforced per request.

Where each check physically lives matters, because one of them is not VIDE's:

| Check | Enforced by |
|---|---|
| Is this a valid Google identity? | the shared `oauth2-proxy`, on a loopback port **PID 1 holds for it** — a systemd socket unit binds that address at `sockets.target` and keeps it across every stop, restart and crash loop, so the proxy inherits the descriptor rather than competing for it. What is *not* reserved is the right to connect: any local account can still speak to that port, which is why the answer to the last row in this table is a document and not a sentence |
| Is this address allowed on *this* instance? | the per-instance `forward_auth` block **in your Caddyfile** |
| Can anything but Caddy reach the IDE? | the socket's group and mode — so **membership of `vide-proxy` is the grant**: every member reaches every instance socket, and therefore a shell as every SSO user, with no cookie and no `forward_auth`. VIDE only ever adds `caddy` |
| What is at the far end of each address? | the units that own the socket's directory and the proxy's port — see [`threat-model.md`](threat-model.md) |
| Can anything but you *command* Caddy? | **your Caddy's admin API** — see below |
| TLS, DNS, the hostname | your Caddy |

Any unix path Caddy can dial is a path Caddy **will** dial, on behalf of whoever
controls the address it was told to use. The socket's permissions say which
*process* may connect; they say nothing about what is at the other end of the
path. What makes the per-instance path trustworthy is that its directory stops
being the instance user's the moment the socket exists — `threat-model.md` has the
mechanism and the one case where it is not yet closed.

## Move Caddy's admin API onto a permissioned socket

It is unauthenticated on
`127.0.0.1:2019`, and `POST /load` replaces the running config — so any local
account can add a site that reverse-proxies an instance socket with no
`forward_auth` and reach that user's IDE, which under SSO has no password behind
it. Moving it to a *different port* is not a fix: the endpoint stays
unauthenticated, just somewhere else, and `vide doctor` only probes 2019, so the
one thing that would have told you goes quiet. `admin off` is not the answer
either: `vide allow` and `vide revoke` reload Caddy through that same API. Put it
on a socket — **and give Caddy somewhere to create it**, because the packaged
unit runs as `User=caddy` and
`/run` is root-owned, so a bare `admin unix//run/caddy/admin.sock` fails to bind
and takes your whole front door down:

```bash
sudo systemctl edit caddy      # adds a drop-in
```
```ini
[Service]
RuntimeDirectory=caddy
RuntimeDirectoryMode=0750
```
```
# then, in your Caddyfile:
{
	admin unix//run/caddy/admin.sock
}
```

Then **restart Caddy once** — a reload cannot make this move:

```bash
sudo systemctl restart caddy
```

`RuntimeDirectory=` is created when the unit *starts*, so `/run/caddy` does not
exist until then; and `caddy reload` sends the config to the admin address named
in *that* config, while the running process is still on `127.0.0.1:2019`. A
reload therefore dials a socket that is not there. The restart drops in-flight
connections for about a second and is the only interruption in the procedure.

Verify, in this order:

```bash
test -S /run/caddy/admin.sock
curl -sS --max-time 2 http://127.0.0.1:2019/reverse_proxy/upstreams   # must FAIL
sudo systemctl reload caddy && echo ok
```

After the restart `systemctl reload caddy` keeps working, because the packaged
unit's `ExecReload` hands it the same Caddyfile and so resolves the same admin
address — which is why `vide allow` and `vide revoke` keep working. `/run/caddy`
ends up `0750 caddy:caddy`, created and removed with the unit, and Caddy binds
the socket itself at mode `0200` — reachable by root and by Caddy's own user,
and by nobody else.

`vide doctor` reports an admin API answering on the default port. It cannot fix
it — that file is yours, not VIDE's.

The per-email decision is made by config VIDE *renders* and you *paste*. If that
block is missing, mangled, or served outside its `route` wrapper, the per-instance
check is simply not running — and code-server behind it has no password.

## The shared cookie

One Google login yields one cookie, issued for `.<parent-domain>`.

- **Shared cookie means shared authentication.** A cookie stolen from any
  instance's browser context is a fleet-wide *authentication* artifact.
  Per-instance 403s still hold, so it is not automatically fleet-wide *access* —
  but it is a valid session everywhere the cookie is accepted.
- **It reaches your whole domain, not just VIDE.** Every host under
  `.<parent-domain>` receives it on every request, including sites of yours with
  nothing to do with VIDE. Anything there that logs request headers logs a live
  session artifact. This is browser behaviour (RFC 6265) and not tunable: a cookie
  set on `auth.<domain>` and readable on `<instance>.<domain>` is necessarily
  readable across `*.<domain>`. **If you host anything you do not fully trust on
  that domain, give the fleet its own zone** — see
  [`reverse-proxy.md`](reverse-proxy.md).
- `vide rotate-sso` regenerates the cookie secret and is **the only kill switch
  for a stolen cookie.** It signs out every user on every instance.
- `/oauth2/sign_out` clears the one shared cookie for every instance. Paired with
  `prompt=select_account` it is the wrong-account recovery.

## Revocation, precisely

- `vide revoke <email> <user>` removes an address from ONE instance.
- Removing it from its **last** instance is immediate: the hot-reloaded union
  authentication file evicts the session.
- A **cross-instance** revoke — the address still allowed elsewhere — takes effect
  when the verb reloads Caddy. Add `--force-restart` to `allow`/`revoke` if the
  change must land even when the reload alone would not carry it.
- **The 30-day cookie lifetime is not the revocation bound.** Do not reason about
  revocation in terms of cookie expiry.
- **Revoke is not a cookie kill.** A revoked address gets 403, but its cookie
  stays a valid authentication artifact. Re-allowing that address **restores
  access to the same cookie** — revoke followed by re-allow does not force a new
  login. If the cookie itself is the problem, `rotate-sso` is the answer.

## The shared proxy secret

`/etc/vide/sso/proxy.env` is `0600 root:root` and holds the OAuth **client
secret** and the **cookie secret** for the whole fleet.

Anything on the box that can reach root can read it, and with the cookie secret it
can mint a valid session for **any allow-listed address on any instance** — with
no Google login and therefore **no trace on the Google side**. That is a strictly
larger blast radius than password mode's, where forging a session requires reading
one instance's `config.yaml` and yields that one instance.

The consequence for planning: **choosing SSO does not solve co-tenancy.** If you
were reaching for SSO because you did not want co-tenants forging each other's
sessions, note that a root-capable co-tenant now forges everyone's, fleet-wide.
Only co-locate mutually trusting users — see
[`threat-model.md`](threat-model.md).

## The pre-authentication surface

The auth host's root URL answers **200 to anyone**, deliberately: sign-out lands
there too, and that visitor has just destroyed the session a gate would demand.
The anonymous page names the product and the instance-URL shape and nothing else —
no address is disclosed, and a client-supplied identity header is stripped before
the page can render.

Accept that this is a fingerprint. An unauthenticated visitor can learn that the
domain runs VIDE, and the difference between `403` and `302` on an instance host
distinguishes "authenticated but not allowed here" from "not authenticated at
all". Neither leaks an address, and neither is a capability.

## Applying a change to an existing instance

**A converge still does not re-render the per-instance authorization body** —
that stays true, and deliberately: a converge runs for whoever is being installed,
and rewriting every instance's authorization hop plus reloading your Caddy during
someone else's install puts the others at risk of that run.

`sudo vide upgrade-sso` now does re-render all of them, once, as part of the same
lever that lands the unit and the port reservation. So a box is either migrated —
units, config and every instance body — or it is not, and `vide doctor` says
which. Use that after upgrading VIDE.

The per-instance lever is still there and still idempotent, for one instance:

```bash
vide allow <an-already-allowed-email> <user>
```

Re-adding an address that is already on the list changes no authorization, but it
**re-renders that instance's body and reloads Caddy**. Note the argument order:
email first. `vide doctor` reports when the copy of the shared auth block under
`/etc/vide/sso/caddy/` no longer matches what the installed build would emit — it
cannot see your Caddyfile, only that copy, and it says so.

## Stopping the gate, and the staged restart

The fleet's authorization port is held by a systemd **socket** unit, not by
oauth2-proxy: PID 1 binds `127.0.0.1:<proxy port>` at `sockets.target` and the
proxy inherits the descriptor. Two operational consequences follow, and the second
one surprises people.

**Stopping the service is nearly a no-op.** The socket is still listening, so the
next connection re-activates the proxy — including `vide doctor`'s own probe if it
were allowed to run in that state, which is why it is not. To take the gate down
deliberately you have to stop the socket too:

```bash
sudo systemctl stop vide-oauth2-proxy.socket    # takes the service with it
```

**But that also frees the address**, and while it is free any local account may
bind it and answer the authorization sub-request for every instance on the box. So
this is a maintenance action to be brief about, not a way to leave a fleet parked.
The same applies to `systemctl mask` on the socket unit: masking it does not switch
the SSO gate off, it gives the address away. A converge refuses to run over a
masked socket unit for exactly that reason.

**Restarting, staged.** `systemctl restart vide-oauth2-proxy.socket` is not the
lever it looks like — `Requires=` propagates, so it bounces the gate for the whole
fleet. To apply a change:

```bash
sudo vide upgrade-sso                              # the supported path
# or, by hand, for the service only:
sudo systemctl restart vide-oauth2-proxy.service   # the socket keeps the port held
vide doctor                                        # reservation row must say reserved
```

During that restart the port stays bound by PID 1, so in-flight `forward_auth`
sub-requests **queue in the accept backlog** instead of being refused — users see
latency where they used to see a 502. That is the intended behaviour; if requests
hang for longer than a few seconds, the proxy is not coming back and
`journalctl -u vide-oauth2-proxy -n 50` is the next step.

## Moving the fleet's authorization port

**The reserved address is write-once.** Once a box has a reservation unit, VIDE
will not re-render it onto a different address — editing `VIDE_SSO_PROXY_PORT` in
`/etc/vide/sso/fleet.env` and running a converge gets a refusal, not a move, and
`vide allow`/`revoke`/`destroy` refuse to repoint the instance bodies for the same
reason. The refusal is not a policy preference. Writing a changed `ListenStream=`
and reloading releases the address systemd is holding and binds **nothing** in its
place, so the gate would be down and its address unowned at the same moment —
free for any local account to bind and answer for every instance on the box.

**The cheap direction is backwards, and it is usually the right one.** If the pin
was changed by mistake, put it back to the address the reservation names. No
re-paste, no outage, no restart; the refusals clear on the spot.

**Check which side moved first, though.** That advice is right when the *pin* was
edited. If the *reservation unit* was edited instead — by hand, by a `.socket.d`
drop-in, or by a restore from a backup taken mid-move — then restoring the pin
**ratifies that edit**: the fleet's authorization address becomes whatever was
typed into a unit file, and every artifact VIDE renders, including the block you
paste, follows it there. To hand the address back to the pin instead, remove the
reservation and let VIDE re-create it — **stopping it first**, because an `rm` +
`daemon-reload` over a socket unit that is still running leaves it `active` with
no unit file and no descriptor, and nothing afterwards rebinds it:

```
sudo systemctl stop vide-oauth2-proxy.socket
sudo rm /etc/systemd/system/vide-oauth2-proxy.socket
sudo systemctl daemon-reload
sudo vide upgrade-sso
sudo systemctl restart vide-oauth2-proxy.socket vide-oauth2-proxy.service
```

That **is** the move, releasing the old address, so it is the outage below and
not a way to clear the line quietly. `vide doctor`
names both addresses; the one the block in your Caddyfile names is the one to
keep.

**If you mean it, the move is a scheduled fleet outage and it is yours to
schedule.** There is no zero-downtime variant: `fd:3` is an index, so the two
addresses can never be live at once. Every SSO instance 502s from step 2 until
**step 5**: the converge there rebinds the reservation, re-renders the auth
host's body at the new pin and reloads Caddy, so the outage ends without waiting
for a paste.

1. Pick a free port **outside** `VIDE_PORT_BASE..VIDE_PORT_MAX` — the instance
   allocator excludes only the *current* pin, so an instance may already own it.
2. `sudo systemctl stop vide-oauth2-proxy.socket` — the gate goes down and the old
   address is free from here.
3. `sudo rm /etc/systemd/system/vide-oauth2-proxy.socket && sudo systemctl
   daemon-reload` — destroying the reservation is the consent. Stopping alone is
   not enough, deliberately: a stop is ambiguous (maintenance, debugging, a reboot
   in flight) and would otherwise turn an unrelated `stop` into agreement to a pin
   edit somebody made weeks earlier.
   **Do not run a converge between this step and step 4.** The pin has not
   changed yet, so at that moment VIDE still agrees with what the reservation was
   configured for — and a converge there does not refuse, it **re-creates the unit
   file you just removed** and rebinds, silently undoing this step. There is no
   warning, because nothing is wrong from VIDE's point of view. **If it happens,
   redo steps 2 AND 3, in that order** — not step 3 alone. The accidental converge
   does not merely re-create the unit, it **starts** it, and an `rm` +
   `daemon-reload` over a *running* socket unit leaves it `active` with its unit
   file `not-found` and its descriptor closed: a reservation that holds nothing
   and cannot be made to hold anything, because `systemctl start` on an already
   active unit succeeds without rebinding. Stopping it first is what lets the
   reload collect it.
   **The order of steps 3 and 4 is the reason.** Once the pin *has* moved, the
   same box behaves the opposite way: the reservation still loaded and still
   holding the old address is exactly what the write refusal is for, so a converge
   there refuses, says so, and changes nothing. That is the safe half; this note
   is about the unsafe one, which is the gap before the pin moves.
4. Edit `VIDE_SSO_PROXY_PORT` in `/etc/vide/sso/fleet.env`. The `.env` row is not
   the lever; the pin is.
5. `sudo ./install.sh --auth sso` — re-creates the unit on the new address and
   binds it, then `sudo vide upgrade-sso` to re-render the instance bodies.
6. **Nothing to paste, and nothing to delete.** This procedure used to need two
   more steps here — `rm /etc/vide/sso/caddy/auth.caddy` and a re-paste of the
   block `vide info` prints — because that file was written only when absent and
   the operator held the only writable copy of the auth host. Neither is true now:
   your Caddyfile imports that file, step 5's converge re-renders it at the new
   pin and reloads Caddy itself. If you are following an older copy of this
   document, drop those steps rather than adapting them; the `rm` is harmless but
   pointless, and there is no longer a block whose paste could go wrong.

   The converge will **decline** to advance the body if the gate is not
   demonstrably serving the new pin, and say so. That is step 5 not having
   landed — go back to it rather than editing anything by hand.
7. `sudo vide doctor` — **three** things, not two: the reservation row must read
   `reserved` on the new port, `THE PIN MOVED` must be gone, and there must be no
   `instance bodies` row. That third one is why step 5 has two commands: the
   converge re-creates and binds the reservation, but only `vide upgrade-sso`
   re-renders the per-instance bodies **on this box** — `allow`, `revoke` and
   `destroy` re-render them too, but on a box whose pin has moved those are
   exactly the writes that refuse, so the migration lever is the only one left —
   and it warns rather than failing if it
   cannot. Without that row a move could look finished on the first two criteria
   while every instance still sent its authorization sub-request to the old,
   now-free address.
   **Run this one with `sudo`, and it is not a formality.** `vide doctor` does not
   require root, and the first criterion is fine without it — the reservation row
   is computed from `systemctl`, `/proc/net/tcp` and the `0644` `fleet.env`. The
   other two are not: both come out of `<sso_dir>/caddy`, which is `0750
   root:vide-proxy`, so an unprivileged run cannot read the instance bodies **or**
   `auth.caddy`. It does not go quiet in the same way about each. The bodies row
   prints `instance bodies: not observable`, which is visible but advisory — it
   does not fail the verdict, so `vide doctor --quiet` says nothing at all. The
   `auth.caddy` rows, including `THE PIN MOVED`, are simply **absent**, and an
   absent row is indistinguishable from a satisfied one. So without root the
   second criterion can read as met by never having been checked. Schedule the
   cron hook as root for the same reason.

Nobody is signed out by any of this and the cookie secret is untouched.

## Root under SSO

A root instance is reachable by exactly the addresses explicitly granted
(`vide allow <email> root`), after the same typed-`ROOT` install ceremony. Its
blast radius is the box.

## Residual risks

- **Any local account can still TALK to the fleet's authorization endpoint.** The
  socket unit reserves the `bind`, not the `connect`: nothing can take the address
  from systemd, but anything on the box can open a connection to it and speak HTTP
  to the pre-authentication surface of the fleet's gate. `trusted_proxy_ips` does
  not separate your Caddy from a neighbour, because on one box both really are
  `127.0.0.1`. Closing this means moving the hop to a permissioned unix socket —
  which would move the block you pasted into your own Caddyfile, and which would
  also void that `trusted_proxy_ips` line, since a request over a unix socket is
  never trusted on `RemoteAddr`. Deferred deliberately; `SECURITY.md` states it.
- **On a box whose gate is running, the reservation is not in effect until that
  gate restarts.** A converge installs and enables the socket unit and restarts
  nothing that is already up, so a fleet upgraded but not yet `upgrade-sso`'d
  behaves exactly as it did before. (If the gate is **down** when the converge
  runs, it starts the socket unit itself and the reservation takes effect there
  and then — so a box that was offline for other reasons migrates on the spot.) `vide doctor` says
  which side of that line each box is on — treat that row as the migration
  checklist, not as an incidental warning.
- **An instance user can reach other instances — and your Caddy's admin socket —
  during a start she triggers.** `/run/vide/<user>` has to be writable by that user
  for code-server to bind its socket there, so she owns it from unit start until
  root freezes it, and the owner of a directory can always `chmod` it. She also
  owns the binary the unit runs, so she chooses how long that lasts. Once frozen
  the path is out of her hands for the life of the instance, and VIDE no longer
  widens the directory for her on every start — but the window is hers to open.
  **This is what "co-locate only mutually trusting users" means under SSO, and it
  is the reason that rule is not a soft one.** `threat-model.md` § *Addresses VIDE
  does not own — and the one it now reserves* has the mechanism, and `SECURITY.md`
  records it as open with what would close it.
- **A re-issued Google Workspace address inherits the previous holder's access.**
  Authorization binds to the address, not to the human.
- **Google account compromise is instance access.** SSO inherits Google's account
  security — enable MFA.
- **The consent screen must be published "In production".** While it is in testing,
  non-test users hit a Google-side `access_denied` that VIDE cannot see or report.
- `vide upgrade-sso` updates the shared proxy binary. VIDE enforces a floor of
  **7.15.2** because CVE-2026-40575 (9.1) is fixed there. To be accurate about what
  that floor is: the vulnerability requires `skip_auth_route` / `skip_auth_regex`,
  and VIDE never renders either — so the floor is defence in depth against a future
  configuration, not a patch for an exposure VIDE has today. The same verb is how
  a changed proxy unit or `proxy.toml` reaches the running process: a converge
  re-asserts both files but never restarts the fleet's gate, so it reports the
  pending restart and leaves the timing to you.

- **A wrong Google client secret is only detectable at Google.** It is used at
  token exchange, so the proxy starts happily, the install goes green, and the
  first browser login fails with `invalid_client`. Nothing on the box can see
  it, which is why `vide doctor` does not mention it. The recovery is
  `sudo ./install.sh --auth sso --sso-reaffirm`: it re-asks for the client id and
  secret, restarts the proxy so it re-reads them, and preserves the recorded
  cookie secret — nobody is signed out.
