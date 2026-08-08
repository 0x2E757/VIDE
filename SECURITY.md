# Security policy

VIDE provisions a browser IDE with a shell on a real machine, and deployments of it
are live boxes reachable from the internet. A public issue describing an
authorization or secret-handling defect is a working exploit against every
deployment at once, including ones the reporter cannot see.

**Please report privately first.**

## How to report

Use GitHub's **private vulnerability reporting** on this repository
("Security" → "Report a vulnerability"). That channel needs no email address from
either side and keeps the report unindexed until there is a fix to point at.

If you cannot use it, open a public issue containing **only** the words
"security report, requesting a private channel" and nothing else — no
reproduction, no affected paths.

There is no bounty. There is no SLA. This is a single-maintainer project and the
honest expectation to set is: reports are read, triaged in the order they arrive,
and answered.

## Which version to report against

There are no tagged releases yet — report against the default branch. Name the
exact tree you tested so a fix can be checked against the same thing:

```bash
git rev-parse --short HEAD    # from a clone — the precise answer
vide --version                # from a deployed box — coarse, but always available
```

Prefer the SHA. `vide --version` reports `__version__`, which is bumped by hand
and so names a range of trees rather than one; on a box provisioned by
`install.sh` it is often the only identifier there is.

Include the output, plus your distro and whether the instance is password or SSO
mode. Those three facts determine which of the two very different trust models
applies.

## In scope

What VIDE itself decides, renders, or writes:

- The rendered Caddy `forward_auth` bodies and the per-instance email allow-list —
  anything that lets an address reach an instance it is not allowed on.
- The shared `oauth2-proxy` configuration VIDE generates, including any auth-skip
  surface appearing where VIDE never intends one.
- Secret handling: generation, entropy, file modes and owners, and any path by
  which a secret reaches argv, the environment, a log, or a world-readable file.
- Unix socket and file permissions, systemd unit hardening, and the privilege of
  what VIDE installs or runs.
- The installer and CLI verbs: privilege escalation, argument handling, refusals
  that should fail closed but do not.

## Known open weaknesses

In scope, known, and **open** — listed so an operator can decide, not waived. A
report of one of these is not unwelcome, but it is not news; if you can widen one
past what is written here, that is. Each says what it takes, what it gets, what
you can do today, and what would remove it.

- **The fleet's authorization hop: the bind is reserved; the connection is
  not.** A root-held socket unit binds `127.0.0.1:<proxy port>` at
  `sockets.target` — before any login session, cron job or user unit exists — and
  PID 1 keeps holding it while the proxy is stopped, restarting, crash-looping,
  killed, or compromised and exited. In every one of those windows an
  unprivileged `bind(2)` gets `EADDRINUSE`. The windows that would otherwise be
  open — every boot, `upgrade-sso`, `rotate-sso`, a crash loop — are therefore
  closed, but only on a box where that unit is **active (listening)** on the port
  the fleet is pinned to **and something is actually bound to it**. Those are
  three conditions, not two: a changed `ListenStream=` plus a bare
  `daemon-reload` satisfies the first two while holding nothing, which is why
  `vide doctor` checks the third. The fleet-cookie harvest closes with them: the
  cookie reaches only the process systemd starts from a root-owned unit.
  **How the holder is checked, and its one admitted limit.** VIDE reads the owning
  UID of the listening socket from `/proc/net/tcp` — kernel-formatted, in its own
  column, world-readable, so the check needs no root and is identical on every
  box — and reports the port as reserved only when that uid is 0. It deliberately
  does **not** parse `ss -Htlnp`: that command's process column renders
  `users:(("<comm>",pid=N,fd=M))` and `<comm>` is set by the reported process
  itself via `prctl(PR_SET_NAME)`, so a squatter naming itself `pid=1` puts a `1`
  into any regex — and into the eye of any operator skimming the line. If you
  verify by hand, use `lsof -nP -iTCP:<port> -sTCP:LISTEN` or `fuser -n tcp
  <port>`, whose pid comes from procfs. The limit that remains is that uid 0 is
  not distinguished from uid 0: a root-level compromise already owns the box.
  **Hand-editing `VIDE_SSO_PROXY_PORT` after the first install is not supported,
  and VIDE refuses to perform the move.** The refusal stands on the reservation:
  everything else in the path is VIDE's to rewrite — what you paste is a site
  header and an `import`, and the body behind it is a VIDE-owned file — but the
  address the gate is actually holding is not something a config rewrite can
  change. Any sequence that moves the pin while the socket unit is
  still holding the old address points every instance's authorization sub-request
  at a port nobody is listening on, and frees the old one for any local account to
  bind. VIDE will not advance the auth body onto an address its gate is not
  demonstrably serving, which is what keeps a half-finished move loud rather than
  quietly broken.
  There is no zero-downtime variant, because `fd:3` is an index and the two
  addresses can never be live at once; a move is a scheduled fleet outage and it
  is yours to schedule. **What refuses, concretely:** a converge will not
  re-render the socket unit onto the new address, and `vide allow` / `revoke` /
  `destroy` — and `upgrade-sso`, which reaches the same guard and whose refusal
  is a warning rather than a failure — will not repoint the per-instance
  authorization bodies at it unless
  the gate is demonstrably already there — so the reserved address is write-once
  and the disagreement stays a loud, fully reversible configuration error instead
  of a scheduled self-inflicted outage. `vide doctor` carries a `THE PIN MOVED`
  row that names both addresses and says **who** holds the abandoned one — four
  answers, not a yes/no, because "this box's own reservation is still on it" and
  "something else is" call for opposite actions, and a row that collapsed them
  would name the wrong one. The four are: your own reservation (nothing is open, the
  pin is what moved), something that is not your reservation, nothing at all (any
  local account may bind it), and *unreadable* — VIDE could not read
  `/proc/net/tcp` and says so rather than guessing in either direction.
  **The cheap way out is backwards while the gate is still on the old address**,
  which is the usual case: put the pin back and the disagreement clears with no
  re-paste, no outage, no restart. It stops being the cheap way out once the move
  has actually landed — walking the pin back then marches the reservation off an
  address it is now holding — so the row picks the direction from the live fact
  rather than always naming the same one. **Check which side moved before you
  restore the pin:** if the *unit* was hand-edited rather than the pin, restoring
  the pin ratifies that edit and the fleet's authorization address becomes
  whatever was typed into a unit file. The refusal messages say this and point at
  the other direction, but they print it in a shortened form —
  `rm … && systemctl daemon-reload && vide upgrade-sso` — and **that form is not
  safe to run literally on a box whose socket unit is up.** Removing the unit file
  and reloading over a *running* socket unit leaves it `active` with no unit file
  and no descriptor, and nothing afterwards rebinds it, because `systemctl start`
  on an already-active unit succeeds without binding. The order that works is
  `stop` → `rm` → `daemon-reload` → converge → `systemctl restart
  vide-oauth2-proxy.socket vide-oauth2-proxy.service`, and
  [`docs/sso.md`](docs/sso.md) gives it as a block to copy. Either way it *is* the
  move, and so an outage you schedule rather than a way to clear the line quietly.
  The supported forward path, which
  begins by destroying the reservation rather than merely stopping it, is in
  [`docs/sso.md`](docs/sso.md) § *Moving the fleet's authorization port*.
  **A second row catches the half-applied move.** Completing the migration but
  skipping the step that re-renders the instance bodies leaves every reservation
  row green — the address is reserved, root-held and answering — while each
  instance still sends its authorization sub-request to the old, now-free port.
  `vide doctor` **run as root** reads those bodies and fails on the disagreement,
  so the state is no longer one the health verb *asserts* is clean. The root
  qualifier is load-bearing rather than pedantic: `<sso_dir>/caddy` is `0750
  root:vide-proxy`, so an unprivileged run cannot read them and says
  `instance bodies: not observable` instead — a line that is deliberately advisory,
  which means it does not fail the verdict and `doctor --quiet` prints nothing.
  Schedule the cron hook as root, or this row is not a control on your box.
  The row is deliberately silent when the gate is **not** on the pin, because
  there the only repair it could name is the very write the grant guard refuses.
  **And the block you paste names no port at all.** What you paste for the auth
  host is a site header and an `import` of a VIDE-owned file — the same shape the
  per-instance blocks have — so it carries no address and cannot carry a stale
  one. Whatever the pin is doing, you end up importing the body VIDE actually
  wrote, which is the file doctor reads. This closes a hazard worth naming because
  it is the one an operator would otherwise re-create by hand: a pasted block that
  named the hop would, on a moved-pin box, aim the whole login flow — not just the
  authorization sub-request — at an address nothing held, published under your own
  TLS name. If you hand-write your own auth block instead of pasting VIDE's, do
  not name the port in it.
  **What that traded away, stated plainly, because it is a real transfer of
  authority:** a verbatim paste meant VIDE could not change the fleet's login flow
  without you seeing the diff and pasting it yourself. An import means a converge
  can. The reason it was still the right trade is that the asymmetry was already
  half-fiction: the per-instance bodies are imported and `vide allow`/`vide revoke`
  rewrite them under your feet, so only the login flow was ever protected — never
  the allow-list, which is the artifact that decides who gets in.
  **The write is not unconditional, and the condition is the same one the
  per-instance bodies carry.** Re-rendering that body can REPOINT every instance's
  authorization sub-request, so it needs the gate demonstrably on the destination
  first. On a box whose pin moved while the reservation refused to follow, the
  converge declines to advance the body, says so, and leaves the login host
  working on the address it is actually serving. Without that lock this change
  would have handed VIDE the ability to break the fleet's login by its own hand,
  out of the same run that refuses the socket-unit write for exactly that reason.
  **A first install reserves the address there and then; a converge never
  restarts a gate that is already up.** On a box with no gate — which is every
  box before its first SSO instance — the converge writes, enables **and starts**
  the socket unit, so the reservation is in effect from that run onward, not from
  some later reboot. After that, a converge deliberately restarts nothing that is
  already running: a run for one user must not be able to drop the auth gate for
  everyone else. The consequence to know is that a **changed** socket unit or
  proxy config is written and reported but not applied until you run
  `sudo vide upgrade-sso`; `vide doctor` tells you a box is in that state.
  **What survives on every box, migrated or not:** any local account can still
  `connect(2)` to that port and speak HTTP to the fleet's authorization endpoint.
  The reservation decides who may **answer** there, never who may **ask**.
  `trusted_proxy_ips = ["127.0.0.1/32"]` does not help: it cannot tell your Caddy
  from a neighbour, because on one box both genuinely are `127.0.0.1`.
  **And the reservation is one address, held by one unit.** `[::1]:<port>` is not
  reserved — every block VIDE renders names the literal `127.0.0.1`, so if you
  hand-wrote `localhost`, change it. A loopback `VIDE_SSO_ISSUER_URL` names a
  different unreserved port whose holder is the fleet's IdP. `systemctl mask` on the
  **socket** unit does not switch the gate off — it gives the address away and
  stops the proxy taking it back; a converge refuses over a masked one and
  `vide doctor` reports it, but nothing prevents root doing it. A `stop` on that
  unit is not the same thing and does not belong in the same sentence: the service
  carries `Requires=` on it, so stopping the socket **takes the gate down with
  it** — the address is freed and the fleet is offline, which is loud rather than
  quiet. `mask` is the trap precisely because it is not. And a socket unit
  whose `ListenStream=` has drifted from the pin reserves a port nobody dials while
  the real hop stays free — `vide doctor` compares the two for exactly that reason.
  **How VIDE decides whether a reservation exists at all**, because the answer
  gates every refusal above and the wrong answer is the one that *permits* a move:
  it asks systemd first and the filesystem only to break a silence. A positive
  answer from the manager always decides, so a unit file that has been removed
  while the unit is still loaded — an `rm` without a `daemon-reload` — still counts
  as a reservation, and it must: the manager still has a reservation configured,
  and if that unit is also active it is still holding the address. The rule is
  about **consent** rather than about what is held at that instant, which is why
  it does not gate on `active` — a reader that trusted the missing file would
  permit the write on a box where the address is genuinely held, reload, drop the
  descriptor and bind nothing in its place. Only when the manager
  answers nothing does the file decide, and there **a masked unit, a dangling
  symlink, an empty or unreadable fragment all count as present** — every one of
  them is a state to refuse over rather than a box with no reservation. The escape
  from all of them is the same consent gesture the move requires — and in the same
  order, `stop` before `rm` before `daemon-reload`, for the reason given above:
  removing a unit file out from under a running socket unit leaves it holding
  nothing that anything can rebind.
  One consequence has its own message, and it applies to a **narrower** box than
  the paragraph above: the fragment gone, the unit still loaded, **and the pin
  already moved**. (With the pin unmoved, VIDE agrees with the loaded address, so
  it simply re-creates the unit — which is why `docs/sso.md` warns against
  converging in the gap between removing the unit and editing the pin.) On that
  narrower box a converge **cannot bring the gate up**: measured, on a real
  manager, as the run failing to start the service. VIDE reports it and continues
  rather than dying, because the refusal's contract is that nothing was written
  and the rest of the run proceeds. **Read that message with care, though — one of
  its sentences is currently wrong**, and it is recorded here rather than quietly
  corrected because the fix is a code change: it tells the operator the address is
  still held, and by the time it prints, the run's own `systemctl enable` has
  reloaded the manager, so the reservation may be holding nothing. Check with
  `lsof -nP -iTCP:<port> -sTCP:LISTEN` before assuming the address is safe, and
  restore the gate with `systemctl restart vide-oauth2-proxy.socket
  vide-oauth2-proxy.service` once the unit file is back.
  *What it takes:* a shell as any local account — no VIDE instance, no role, no
  sudo. *What it gets:* local pre-authentication access to the fleet's
  authorization endpoint, with headers of its choosing from inside the trusted
  CIDR. The bind is closed; this is what the reservation does not reach.
  *Today:* keep `vide doctor` on a schedule and read the **reservation** row
  rather than the proxy-unit row — a proxy that is down does not mean the address
  is free, and a free address is the thing to page on.
  *Removed by:* moving the hop to a permissioned unix socket, which closes the
  connection too. Deferred deliberately: it changes the `auth.<parent>` block you
  pasted into your own Caddyfile, and a version that frees this TCP port while your
  Caddyfile still names it would be worse than what it fixes — a squatter would
  then serve `/oauth2/start` under your TLS.
- **A password instance's port — open.** Nothing reserves it: the socket unit
  above holds the fleet's authorization hop, and nothing else. Once an instance
  is stopped or destroyed while
  your site block still names its port, any local account may bind it — including
  VIDE itself, which will hand it to the next instance you create. Remove the site
  block and reload before, or soon after, you destroy an instance.
- **An SSO instance user can still reach other instances, and your Caddy's admin
  socket, during a start she triggers.** `/run/vide/<user>` has to be writable by
  that user for code-server to bind its socket there, so she owns it from unit
  start until root freezes it — and an owner can always `chmod` a directory, which
  hands `caddy` traversal as *other*. She controls the `ExecStart` binary, so she
  chooses how long that lasts; one request through Caddy during it survives the
  refusal that follows, because Caddy pools connections per upstream address.
  **Expect no evidence:** if she puts a genuine socket of her own back before the
  freeze, the unit's check passes, the instance goes active, nothing is logged,
  the directory is wiped at the next stop, and `vide doctor` reports health.
  *What bounds it:* the window is the start she triggers and nothing wider — the
  directory is `0700` and the `vide-proxy` grant happens only after root owns it,
  so the steady state between starts is closed. *Today:*
  under SSO, co-locate only mutually trusting users; this is the sharpest form of
  the co-tenancy rule below and not a softer one. *Removed by:* giving Caddy a
  path in a directory the instance user never owns, so the address she can rewrite
  and the address Caddy dials stop being the same one.

All three are described with their mechanism in
[`docs/threat-model.md`](docs/threat-model.md)
§ *Addresses VIDE does not own — and the one it now reserves*.

## Out of scope

**Upstream projects.** code-server, oauth2-proxy, Caddy, Node.js and pnpm are
installed by VIDE but not maintained here. Report defects in them upstream — that
is where a fix can actually happen. VIDE's docs cite an open code-server
authentication defect and enforce a minimum oauth2-proxy version precisely because
those live upstream.

**Trusting three upstream installer scripts, which VIDE runs unverified.** Node
(via nvm), pnpm and code-server are installed by fetching each project's own
`install.sh` and executing it — nvm's and pnpm's **as root**, code-server's as
the instance user. There is no checksum and no signature on any of the three, so
whoever controls `get.pnpm.io`, `code-server.dev`, or the `nvm-sh/nvm` tag VIDE
pins reaches your box with that privilege. This is a deliberate delegation, not
an oversight, and it is the largest trust VIDE extends to anyone: report it as a
discussion, not as a vulnerability. What *is* in scope here is VIDE weakening the
transport underneath it — every fetch must stay https with certificate and
hostname verification, a TLS 1.2 floor, and redirect-downgrade to http refused
(`src/vide/net.py`); a path that bypasses that is a finding. So is any *direct*
artifact download that loses its pin: the oauth2-proxy tarball is checked against
its published sha256 behind a hard CVE floor, and the JetBrains Mono faces
against sha256 values committed in this repository.

**Documented, accepted trade-offs.** These are design decisions with reasoning in
[`docs/threat-model.md`](docs/threat-model.md), not undisclosed defects. Reporting
them is welcome as a discussion; they will not be treated as vulnerabilities:

- The perimeter (TLS, DNS, IP-whitelist) is the operator's reverse proxy.
- An IDE with a shell is a shell; extensions and tasks run as the run user.
- Workspace Trust is disabled by default, with a per-instance knob to restore it.
- Co-tenancy is shared trust — users on one box are not isolated from each other.
  A root-capable co-tenant can forge fleet-wide SSO sessions, and under SSO every
  instance user holds a shell by design. Closing your Caddy's admin API
  (`docs/sso.md`) is the operator's half and is necessary; moving it to another
  *port* is not a fix — the endpoint is still unauthenticated, just elsewhere, and
  `vide doctor` only probes 2019. What your Caddy *dials* is a separate question
  from who may command it, and it is answered in `docs/threat-model.md`.
- The SSO cookie is issued for the whole parent domain and is a fleet-wide
  authentication artifact.
- A root instance has uncontained blast radius; that is what the typed-`ROOT`
  ceremony is for.

**Anything requiring privilege you already have.** Enumerating paths, ports, modes
or unit names from a shell on the box is not a finding — those are published on
purpose so the claims about them can be checked.

## How security-relevant updates are announced

VIDE enforces a minimum `oauth2-proxy` version and `vide doctor` compares the
installed proxy against the latest upstream release, pointing at
`vide upgrade-sso` when it is behind. That check is the advisory channel for the
one component VIDE version-pins. If the floor moves, it moves in the code with the
CVE named at the constant, and `vide doctor` goes red on boxes below it — so the
box tells the operator, rather than a mailing list they are not on.
