# Threat model — what VIDE protects, what it does not, and what you accept

VIDE puts a browser IDE with a shell in front of a machine. That is the point, and
it means the interesting question is never "is it secure" but "what exactly is
holding the line, and what happens when each piece fails". This document answers
that. Nothing here is a caveat buried for legal comfort; each item changes how you
should deploy.

## The one-sentence version

VIDE binds code-server to loopback and hardens what it installs; **the perimeter
is your reverse proxy's job and VIDE cannot verify it**, and behind the perimeter
the IDE is a shell as the run user.

## Identity & privilege

- The instance runs as the **invoking user**. Run bare as `root` and VIDE warns and
  falls back to a dedicated non-root **`vide`** user (auto-created, with a
  generated login password and password-`sudo`; the `sudo` package itself is
  apt-installed if the box lacks it — minimal images ship only the group).
- `VIDE_ALLOW_ROOT=1` (or `VIDE_USER=root`) deliberately runs a **root instance**.
  It requires an extra typed confirmation and carries uncontained blast radius.
- **`vide` + password-sudo is threat-equivalent to root** under IDE compromise: a
  terminal or a malicious extension can capture the sudo password as it is typed.
  It is a speed bump, not containment. Treat any instance whose user can `sudo` as
  a root instance when you reason about blast radius.
- code-server opens at the run-user's `$HOME` and the whole filesystem is browsable
  within that user's permissions. That is the point — you are administering the box.

## The four deliberate trade-offs

### 1. The perimeter is yours

VIDE binds loopback only: a local TCP port in password mode, a local unix socket
under SSO. TLS, DNS and the **IP-whitelist** live in your Caddy.

What remains when the perimeter fails:

- **Password mode:** one 128-bit password, in front of a shell that can reach root
  via `sudo`.
- **SSO mode:** Google authentication plus the per-instance email allow-list — and
  nothing else, because code-server is set to `auth: none`. See
  [`sso.md`](sso.md).

The subdomain is not a secret in either mode: it appears in
Certificate-Transparency logs the moment you issue a certificate.

### 2. Always latest by default

VIDE installs the latest code-server. A bad upstream release has no built-in revert
lever — recovery is reprovision, or wait for upstream. Pin a known-good version per
run with `VIDE_CODE_SERVER_VERSION`, or set `VIDE_CODE_SERVER_PIN_LATEST=1` to
resolve the current latest tag and pin *that*, which makes the run reproducible
(resolved from the `/releases/latest` redirect — no GitHub API, no token; falls
back to unpinned latest if resolution fails).

### 3. Workspace Trust is disabled by default

VIDE launches code-server with `--disable-workspace-trust`. **This is a deliberate
weakening of an upstream security control**, recorded here rather than left to be
discovered.

With it off, opening a folder executes that folder's tasks, debug configurations
and extension code **with no prompt**, as the run user — which is `root` for a root
instance. The reason it is off: the prompt is modal, appears on first open of every
directory, and on a box you administer it is answered "trust" every time, which
trains the reflex the prompt exists to prevent. That reasoning does not make the
weakening go away.

Re-enable per instance with `VIDE_WORKSPACE_TRUST=1` in `/etc/vide/<user>.env`.

### 4. Three upstream installer scripts are executed unverified

VIDE does not install Node, pnpm or code-server itself. It fetches each project's
own `install.sh` and runs it:

| Script | Version selection | Verified? | Runs as |
|---|---|---|---|
| `raw.githubusercontent.com/nvm-sh/nvm/<tag>/install.sh` | pinned to a git **tag**, which upstream can move | no | **root** |
| `get.pnpm.io/install.sh` | always whatever that URL serves | no | **root** |
| `code-server.dev/install.sh` | always whatever that URL serves | no | the instance user |

**No checksum. No signature.** Whoever controls one of those three endpoints —
or, for nvm, whoever can move the tag — reaches your box with that privilege.
The instance user is not a meaningful containment boundary either: VIDE puts it
in the `sudo` group, and under `VIDE_ALLOW_ROOT=1` it *is* root.

This is a delegation, made deliberately: these installers know their own
projects' layout, platform matrix and upgrade quirks, and reimplementing them is
how you get a provisioner that breaks on the next upstream reshuffle. It is
still the largest trust VIDE extends to anyone, and it is stated here because
the alternative — leaving it to be discovered — is the thing this document
exists to prevent.

What is actually defended:

- **Transport.** Every fetch is https with certificate and hostname
  verification, a TLS 1.2 floor, and **redirect-downgrade to http refused** —
  `urllib`'s default handler permits that downgrade, so `src/vide/net.py`
  replaces it. Non-https URLs are refused outright, including ones an operator
  supplies via `.env`.
- **Staging.** Scripts are downloaded into a private `0700` directory and
  executed from the file, never piped into a shell: a truncated body cannot
  half-execute, and there is no `/tmp` symlink race against the `.part` sibling.
  The code-server installer, which runs as the instance user rather than root,
  needs to be readable by that user, so the directory and the file are widened
  to `0755`/`0644` **after** the download completes and the race is over. Both
  stay root-owned throughout: world-readable was never the hazard, and
  world-writable never happens.
- **Everything VIDE downloads directly** — rather than through someone's
  installer — **is pinned and verified.** The oauth2-proxy tarball is checked
  against its published sha256 behind a hard CVE floor (`FLOOR` in
  `src/vide/oauth2proxy.py`, not an overridable setting), extracted one known
  member at a time rather than by `extractall`. The JetBrains Mono faces and
  their `OFL.txt` are checked against sha256 values **committed in this
  repository**, each verified before it is installed. A mismatch aborts the
  step, so a partial set can land — the licence and any face checked before the
  failure — but never an unverified byte.

The asymmetry is real and worth naming: a decorative webfont is held to a
stricter standard than a script that runs as uid 0. Closing it means pinning
each installer at a revision and committing its expected hash — at the cost of
a repository edit every time any of the three ships a new installer.

## Secret handling

- A **128-bit** password is generated per instance, shown **once**, and only its
  **argon2id hash** is stored — in `~/.config/code-server/config.yaml`, `0600`,
  owned by the run user. No secret is ever written to the repo.
- That `config.yaml` is **secret-equivalent to a live session token**:
  code-server's stored hash doubles as a replayable cookie
  ([issue #7696](https://github.com/coder/code-server/issues/7696)). Hence `0600`,
  a distinct per-instance `cookie-suffix`, and `vide rotate` as the **only**
  revocation (regenerate + restart).
- Behind a loopback proxy code-server's own login throttle is blind — every request
  looks like `127.0.0.1` — so **password entropy is the primary control**.
- The OAuth client secret never touches VIDE's argv, VIDE's environment, or
  `.env`. It arrives per invocation via a masked prompt or `--sso-secrets-stdin`,
  and lands only in `/etc/vide/sso/proxy.env` (`0600 root:root`). It *is* in the
  proxy's own process environment, by design and by upstream's interface — that
  file is an `EnvironmentFile=` — which is why the file's mode, not its absence,
  is the control.

## Co-tenancy is shared trust, not isolation

**Only co-locate mutually trusting users.** Both modes leak across instances, but
not in the same way, and SSO's leak is the larger one:

- **Password mode:** any sudo-capable user on the box can read another instance's
  `config.yaml` and forge **that instance's** sessions.
- **SSO mode:** any sudo-capable user can read `/etc/vide/sso/proxy.env`, which
  holds the fleet's cookie secret, and mint a valid session for **any allow-listed
  address on any instance** — with no Google login, and therefore no trace on the
  Google side.

And under SSO an instance user holds a shell by design — `auth: none` plus an
integrated terminal is the product — so "no sudo" is not a high bar here.

### Addresses VIDE does not own — and the one it now reserves

**None of what follows needs sudo.** This section deliberately carries **no
count** of such paths: a count of *attacks* is not something anyone can keep
complete, and a reader takes a count as a promise. What **is** enumerable
is the set of **upstream addresses the config VIDE renders tells your Caddy to
trust**, because they are literals in one module. That set is stated below in
full; it is not a claim that nothing else exists, and two things that are not
addresses at all — your Caddy's admin API and this checkout — follow it for the
same reason, that they need no sudo either. There are three address shapes:

    reverse_proxy unix/<socket>          an SSO instance
    forward_auth  127.0.0.1:<port>       the fleet's one authorization hop
    reverse_proxy 127.0.0.1:<port>       the shared auth host, and a password instance

The heading is only half true of the second row. VIDE does not own that address
in the sense of the Caddyfile — the operator still pastes it — but **systemd
holds the bind**, so it is not an address anyone may take. Read the bullets below
for exactly how far that goes; "reserved" is a claim about `bind(2)` and about
nothing else.

Your Caddyfile is durable and trusts those addresses forever. Whatever answers at
one of them is what your hostname serves, under your TLS. So for each one the
question is not "who is allowed" — that part is answered per request, and it
holds — but **who decides what is at the far end.**

- **An SSO instance's socket — closed.** `/run/vide/<user>` is created for the
  instance user, because code-server has to bind the socket as that user. Once the
  socket exists, root takes the directory: `2750 root:vide-proxy`, verified after
  the fact, and the unit refuses to start if the path is not by then a plain,
  singly-linked socket owned by that user. Before that landed, the user could
  replace the socket with a symlink at any later moment and your Caddy would
  follow it — to another instance's `auth: none` IDE, or to your Caddy's own admin
  socket. **`vide doctor` reports the directory's posture**, because the freeze is
  per-activation state and a converge deliberately restarts nothing: after an
  upgrade, an instance that has not been restarted is still unfrozen. That row is
  readable without sudo — `/run/vide` itself is root-owned `0755` — though the
  socket's own permissions inside it are not.
  **The start is a narrower version of the same thing, and it is still open.**
  code-server has to be able to write that directory to bind at all, so the user
  owns it from unit start until the freeze — and the owner of a directory can
  always `chmod` it, which means she can hand `caddy` traversal as *other* without
  any group at all. She controls the `ExecStart` binary (it lives in her `$HOME`),
  so she decides how long that lasts, and one request to her own hostname during
  it is enough — Caddy pools per upstream address, so the connection outlives the
  refusal that then fails her unit. VIDE no longer *hands* her that window (the
  `vide-proxy` grant is part of the freeze rather than a step before it, and the
  directory is `0700` until then), so it is a window she must open and hold rather
  than one that is open on every start. It is not closed. **Under SSO, treat every
  instance user as able to reach every other instance and your Caddy's admin
  socket during a start she triggers.**
  *And expect no evidence.* The unit's refusal — the one line the box would ever
  print about this — fires only on the clumsy form, where the swapped path is
  still swapped when root looks. The form worth planning for puts a genuine socket
  of her own back before the freeze: the check then passes, the unit goes
  **active**, nothing is logged, nothing is left on disk (the directory is wiped
  at the next stop), and `vide doctor` sees a healthy instance — the whole window
  is `activating`, which every liveness check here treats as a non-event on
  purpose, because treating it otherwise would page on every ordinary restart. The
  pooled connection she opened is what persists, and she can renew it at any start
  she chooses. The only thing that closes this is moving the path Caddy dials into
  a directory she never owns; that change was **considered and declined** for this
  release, because it moves `VIDE_SOCKET` in every per-instance record and the
  unit fails closed on a record it does not recognise — so an upgrade would strand
  every SSO instance until each was re-converged, and no tier here can rehearse
  that.
  *The bound of the closure, stated precisely:* what the unit verifies is that the
  path holds a plain, singly-linked socket **owned by that instance user**. It does
  not verify that it is the socket code-server just bound. So the user can still
  choose her own upstream, by binding a socket of her own at the path before
  code-server does — which reaches her own instance, on her own hostname, as
  herself. That is self-directed and strictly narrower than what it replaced; it is
  written down because "closed" should mean something exact.
  *If you are ever recovering from this:* restoring the socket is not sufficient.
  Caddy pools connections per upstream address, so it keeps answering from the old
  far end until you restart it — and `vide doctor` goes green while it still does.
- **The fleet's authorization hop — the bind is closed once the box has migrated;
  the connect never was.** `units/oauth2-proxy.socket` holds `127.0.0.1:<port>` as
  PID 1 from `sockets.target`, which is reached before `basic.target` and therefore
  before any process an ordinary account could be running. The service is started
  from that inherited descriptor (`http_address = "fd:3"`) and never binds anything
  itself, so the address survives every event that used to free it: the
  OIDC-discovery gap at boot, `upgrade-sso`, `rotate-sso`, a crash loop, `kill -9`,
  and a compromised proxy that exits to hand the port to an accomplice. In-flight
  `forward_auth` sub-requests during a restart now queue in the accept backlog
  instead of being refused.
  *The bound of the closure, stated precisely:* what is guaranteed is that
  `bind(127.0.0.1:<port>)` fails for everyone but PID 1, for as long as the socket
  unit is `active (listening)` and its `ListenStream=` equals the pin
  `sso.fleet_port` returns — **and something is actually bound**. Those first two
  conditions can both hold with nothing held: a reload re-claims a serialized
  listening fd only for an address that still matches the reloaded configuration,
  so a changed `ListenStream=` plus a bare `daemon-reload` leaves the unit
  `active (listening)` holding neither address. `vide doctor` carries a NOT BOUND
  row for exactly that, and the third condition is the one it checks. Nothing else
  is guaranteed.
  *How the holder is established, and what that is worth.* VIDE reads the owning
  UID of the socket listening on the pinned address out of `/proc/net/tcp` — a
  kernel-formatted number in its own column, world-readable, so the check needs no
  root and is the same check on every box. It does **not** parse `ss -Htlnp`, and
  that is deliberate: the process column there renders
  `users:(("<comm>",pid=N,fd=M))`, and `<comm>` is whatever the process passed to
  `prctl(PR_SET_NAME)` — no privilege required — so a squatter naming itself the
  five characters `pid=1` can put a `1` into any regex over that line. What the uid
  read does not distinguish is uid 0 from uid 0: a root-level compromise already
  owns the box, and that is out of this closure's scope rather than inside it. It says nothing about who may
  `connect(2)`; nothing about `[::1]:<port>`, which is not reserved and must not be,
  because `fd:3` means "the first descriptor systemd passed" and a second
  `ListenStream=` repoints the gate; nothing about the port a loopback
  `VIDE_SSO_ISSUER_URL` names; and nothing about a box whose gate is running with
  a socket unit that has since been **changed** on disk — a converge writes and
  reports the new unit but deliberately restarts nothing that is up, so the
  address stays held under the OLD definition until `vide upgrade-sso`.
  *The connect surface is the residual, and it is not cosmetic.* Every local account
  can still speak HTTP to the fleet's authorization endpoint, and
  `trusted_proxy_ips = ["127.0.0.1/32"]` — the line rendered as the CVE-2026-40575
  mitigation — cannot separate Caddy from a neighbour, because on one box both are
  127.0.0.1. Whatever the proxy's pre-authentication surface is worth on the day you
  read this, it is worth it to every account on the box. Closing that means a
  permissioned unix socket, which moves the block the operator pasted — and which
  would also void `trusted_proxy_ips`, since a request over a unix socket has
  `RemoteAddr == "@"` and is never trusted on it. That is a separate, one-way
  decision and it is not this change.
  *When the reservation lapses:* `stop`, `restart`, `mask` or `disable` on the
  socket unit (root's hand — `mask` is the trap, it hands the address over rather
  than switching the gate off; `disable` is the quiet one, because the unit keeps
  holding the port right now and is simply absent from the next boot transaction);
  a socket unit that has itself gone to `failed`, which closes the descriptor; and
  an edited `ListenStream=` followed by `daemon-reload`, which does **not** rebind —
  it drops the old descriptor and binds nothing, so the unit reads
  `active (listening)` while both addresses are free.
  *Which of those `vide doctor` can see, stated exactly, because "a row for each"
  was written here before it was true:* `mask` and `disable` have their own rows;
  a `failed` or stopped socket unit falls into the migration-checklist row (NOT
  YET RESERVED) rather than a row of its own, which under-states it; the
  reload-orphan is the NOT BOUND row. **All of those are computed against the
  PIN.** A hand edit of `VIDE_SSO_PROXY_PORT` moves the pin itself, and then
  every one of those rows is asking about the new address while the fleet's real
  hop — the one the auth host's body still dials — is the old one. (That body is a
  VIDE-owned file imported by a three-line block, which is why the converge can
  be the thing that fixes it, and why it refuses to when fixing it would repoint
  the fleet at an address the gate is not serving.) That state is
  seen by exactly one row, `THE PIN MOVED`, which compares the port inside
  VIDE's own copy of the auth block against the pin and asks the kernel who
  holds the abandoned address. Without it the section is **green** on that box:
  reserved, uid 0, `/ping` answered, exit 0, every IDE 502.
  *What that row may claim about the holder, stated precisely, because it used to
  claim more than it had established:* it reports one of four answers, not a
  boolean. `/proc` unreadable — no claim in either direction. Nothing on the
  address — the open door. Held by **this box's own reservation** — which is the
  ordinary steady state of a correctly-refused box, and was previously reported
  as a stranger, sending the operator at the containment ladder whose every rung
  either takes the fleet down or frees the address their Caddyfile still dials.
  Held by something that is not our reservation. The benign answer is keyed on
  `certain == {0}` **and** our loaded reservation covering that address — never
  on `on_hop`, which folds in the `::` bucket any unprivileged account can create
  at will; keying it there would let an attacker-supplied signal turn an
  open-door row into a this-is-fine row, which is the inversion `HopHolders` was
  split apart to prevent.
  *A second row, for the state the first one cannot see:* `THE PIN MOVED` reads
  `auth.caddy`, VIDE's record of what it last emitted. The per-instance bodies are
  a different artifact with a different lifecycle. Every write that touches the
  allow-list re-renders them — `allow`, `revoke` and `destroy` all do — but on a
  moved-pin box those are precisely the writes that **refuse**, so the only lever
  left that re-renders them is `upgrade-sso`, and that one **fails soft**: it warns
  and returns rather than raising, which is correct (refuse the write, never the
  verb) and is exactly what leaves the bodies behind. Complete the documented move, skip or lose only that
  step, then finish the last one: `auth.caddy` is rewritten at the new pin, so
  `THE PIN MOVED` and the drift row both fall silent, every reservation row is
  green — and each instance still forward_auths to the old, now-free address. So
  the bodies are enumerated and compared against the pin, and the disagreement is
  part of the verdict. The answer to a fail-soft control is a sensor, not a raise.
  The enumeration walks the directory rather than the instance registry, because
  the operator's Caddyfile imports those paths **by name** and a body left behind
  by a destroyed instance is still imported.
  *And the bound on it, which is a real one:* that directory is `0750
  root:vide-proxy` and `doctor` is `needs_root=False`, so an unprivileged run
  cannot list it. `Path.glob` would have swallowed that error and yielded nothing,
  which the row would have read as "every body agrees" — so the directory is
  tested explicitly and the row reports `not observable` instead. That line is
  **advisory**: it does not fail the verdict, on the rule this section applies
  elsewhere that an unobservable property is not a fault. The consequence has to
  be said plainly rather than left as a nicety: an unprivileged `vide doctor
  --quiet` prints nothing and exits 0 over a half-applied move, because that
  channel emits `proxy_health`'s lines only when the verdict is false. **This row
  is a control only when doctor runs as root** — which is how the cron hook should
  be scheduled, and is what `docs/sso.md` now says at the step that depends on it.
  Making it fail the verdict instead would redden every unprivileged run on every
  healthy box, which is a different way to lose the same control.
  *And the same bound reaches further than this one row, which is worth stating
  once rather than per row:* `auth.caddy` lives in that same `0750` directory, so
  `THE PIN MOVED` and the auth-block drift row are **absent** — not merely
  advisory — from an unprivileged `vide doctor`. Every claim in this section about
  what doctor sees is therefore a claim about doctor **run as root**. An
  unprivileged run is a weaker instrument than it looks, because the rows it
  cannot compute do not announce themselves.
  *And that box is no longer reachable through any VIDE verb.* The two writes
  that used to follow the pin now refuse to: a converge will not re-render the
  socket unit onto an address other than the one the loaded reservation names,
  and `_render_all` will not repoint the per-instance authorization bodies unless
  the gate is demonstrably on the destination already — the reservation active,
  configured for it, and the socket there owned by uid 0 alone. (On a box with no
  reservation at all — one whose socket unit has been removed by hand — the proxy
  holding the port itself counts instead. That permit is gated on the reservation
  being ABSENT precisely because the account it trusts is the one with a
  pre-authentication surface: where a reservation does exist, a compromised gate
  could otherwise bind the new pin and vouch for itself.) So the edited pin
  is a steady, loudly-reported disagreement (`DRIFT` plus `THE PIN MOVED`) rather
  than a state the box walks into by converging and rebooting. Not *impossible*:
  root can still edit the unit by hand, which is why `THE PIN MOVED` stays. The
  supported forward path destroys the reservation first, so the consent is an
  `rm` rather than a `stop` — a `stop` happens for unrelated reasons and would
  otherwise ratify a pin edit nobody remembered making.
  *Which reader answers "is there a reservation here", and why the ORDER of the
  two is a security property rather than a style:* the manager is asked first and
  a positive answer always decides; the filesystem is consulted only when
  `systemctl show -p Listen` comes back empty. Inverting those two costs the hop.
  On a box where the operator removed the fragment and has not reloaded, the unit
  is still loaded and still holding the address — `show -p Listen` says so — and a
  file-first reader answers "no reservation here", permits the write, reloads, and
  systemd drops the descriptor it was holding and binds nothing in its place: VIDE
  releasing the fleet's authorization hop by its own hand, out of the function
  written to prevent exactly that. The filesystem tie-break is a plain stat rather
  than a manager word because `is-enabled` prints `not-found` for an absent unit
  only from systemd 253, while Debian 12 (252) and Ubuntu 22.04 (249) print
  nothing — a first SSO install on either would otherwise have refused to write
  its own socket unit. And presence is `exists() or is_symlink()`, so a **mask**
  counts as present: masking replaces the entry with a symlink to `/dev/null`,
  which is not a regular file, and on this unit masking does not switch the gate
  off — it gives the address away, which is not a state to permit a move over. An
  empty or unreadable fragment counts as present for the same reason: the reader
  that maps every `OSError` to `""` cannot tell "unreadable" from "absent", and
  absent is the one answer that permits.
  *One consequence, which a tier found rather than a reading:* the refusal can now
  decline with **no fragment on disk**, and on that box a converge cannot bring the
  gate up — measured as an exit 5 out of the run, not deduced. Both `systemctl
  enable` on the socket unit and the service's own `enable --now` are therefore
  tolerant of that one state, and the run says what happened and continues; the
  contract is "refuse the write, never the verb", and before this it was being
  broken three statements past the guard written for it. *And the cause is settled,
  by deduction from two measurements this tree already had rather than by a new
  one, because it matters:* a unit whose file has been deleted stays **loaded**
  until something reloads the manager — §16d-b of `tests/sso-mode/in-container.sh`
  measures exactly that — and a
  loaded unit satisfies `Requires=`. So the failure is impossible without a reload
  in between, and `systemctl enable [--now]` performs one before it starts
  anything, on every supported version. The converge's own `enable --now` of the
  service is therefore what unloads the reservation and closes PID 1's descriptor.
  **That is a defect and it is recorded as open:** on a box whose gate is already
  down, the same run first starts the still-loaded socket unit — binding the old
  address — and then reloads it away, and no row names it, because the unbound
  check is sampled before the reload and is keyed on a pin that has moved. On a
  box whose gate is up, the address survives on the running proxy's inherited dup
  until that process exits. The message printed in this state asserts the address
  is still held, which by then it may not be; verify with `lsof -nP -iTCP:<port>
  -sTCP:LISTEN` rather than trusting the sentence.
  *One consequence for the probe, which was the sharper half of this:*
  `proxy_answers` used to ask the PIN. On a refused box that is an address nobody
  is listening on, so `upgrade-sso` reported the fleet's gate dead — and handed
  the operator a binary-rollback procedure that undoes a CVE fix — while
  `rotate_sso` read the same silence as "the proxy rejected the new cookie
  secret", **restored the previous secret** and raised. The stolen-cookie kill
  switch un-burned the secret it was invoked to burn. It now probes the address
  the gate is actually serving on.
  *A separate detection worth naming, because the obvious reading of the holder
  check is that this state would be invisible:* an attacker who hands the
  LISTENING socket back while staying alive keeps serving every connection Caddy
  already had open, and every holder check goes green behind it. `vide doctor`
  reads the ESTABLISHED rows
  on the hop out of the same `/proc/net/tcp` table and raises the containment
  ladder when their owning uid is neither root's nor the proxy's. It is a POLL,
  not a stream — it sees the harvest only while a connection is still open — so
  it narrows the window rather than closing it.
  *If you are ever recovering from this:* the lever gained a unit — **name the
  socket explicitly**, and the reason is attribution rather than mechanism. A
  start job for the service does pull the socket in through its own `Requires=`
  and `After=`, and a socket unit starts straight out of `failed` (its trigger
  limiter is off), so the bind does happen. What you lose by not naming it is the
  ability to say afterwards *which* unit came up and who ended up on the address —
  so start the socket first, then let `vide doctor` settle the holder: it reads the owning
  uid from `/proc/net/tcp` and says `reserved` only when that uid is 0. If you
  would rather see it yourself, use a command whose pid comes from procfs rather
  than from a process-chosen string — `lsof -nP -iTCP:<port> -sTCP:LISTEN` or
  `fuser -n tcp <port>`. **Do not settle it by looking for `pid=1` in `ss -Htlnp`
  output:** the quoted name in that column is set by the process being reported, so
  a squatter can make it read `pid=1`, and a human skimming that line is more
  likely to be fooled than a regex was. Read the `pid=` field after the closing
  quote, or use one of the two commands above. And check `ss -Htnp` **without**
  `-l` too: an attacker that handed the listening socket back while staying alive
  is invisible to the listening form and still answering everything Caddy already
  had open.
- **A password instance's port — open in the same shape.** The record is removed
  when the instance is destroyed and the port returns to the allocator, but your
  pasted block still names it. A stopped, `down`ed or destroyed instance therefore
  leaves one of your hostnames pointing at a port anyone may bind — including VIDE
  itself, which will hand it to the next instance you create. Remove the site block
  and reload before, or soon after, you destroy an instance.
- **Caddy's admin API — the operator's half.** Unauthenticated on
  `127.0.0.1:2019` by default, and `POST /load` replaces the running config. The
  socket's mode decides which *process* may connect, not who may command it, and
  not what is at the far end of what that process dials. `docs/sso.md` says how to
  close it, and calls it a prerequisite rather than a hardening extra.
- **The checkout.** VIDE runs its own tree as root on every `sudo ./install.sh`
  and every `sudo vide`, and `.env` is root-equivalent in full — two of its
  installer URLs are fetched and executed as root, and **every** key in the file,
  named in the schema or not, is injected into the environment each root child
  inherits — so whoever can write the clone, or any directory above it, reaches
  root at your next converge without holding sudo at all. **Both doors refuse before
  any of this tree runs**: `sudo ./install.sh` and `sudo vide` carry the same
  check, byte for byte, ahead of the `exec` — duplicated rather than shared,
  because a helper file would live in the tree being judged. Each **walks** `src`
  and `units` rather than consulting a list of names, which is what a list cost:
  `src/vide/tui/` — imported as root on every wizard install — was missing from
  both of them for as long as the list existed.
  Two ceilings remain, and they are limits rather than defects to report. The gate
  asks "can a third party write this **now**", not "has one ever" — if the answer
  was ever yes the tree's *contents* are suspect and no permission change restores
  them, which is why the refusal tells you to re-clone, and to delete
  `__pycache__` if you repair in place rather than re-cloning. And it reads mode
  bits, so a POSIX ACL is invisible to it. Neither door defends against someone
  who can already rewrite the shim itself; what they buy is the far more common
  case where an ancestor, `.env`, or a source file is writable and the shim is
  not. Keep the clone out of `/tmp`, out of any shared-group tree, and out of any
  instance user's `$HOME` — that is what the gate is a backstop for, not a
  replacement.

**Under SSO, the authentication log is not an access log.** `oauth2-proxy` records
the identity it authorized, for the hostname it was asked about. Nothing anywhere
records the upstream that request was then sent to — the rendered blocks emit no
`log` directive, and code-server is `auth: none` and authenticates nobody.

So choosing SSO does not solve co-tenancy; it enlarges the blast radius of a
co-tenant who can reach root, and it gives every instance user a shell without one.
If you need real isolation between users, that is one box each, not one box with
two instances.

## What is out of scope, deliberately

- **Break-glass and recovery.** If VIDE falls over, reconnect to the VM yourself
  (SSH or your provider's console) and fix it. VIDE does not ship or manage sshd,
  and does not try to be the last way in.
- **The reverse proxy itself.** VIDE renders a snippet and verifies what it can
  reach locally. It never validates your TLS, your DNS, or your whitelist.
- **Anything inside the IDE.** Extensions, tasks and terminals run as the run user
  by design. VIDE does not sandbox them and does not pretend to.

## The two passwords — password mode only

When `install.sh` runs as bare root it creates a dedicated `vide` OS user. In
**password mode** that user ends up with two independent passwords, each printed
exactly once and never stored in plaintext:

- a **login/sudo password**, so `sudo` from the IDE terminal still challenges;
- a **code-server password**, which unlocks the web IDE.

`vide rotate <user>` regenerates only the code-server one.

**Under SSO neither password is set.** code-server is `auth: none`, and no login
password is generated, so the account's password stays locked. The account is still
created in the `sudo` group — which means:

> Running `passwd vide` on an SSO instance **enables password-sudo** where there
> was none. That converts the instance to the "threat-equivalent to root" case
> described above. Do it knowingly, or leave the account's password locked and use
> `sudo` from a root shell instead.

VIDE keeps no copy of either password. If you lose the login/sudo password on a
password-mode instance, reset it from a root shell with `passwd <user>`.
