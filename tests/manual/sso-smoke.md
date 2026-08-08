# Manual SSO smoke — the standing gate for what the hermetic tiers cannot reach

The `tests/sso-mode/` gate runs a REAL oauth2-proxy, a REAL Caddy and a fake
OIDC provider, so login / whitelist / revoke / rotate all have hermetic teeth.
What it CANNOT reach is Google itself, a real browser, real wildcard DNS/TLS,
and the real terminal. This checklist covers exactly that residue. Run it on a
disposable box with a real domain, and record the result wherever the change that
declares the SSO slice done is reviewed.

Every line has an expected observation. A deviation is a finding against the
implementation — never a reason to soften this list. Cross-references to
`tui-smoke.md` mean "the invariant there still holds"; don't re-walk it here.

## Prerequisites (all external — verify BEFORE any checkbox counts)

- [ ] A real registrable domain with **wildcard DNS** (`*.example.com`) and
      **wildcard or per-name TLS** already served through YOUR Caddy.
- [ ] A **Google Cloud OAuth client** (Web application) whose consent screen is
      published **"In production"** — NOT "Testing". In Testing, only
      hand-listed test users can log in, so `vide allow` alone silently strands
      everyone else at a Google-side `access_denied` that VIDE cannot see. With
      only openid/email/profile scopes, publishing needs no verification review.
- [ ] The redirect URI `https://auth.<domain>/oauth2/callback` registered on
      that client (the ONE URI VIDE ever needs — instances never touch it again).
- [ ] **TWO** Google accounts: one you will whitelist, one you will not (the
      wrong-account and deny paths need a real second identity).
- [ ] oauth2-proxy ≥ 7.15.2 reachable (VIDE installs it; the floor is enforced).
- [ ] The box has **no VIDE reservation unit** — `ls /etc/systemd/system/vide-oauth2-proxy.socket`
      → absent. The fleet's authorization port is held by a systemd socket unit,
      and a box that already has one is not the first-install box §0 and §1
      describe. §0's baseline checks it too.

**What this list is for.** The
host-smoke tiers (`tests/host-smoke/`) now walk the reservation on a real
rootful systemd — a first install writes, enables and starts the socket unit, a
reboot re-freezes the instance socket directories, and `tests/sso-mode/` §16d
walks all four move refusals end to end against a real manager. **Do not re-walk
any of that here.** What is still out of every tier's reach, and therefore what
the rows below add: real Google, a real browser, real wildcard DNS/TLS, the real
terminal — and the one artifact no tier can own, **the operator's own Caddyfile**.

## 0. Refusal before mutation (walk FIRST, on the PRISTINE box)

The hermetic tiers assert this (unit I8 + the sso-mode gate); a real box is where
"untouched" is not a mocked Executor's word. Walk it BEFORE §1 — after §1 the
shared proxy is provisioned, so the missing-credential cells cannot be observed
here at all.

- [ ] Baseline (record the output):
      `id vide; getent group vide-proxy; ls -d /etc/vide /opt/vide 2>&1; dpkg -s argon2 | head -1;
      ls /etc/systemd/system/vide-oauth2-proxy.{service,socket} 2>&1`
      → user absent, group absent, no such dirs, **neither proxy unit present**.
      The socket unit is the one artifact whose accidental survival would make §1
      a *second* install wearing a first install's clothes.
      **Record argon2's state rather than expecting a particular one.** Asserting
      "argon2 not installed" here would be asserting a fact about the disk: many
      baseline images ship it, and the very first checkbox would then produce a
      finding against the implementation for something it did not do. What the rows
      below assert is that the refusals did not CHANGE it, which is the claim that
      has teeth either way; `tests/host-smoke/run.sh` phrases its own row
      `argon2 state unchanged (present)` for the same reason.
- [ ] For EACH of `--fqdn`, `--sso-client-id`, the secret (`--sso-secrets-stdin`),
      `--sso-allow` in turn: `sudo ./install.sh --no-gui --auth sso …` with exactly
      that one input omitted → `EX_USAGE` (64) NAMING the omitted flag; no hang;
      no value echoed.
- [ ] Also an **upper-case fqdn** (`--fqdn U.<domain>`): a `ConfigError` (78)
      naming the DNS-name shape — NOT a late renderer death after mutation.
- [ ] After EACH refusal, re-run the baseline → **byte-identical to pristine**: no
      `vide` user, no `vide-proxy` group, no `/etc/vide` (so no
      `/etc/vide/sso/fleet.env`), no `vide-oauth2-proxy.service`, **no
      `vide-oauth2-proxy.socket`**, argon2 in whatever state you recorded above and
      not a different one. A single artifact
      present here is a finding against the implementation, not a reason to soften
      this list. The socket unit earns its own mention: it is written by the same
      converge that writes the service, so a refusal that leaked it would leave the
      box holding the fleet's authorization port with nothing configured to serve
      on it.
- [ ] Retry: adding ONLY the omitted flag makes the same command succeed — with no
      `vide destroy`, no hand-removal of half-provisioned state.

## 1. First SSO install (fresh box, real terminal)

- [ ] `sudo ./install.sh` → wizard opens; the auth-mode screen shows two rows,
      **"Per-instance password" preselected**. Choose "Passwordless — Google SSO".
- [ ] Empty FQDN → the field inline re-asks ("SSO needs a real public name");
      enter `u.<domain>`.
- [ ] The shared-domain confirm shows the derived `.<domain>` and the
      `auth.<domain>` login-service name.
- [ ] client_id field is VISIBLE, client_secret field is MASKED. A deliberately
      mangled secret paste (drop the `GOCSPX-` prefix) → "does not look like…"
      re-ask, never silently accepted.
- [ ] ONE whitelist email asked; the NORMALIZED (lowercased) form is echoed.
- [ ] Summary shows the socket path, the whitelist recap, the 30-day session
      line, the FLEET-WIDE sign_out wording, and NO "SHOWN-ONCE password"
      promise in the "Enter closes…" copy.
- [ ] The client secret NEVER appears: not on the pane, not in `l` full-log
      view, not in the post-exit replay, not in the scrollback (grep it).
- [ ] After Enter: the pasted shell block + the shared auth block are in
      scrollback; paste both into YOUR Caddy; `usermod -aG vide-proxy caddy`
      per the printed instruction, then **restart caddy once**.
- [ ] **The shared auth block goes in ONCE**, and it should be three lines:
      a site header and an `import` of `/etc/vide/sso/caddy/auth.caddy`. If what
      you are pasting is ~100 lines of routing and inline HTML, you are on an
      older build — the body lives in that file now and VIDE keeps it current.
      It is still not per-instance, and §5 below is where a second instance tempts
      you to add a second copy — caddy answers `ambiguous site definition` and
      refuses **the entire config**, taking down every site you serve, VIDE's and
      your own. `caddy validate --config /etc/caddy/Caddyfile` before you reload,
      every time.
- [ ] The file that block imports, and the pages it serves, are really there:
      `sudo ls /etc/vide/sso/caddy/auth.caddy /etc/vide/sso/caddy/pages/` →
      `sign-in.html` and `signed-out.html`. A valid config importing a body whose
      pages are missing serves 404s on the fleet's login host.
- [ ] The reservation exists and is HELD before any browser is involved:
      `systemctl is-enabled vide-oauth2-proxy.socket` → `enabled`,
      `is-active` → `active`, and `sudo ss -lntp 'sport = :4180'` shows
      `("systemd",pid=1,…)` on the address. A first install starts it, so this is
      true immediately rather than after the next restart.
- [ ] Browser: visit `https://u.<domain>` → Google consent → login with the
      whitelisted account → the IDE loads. `--prompt=select_account` shows the
      account chooser.

## 2. Interrupts (real terminal) — SAME pristine-box dependency as §0

Walked 2026-07-27 and found the hard way: the credential screens exist only
while the shared proxy is **not yet provisioned**. Once §1 completes, an SSO
install for a new user *joins* the existing proxy and never asks — so the two
Ctrl-C points below become unreachable on that box. Walk §2 (and §4's first two
bullets) **before** §1, or on a re-restored box. Both abort before mutation, so
they leave the box pristine and cost nothing to walk first.

- [ ] Ctrl-C at the secret field → abort → the resume note carries `--auth sso`
      and `--sso-client-id <id>` (if it was ratified) but **never the secret**.
- [ ] Ctrl-C at the whitelist field → the resume note carries no `--sso-allow`
      (the pasted command re-asks it).
- [ ] A pasted resume command actually re-solicits the secret on stdin.

## 3. The gate (`--no-gui` parity)

- [ ] A bare `sudo ./install.sh --no-gui` (no `--auth`) still runs the
      byte-familiar PASSWORD contract (regression check).
- [ ] Full SSO install via `--auth sso --sso-client-id … --sso-secrets-stdin`
      with a heredoc supplying `VIDE_SSO_CLIENT_ID=`/`VIDE_SSO_CLIENT_SECRET=`.
- [ ] Missing-input refusals are walked in **§0 on the pristine box** — on THIS
      box the shared proxy is already provisioned, so the credential asks are
      legitimately skipped and this section cannot observe them.
- [ ] Sticky-proxy trap: on THIS box (proxy provisioned by §1) an SSO install for
      a NEW user that omits the secret must NOT succeed silently — it either names
      the flag or explicitly narrates joining the existing shared proxy (no
      credentials needed for this instance). `sha256sum /etc/vide/sso/proxy.env`
      is UNCHANGED either way (the cookie secret is never re-minted).
- [ ] `TERM=dumb sudo ./install.sh --auth sso …` → the decision-6 refusal whose
      paste-ready twin shows the SSO flag shape (with `--sso-secrets-stdin`,
      never `--sso-client-secret`).
- [ ] `ps` / `/proc/<pid>/cmdline` never show the client secret at any moment.

## 4. Paste (real terminal — the tiers pin the parser; the human pins the tty)

- [ ] Bracketed paste into the client_id AND secret fields survives byte-exact
      (verify by a successful login). **Needs an unprovisioned box — see §2.**
- [ ] Plain paste (on a terminal that does not do bracketed paste) also survives.
- [ ] A multi-line accidental paste does NOT self-submit any field.
- [ ] Paste onto a MENU does nothing.
- [ ] Inside tmux: the paste path still works; terminal sane afterwards
      (cross-ref `tui-smoke.md` §1 "terminal is sane").

## 5. Join-existing (second instance, no Google setup)

- [ ] A second SSO install for another user shows "Join existing SSO (.<domain>)"
      copy and NO credential screens; its twin has no secret flags and is fully
      paste-ready.
- [ ] An FQDN outside the parent domain → refusal naming the parent domain.
- [ ] **The paste trap this section exists to catch, and no tier owns your
      Caddyfile.** `vide info <second-user>` prints that user's site block **and
      re-prints the shared auth block**. Paste only the per-instance half; you
      already have the shared one from §1. If you append both, caddy refuses the
      whole config with `ambiguous site definition` and every site on the box goes
      down until you delete the duplicate. Confirm with
      `grep -c '^auth\.<domain> {' /etc/caddy/Caddyfile` → **1**, then
      `caddy validate` → `Valid configuration`, then reload.
      (VIDE's own host-smoke tier made exactly this mistake on 2026-08-08 and
      spent a full run reading the dead front door as twelve lost sessions.)
      **The trap is smaller than it was and worth understanding, not just
      avoiding.** The re-print used to be the ONLY way a changed shared block
      reached an installed box, which is why it happens at all; that reason is
      gone — VIDE rewrites the imported body itself now. What is duplicated if you
      paste twice is three lines naming no port, so the failure is a config Caddy
      rejects outright rather than a second copy of a login flow quietly aimed
      somewhere. Loud beats subtle, but it still takes the box down.

## 6. Existing-instance journeys (SSO)

- [ ] Re-run the wizard for an SSO user → the menu describes it as "socket", the
      **Rotate row is ABSENT**, and the title carries the "rotate-sso is
      box-wide" hint.
- [ ] `sudo vide rotate <sso-user>` → StateError naming `rotate-sso`.
- [ ] A password instance on the same box still shows its Rotate row (mixed
      fleet).

## 7. Fleet behaviors (two real subdomains + two accounts)

- [ ] Shared cookie: log in on instance A, open instance B (both whitelisting
      you) → no second login.
- [ ] `sudo vide revoke <you> <B>` → B answers 403 for you; A still 200.
- [ ] Visit `https://auth.<domain>/oauth2/sign_out` → BOTH instances' sessions
      dead (fleet-wide); confirm the summary/snippet copy said so.
- [ ] `sudo vide rotate-sso` → every live session dies; a fresh login works.
      From the browser that was ALREADY signed in, expect exactly one refusal
      first: upstream answers 403 "CSRF token mismatch, potential attack"
      because that browser's login cookie was encrypted with the old secret.
      `rotate-sso` warns about this before you meet it; a plain reload gets in,
      with no cookie clearing. Walk the recovery in the SAME browser — a fresh
      profile silently skips the whole defect class (2026-07-27).
- [ ] `https://auth.<domain>/` (the page a post-rotation re-login lands on, since
      the proxy's own "Sign in" button carries no `rd`) → VIDE's "sign-in only —
      open your instance URL again" page, NEVER "404 page not found".
- [ ] The wrong (non-whitelisted) account → a 403 that is a dead end, with the
      sign_out URL reachable to switch accounts.
- [ ] `https://<instance>/vide` in the SAME browser → names the Google account
      you are signed in as and this instance; its Sign out link really signs you
      out of BOTH. On the instance you are NOT allow-listed for, the same URL
      answers 403 — never a friendly page carrying someone's address.

## 7b. Moving the fleet's authorization port (real browser, real outage)

Never walked by a human. `tests/sso-mode/` §16d proves the
four refusals against a real manager with a fixture IdP; what it cannot show is a
**real Google login surviving the move**, which is the only question an operator
actually has. Walk `docs/sso.md` § *Moving the fleet's authorization port* to the
letter and record deviations against the doc, not against this list.

This IS a scheduled fleet outage: `fd:3` is an index, so the two addresses can
never be live at once and every instance 502s from step 2 until step 5. Walk it
last, after §7, when signing everyone out costs nothing.

- [ ] `sudo vide doctor` **as root, and the qualifier is load-bearing**: run it
      unprivileged first. `<sso_dir>/caddy` is `0750 root:vide-proxy`, so an
      ordinary run cannot read it — `THE PIN MOVED` and the auth-block drift row
      are then **absent**, and an absent row looks exactly like a satisfied one.
      Confirm you can see the difference between the two runs before trusting
      either. Schedule your cron hook as root for the same reason.
- [ ] Edit the pin WITHOUT destroying the reservation → the next `vide allow` and
      the next converge both **refuse**, name both addresses, and change nothing.
      The doc's step 3 warns not to converge in the gap between the `rm` and the
      pin edit; if you land there anyway, the converge silently RE-CREATES the unit
      and you redo steps 2 and 3 in that order.
- [ ] `vide info <user>` prints the same three-line block it always prints, with
      **no caveat**, and that is correct rather than a regression: the block names
      no port, so it cannot carry a stale address whatever the pin is doing. Check
      the block really is portless — `vide info <user> | grep -c '127\.0\.0\.1'`
      → **0** for the auth block's lines. Earlier builds printed
      **DO NOT RE-PASTE** here; if you see that, you are testing an older tree.
- [ ] The converge on a moved-pin box **declines to advance the auth body** and
      says so, rather than repointing the login host at an address the gate is not
      serving. Confirm `/etc/vide/sso/caddy/auth.caddy` still dials the OLD port
      while the pin names the new one.
- [ ] Complete the move. `sudo vide doctor` → `proxy port: reserved` on the NEW
      port, `THE PIN MOVED` **gone**, and **no `instance bodies` row**. That third
      criterion is the one that catches a move which looks finished: every
      reservation row can be green while each instance still forward_auths to the
      old, now-free address.
- [ ] **Log in again in a real browser with a real Google account** — with no
      paste and no caddy reload of your own, because step 5's converge re-rendered
      the imported body and reloaded Caddy for you. This is the row the whole
      section exists for: everything above it is state, and only this one is the
      fleet working.
- [ ] The old address is free afterwards: `sudo ss -lntp 'sport = :<old-port>'`
      → nothing. Anything still holding it is a finding.

## 8. The proxy unit's hardening (the ONE thing the hermetic gate cannot run)

The sso-mode gate runs under ROOTLESS podman, which cannot set up the proxy
unit's namespace/seccomp/capability sandboxing — so the gate drops it in a
relaxation and proves only the FUNCTIONAL surface. `test_sso_units` pins the
shipped unit's hardening directives statically, but only a REAL rootful systemd
proves they let the Go binary actually run. Walk this on the disposable box:

- [ ] `systemctl start vide-oauth2-proxy.service` under the SHIPPED unit (no
      drop-in) → the service reaches `active (running)` and `/ping` answers.
      A 217/USER failure here means a hardening directive is incompatible with
      this kernel — trim it in the unit with a provenance comment, never in a
      drop-in.
- [ ] `systemd-analyze security vide-oauth2-proxy.service` → an "OK"/low
      exposure score (informational; the daemon is a root-of-trust network gate,
      so the score should be strong).

## 9. Observe-only (not walk-gating; the hermetic tiers pin the mechanism)

- Day-30 expiry UX: on a disposable box with a temporarily short `cookie_expire`,
  the re-auth is one redirect + one account-chooser click (no interstitial
  button page — `skip_provider_button`). NEVER shorten `cookie_expire` on a real
  fleet.
- The first real login URL: a glance for `prompt=select_account` behaving as set.
