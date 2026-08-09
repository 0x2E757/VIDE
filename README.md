# VIDE — Virtual IDE

Run one command on a Debian/Ubuntu VM and get a browser-based VS Code
(**code-server**) serving that box — a convenient alternative to plain SSH for
working on and administering the machine. VIDE deliberately does one thing:
**stand up a per-user, loopback-bound code-server under systemd.** How it is
reached from the outside is your reverse proxy's job, not VIDE's.

**Status: 0.1.0, no tagged releases yet.** The behaviour described here is
tested (see [`CONTRIBUTING.md`](CONTRIBUTING.md)) and meant to be relied on, but
expect breaking changes between commits and no guaranteed upgrade path. Run it
on a box you can reprovision.

```bash
# prerequisites — git fetches this tree; Caddy is the reverse proxy SSO mode requires
command -v git   >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y git; }
command -v caddy >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y caddy; }

# the install itself — clone this tree, then run the installer from inside it
sudo git clone https://github.com/0x2E757/VIDE /opt/vide-src
cd /opt/vide-src
sudo ./install.sh                 # interactive terminal → the curses wizard
sudo ./install.sh --no-gui --user alice --fqdn vide.example.com   # scripted
```

`install.sh` installs Node.js + pnpm (once, system-wide), installs code-server
(per-user, latest), generates a unique password, wires a `systemd` unit, brands
the editor (see below), and prints a ready Caddy snippet. Re-running is safe and
idempotent.

**Clone somewhere only you or root can write** — `/opt/vide-src` above, or your
own home; `/tmp` is not, and neither is anywhere an instance user can reach. VIDE runs
this tree as root, because whoever can edit the checkout owns your next
`sudo ./install.sh`. Both entry points refuse a third-party-writable checkout
before executing any of it, but that gate is a backstop rather than the rule: it
reads mode bits and not ACLs, and it asks whether someone can write *now* — never
whether anyone ever did, which no permission check can.
[`docs/threat-model.md`](docs/threat-model.md) states its limits in full.

## Reaching the IDE you just installed

**Installing does not make it reachable, on purpose.** code-server is bound to
loopback, so immediately after a successful install nothing outside the box can
open it. Two ways forward:

- **An SSH tunnel, for right now and for a single user.** Needs no DNS, no
  certificate and no proxy:

  ```bash
  ssh -L 8080:127.0.0.1:<port> you@the-box     # <port> from `vide ls`
  ```

  then open `http://localhost:8080`. Browsers treat `localhost` as a full secure
  context, so the IDE works normally. Under SSO the instance binds a unix socket
  instead of a port and this route does not apply.

- **A reverse proxy, for anything lasting.** You supply a domain, TLS and — in
  password mode — an IP-whitelist. `install.sh` prints a ready Caddy snippet and
  `vide info <user>` re-prints it. The contract is in
  [`docs/reverse-proxy.md`](docs/reverse-proxy.md); read it before exposing
  anything, because the perimeter is the half VIDE cannot verify.

## Two auth modes

Each instance is installed in ONE of two modes (`--auth password` — the default —
or `--auth sso`), immutable per instance (switching = `vide destroy` + reinstall):

- **Password** (default): a per-instance code-server password over a loopback TCP
  port. One 128-bit password in front of a shell that can reach root via `sudo`.
- **Passwordless Google SSO** (`--auth sso`): the instance binds a **unix socket**
  (no TCP port) behind ONE VIDE-managed, box-shared `oauth2-proxy`. Authentication
  is fleet-shared (one Google login, one `.<domain>` cookie); **authorization is
  per instance** via `vide allow` / `vide revoke`. code-server itself is set to
  `auth: none` — the proxy and your Caddy are the only gates.

  SSO has consequences a password instance does not have — a fleet-wide cookie
  that reaches your whole domain, fleet-wide sign-out, a shared proxy secret, and
  a revocation model that is not the cookie lifetime. **Read
  [`docs/sso.md`](docs/sso.md) before choosing this mode.**

  **And the one that decides whether this mode fits at all: SSO instances on one
  box are not isolated from each other.** An instance user gets a shell (that is
  what an IDE is), and during a start they trigger they can reach another
  instance's `auth: none` IDE and your Caddy's admin socket — a known, open
  limitation with no evidence left behind, disclosed in
  [`SECURITY.md`](SECURITY.md) with what would close it. So SSO is for **one
  tenant, or people who already trust each other with root on this machine.** If
  you need users isolated from one another, that is one box each.

## The install wizard

On an interactive terminal (stdin AND stdout are real ttys) `install.sh` /
`vide install` opens a fullscreen curses wizard that drives the same install
step-by-step: it discovers the box, asks only at the real forks (target user,
existing-instance action, keep-vs-reinstall toolchain, password generate-vs-type,
FQDN), and streams the live log in a bottom pane.

Redirected or piped stdio (`> file`, `| tee`, CI, cron, `ssh -T`) falls back to
the plain non-interactive flow automatically; `--no-gui` forces that explicitly,
and every wizard question has an argv/env twin (the summary screen prints the
exact equivalent command). A terminal that cannot host curses (`TERM=dumb`,
terminfo missing) is refused with a paste-ready `--no-gui` command instead of a
broken screen.

Everything durable — the full log, the SHOWN-ONCE password, the Caddy snippet —
prints to the normal terminal buffer only after the wizard closes, so it survives
in scrollback. If the ssh session drops mid-install: re-run to converge; a
password generated but never shown is recovered with `vide rotate <user>`. An
operator-chosen password comes via the wizard's masked field or
`--password-stdin` (one line on stdin; min 8 chars) — never argv or env.

## What you are accepting

Four trade-offs are deliberate and none of them is hidden. The reasoning, the
blast radius of each, and the co-tenancy model are in
[`docs/threat-model.md`](docs/threat-model.md); the short version:

1. **The perimeter is your proxy's, and VIDE cannot verify it.** TLS, DNS and the
   IP-whitelist live in your Caddy. The subdomain is public anyway
   (Certificate-Transparency logs).
2. **Always latest by default.** VIDE installs the latest code-server; a bad
   upstream release has no built-in revert lever. Pin with
   `VIDE_CODE_SERVER_VERSION`, or set `VIDE_CODE_SERVER_PIN_LATEST=1` to resolve
   the current latest tag and pin *that*.
3. **Workspace Trust is disabled by default.** Opening a folder runs that
   folder's tasks, debug configs and extension code with no prompt, as the run
   user. Re-enable per instance with `VIDE_WORKSPACE_TRUST=1` in
   `/etc/vide/<user>.env`.
4. **Three upstream installer scripts are executed unverified.** VIDE delegates
   Node, pnpm and code-server to their projects' own `install.sh`, and runs them
   with no checksum and no signature: nvm's and pnpm's **as root**, code-server's
   as the instance user (who is in the `sudo` group). Whoever controls
   `get.pnpm.io`, `code-server.dev`, or the `nvm-sh/nvm` tag VIDE pins gets what
   that script gets. Every fetch is https with certificate and hostname
   verification, a TLS 1.2 floor, and redirect-downgrade to http refused
   (`src/vide/net.py`) — so this is upstream trust, not transport exposure.
   Artifacts VIDE fetches *directly* rather than through someone's installer are
   pinned and verified: the oauth2-proxy tarball against its published sha256
   plus a hard CVE floor, and the JetBrains Mono faces against sha256 values
   committed in this repository.

## Multi-instance

One instance per OS user via the `code-server@<user>` template unit, each on its
own loopback port. Run for several users (e.g. `vide` and, deliberately, `root`)
and route each to its own subdomain in your Caddy.

**Several instances is not several tenants.** Users on one box are not isolated
from each other in either mode — in password mode any sudo-capable user can forge
another instance's sessions, and under SSO an instance user needs no sudo at all
(above, and [`SECURITY.md`](SECURITY.md)). Multi-instance is for one person's
several roles, or for a team that already shares this machine's root. It is not a
boundary between people.

## The `vide` CLI

```
vide help                # the same list, from the binary
vide --version           # VIDE's own version (quote it in a bug report)
vide install [flags]     # what `sudo ./install.sh` execs; same flags
vide ls                  # all instances: user, active, port, code-server version
vide status [user]       # state + /healthz + recent logs
vide info <user>         # re-emit the Caddy snippet + port
vide down <user>         # stop + disable (keeps data)
vide destroy <user>      # remove code-server/config/port record (NOT $HOME)
vide upgrade <user>      # reinstall latest code-server, then restart (decoupled)
vide rotate <user>       # regenerate password + cookie-suffix, restart (kill switch)
vide doctor [--quiet]    # read-only health: toolchain + instances + shared SSO proxy
vide toolchain [--force] # (re)install/repair the shared Node+pnpm toolchain (no restart)
vide allow <email> <user>   # permit an email on ONE SSO instance's whitelist (reloads caddy)
vide revoke <email> <user>  # remove an email from ONE SSO instance's whitelist (reloads caddy)
                            #   both take --force-restart to restart the instance too
vide rotate-sso          # rotate the shared SSO cookie secret (signs out ALL users, ALL instances)
vide upgrade-sso         # upgrade + restart the shared oauth2-proxy binary
```

Install and upgrade are **decoupled**: adding or converging one user never
restarts another user's live session. Upgrading is the only routine that restarts,
and only the targeted instance.

## Branding — what VIDE changes inside the code-server tree

Not purely cosmetic bookkeeping: VIDE modifies files upstream owns, and you
should know which before you debug a diff.

- **Both favicons** in `<code-server>/src/browser/media` are replaced with
  VIDE's mark, so a tab full of instances is identifiable.
- **Three JetBrains Mono `.woff2` faces plus its `OFL.txt`** are downloaded from
  `raw.githubusercontent.com/JetBrains/JetBrainsMono` at a pinned tag, each
  verified against a sha256 committed in this repository (a mismatch aborts the
  webfont step; the licence and any face verified before it have already been
  placed, so a partial set can land — never an unverified one), and placed
  beside the favicons. The
  licence ships with them because OFL-1.1 requires it of every copy.
- **`workbench.html` is patched** to load those faces.
- **`settings.json` is seeded once, only if absent** — font stack, ligatures on,
  and code-server's chat/agent surface off. Never converged, so it is yours the
  moment it exists; an instance that already had one gets none of this.

All of it is best-effort and caught separately: a font mirror being down leaves
the favicon in place and never fails an install. These four download URLs are
**not** overridable from `.env` — they are pinned by sha256, so a redirected
base could not satisfy the pins anyway.

## Durability

Built to keep working for years. The only breakage accepted over time is an
upstream download URL moving — and of those, the three **installer** URLs are
the ones you can repair yourself from `.env`, without waiting for a release.

- Every converge (`install.sh` re-run or `vide toolchain`) re-heals the toolchain
  **without the network** — re-points the `node/npm/npx/pnpm` symlinks from the
  on-disk layout and re-applies world-traversable perms plus the per-user
  `PNPM_HOME` drop-in. Both the pnpm binary location and the per-user global-bin
  subdir are **resolved from the install, not hard-coded**, so a future pnpm layout
  change is healed by a re-converge rather than a code edit.
- The three installer URLs are **overridable constants**: set them in `.env` and
  re-run the verb that reads the one you changed —
  `VIDE_NVM_INSTALLER_URL` / `VIDE_PNPM_INSTALLER_URL` → `sudo vide toolchain`;
  `VIDE_CODE_SERVER_INSTALLER_URL` → `sudo vide upgrade <user>`, per instance.
  (They are genuinely different verbs: `toolchain` converges Node and pnpm only,
  so pointing it at a moved code-server URL exits 0 having done nothing.) A moved
  URL fails **fast and loud** naming the variable to set; transient faults
  (5xx/timeout/429) retry with backoff.
- `vide doctor` distinguishes "IDE up" from "workspace toolchain healthy" (code-
  server runs on its own bundled Node), so a dead shared Node is not a false green.

## State model

- Per-instance state is **derived from the system**, never from the repo:
  `systemd code-server@*` units + `/etc/vide/<user>.env` (the root-owned port
  record). `.env` in the repo holds per-invocation inputs plus a few fleet-scoped
  settings — and it is **root-equivalent**: some of its rows are fetched and
  executed as root, so VIDE refuses to run from a checkout other people can write
  (see [`.env.example`](.env.example) and
  [`docs/threat-model.md`](docs/threat-model.md)).
- Break-glass / recovery is **out of scope**: if VIDE falls over, reconnect to the
  VM yourself (SSH or your provider's console) and fix it. VIDE does not ship or
  manage sshd.
- Rolling a change back is `git revert` + re-converge — see
  [`docs/rollback.md`](docs/rollback.md).

## Where the reasoning lives

**In the source, next to what it describes.** VIDE's modules carry long
doc-comments explaining *why* each mechanism is shaped the way it is, and those
comments are the design record — the documents in `docs/` state outcomes and
contracts, not construction history. If you are evaluating a decision, read the
module; if you are looking for what VIDE promises you, read here and `docs/`.

## Layout

The implementation is **Python (stdlib-only, ≥3.10)**; the two entry-point paths
are thin bash shims and are deployed contract (every installed box's
`/usr/local/bin/vide` symlink points at `./vide` — the path may never move or
become a directory).

```
install.sh              # bootstrap shim: ensures python3, execs `vide install`
vide                    # CLI shim: execs the Python entry point
src/vide/               # the implementation (executor, config, node, secrets,
                        #   codeserver, sysd, registry, ports, preflight, cli,
                        #   sso, oauth2proxy, branding, ...)
units/code-server@.service   # systemd template unit (shipped verbatim)
units/code-server-launch     # launcher wrapper (resolves $HOME per instance; stays shell)
units/oauth2-proxy.service   # the shared SSO gateway unit (hardened, static)
units/oauth2-proxy.socket    # PID 1 holds the fleet's authorization port from sockets.target
docs/reverse-proxy.md   # the transport contract for your Caddy
docs/sso.md             # the SSO mode in full: cookie scope, revocation, blast radius
docs/threat-model.md    # what VIDE protects, what it does not, and what you accept
docs/rollback.md        # the rollback runbook (git revert + re-converge)
src/vide/tui/           # the curses install wizard (adapters over the same sequencer)
tests/unit/             # Python unit tier (stdlib unittest; seconds, no root)
tests/integration/      # black-box container tier (the acceptance arbiter)
tests/parity/           # durable-artifact shape diff against a frozen golden
tests/vide-branch/      # black-box gate for the dedicated-'vide' journey
tests/sso-mode/         # black-box SSO gate (real proxy + caddy + fake OIDC IdP)
tests/host-smoke/       # gates that need a real disposable box (incl. rollback)
tests/manual/           # the two human gates: wizard rendering, real-Google SSO
```

## Requirements

- **Platform:** Debian or Ubuntu with systemd, on `x86_64`/`amd64` or
  `aarch64`/`arm64`. Anything else is refused before the first change is made:
  upstream Node.js and code-server ship no standalone binary for 32-bit ARM
  (`armv7l`, e.g. 32-bit Raspberry Pi OS), `i686`, or `riscv64`.
- **Privilege:** run as root (via sudo).
- **A reverse proxy, which you supply and VIDE never installs or edits.** The
  quick start's prerequisite line apt-installs Caddy when it is absent — that
  is still you supplying it, before `install.sh` runs; no VIDE code installs a
  proxy. In password mode any proxy will do — VIDE only prints a snippet.
  **SSO mode structurally requires Caddy**, because `vide allow`/`revoke`
  rewrite a Caddy config file and reload it through Caddy's admin API on
  `127.0.0.1:2019`, and the `caddy` user must be in the `vide-proxy` group to
  reach the instance sockets. **What VIDE renders is valid Caddy 2.6.2** — the oldest version
  Debian and Ubuntu still ship — and it stays inside that dialect on purpose: a
  directive from a later Caddy would fail your *entire* config, VIDE's sites and
  everyone else's. Nothing probes your Caddy's version, so this is a floor VIDE
  keeps rather than one it checks; newer is fine.
- **Must already be present** — VIDE checks for these by name and refuses if one
  is missing; it does not install them: `openssl`, `ss` (package `iproute2`), and
  `systemctl`. (`curl` is checked by the same gate but apt-installed first, so it
  never reaches you as a refusal.) Stock cloud and server images ship all three; a stripped
  `debootstrap --variant=minbase` or a minimal container image may lack `openssl`
  or `iproute2`.
- **Installed for you** if absent: `python3` (by `install.sh`, before anything
  else runs), then `argon2`, `curl`, `git` (also installed by the quick start's
  prerequisite line when absent — a stock cloud image may arrive without it, and
  `install.sh` cannot install the tool that fetches `install.sh`),
  `ca-certificates`, `sudo`, and `libatomic1` (pnpm's standalone binary links
  against it; Node does not, so a box without it installs Node and then fails
  at `pnpm --version`. It is `Priority: optional` and absent from minimal
  Debian/Ubuntu images).
  `apt-get` is invoked only for these — it is never probed for separately,
  because the Debian/Ubuntu gate above already vouches for it.

### Exit codes

Stable, sysexits.h-shaped, so scripts and tests can assert them.

| Code | Name | Meaning |
|-----:|------|---------|
| 64 | `EX_USAGE` | bad invocation or missing argument |
| 69 | `EX_UNAVAILABLE` | a required command or download is unavailable |
| 70 | `EX_SOFTWARE` | internal error (a toolchain step did not converge) |
| 75 | `EX_STATE` | host state problem (lock held, no free port) |
| 77 | `EX_NOPERM` | needs privilege it does not have |
| 78 | `EX_CONFIG` | misconfiguration (unsupported distro, arch, or user) |

(`EX_DATAERR=65` is defined and reserved, but no code path emits it today.)

## Contributing, and reporting a vulnerability

Development setup, the test tiers and what a change has to keep green are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports go through
[`SECURITY.md`](SECURITY.md) — please do not open a public issue for an
authorization or secret-handling defect, because deployments of this are live
machines.

## License

MIT — see [LICENSE](LICENSE).
