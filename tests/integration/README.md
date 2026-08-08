# VIDE integration tier — what it proves, and what it costs

```bash
tests/integration/run.sh                 # Debian, ~5-8 min
tests/integration/run.sh --distro all    # + Ubuntu
```

Needs `podman`, `uidmap`, `passt` on the host, and cgroup v2. Needs the network:
the run genuinely fetches nvm, Node, pnpm and code-server.

## Why this exists

Static checks are **structurally blind** to how a downloaded tool behaves once
installed. **Three toolchain bugs once shipped with a fully green static suite.**
All three lived on one axis — the workspace toolchain as seen by the *non-root
target user* through a *login shell*:

| Historical bug | Assertion that now catches it |
|---|---|
| pnpm's cmd-shim resolves its payload relative to `$0` and is not symlink-safe | `pnpm add -g cowsay` **as the user**, then `command -v cowsay` |
| `PNPM_HOME` / global-bin subdir wiring | `su - user` exports `PNPM_HOME`; `su user` (non-login) does not |
| `/opt/nvm` not world-traversable — works for root, dead for users | `chmod 700 /opt/nvm` ⇒ `vide doctor` must go **red** |

None of them is visible to `install.sh`'s exit code, and none is visible to
`GET /healthz` — **code-server answers `/healthz` on its own bundled Node**, not on
the shared toolchain. A suite that checks only those two is a false green.

The tier also makes an assertion no static check can: a **real authenticated HTTP
session** against a real code-server with the real generated password, plus its
negative control (a wrong password must not authenticate).

## Black-box contract

`in-container.sh` may depend only on VIDE's **external** surface: argv, exit codes,
files on disk, systemd unit state, HTTP behavior. It never imports or reads VIDE's
internals. `tests/unit/test_harness_guards.py` (`TestBlackBoxBoundary`) enforces
this statically, so the boundary cannot erode by accident.

That is not fussiness. A tier that knows how VIDE works internally starts passing
for the wrong reason: a red result has to mean "the behaviour is wrong", never
"the test knew too much about the implementation".

## Security posture

This tier executes third-party installers fetched at test time, so the harness is
split in two with a hard boundary:

- **`run.sh`** is the only file that touches the host. It does nothing but
  `podman build` / `run` / `exec` / `rm`.
- **`in-container.sh`** does every mutation, and **refuses to start** unless it can
  prove it is inside a throwaway container: a container marker
  (`/run/.containerenv` or `/.dockerenv`) *and* a non-empty
  `VIDE_IN_THROWAWAY_CONTAINER`. Invoked on a host by mistake, it exits 78
  before the first write.

Rules `run.sh` holds to, all verified by static guards in
`tests/unit/test_harness_guards.py`:

- **Rootless podman preferred.** A container escape lands on an unprivileged host
  uid rather than root. Verified: rootless + `--systemd=always` boots a real systemd
  PID 1 on cgroup v2, so **no `--privileged` and no `--cap-add` are needed.**
- **Never `--privileged`.** It disables seccomp and AppArmor. The container executes
  three `curl | sh` installers fetched from the internet at test time (nvm,
  get.pnpm.io, code-server.dev); a privileged escape from that would be host root.
- **Never `--network=host`, never `-p`/`--publish`.** The container runs a real IDE
  with a real password and a shell behind it. The login assertion reaches it from
  inside the container's own network namespace.
- **The repo is mounted read-only.** A test cannot mutate the working tree.
- **The one-time password never touches argv** (`/proc/<pid>/cmdline` is world
  readable). It is captured from `install.sh`'s stderr into a `0600` file on tmpfs,
  handed to `curl` with `--data-urlencode password@file`, redacted from the retained
  log, and shredded on exit.

Residual risk, accepted and named: the three upstream installer *scripts* are
unpinnable (no upstream checksums). We do not fake-pin them.

## What a container cannot honestly assert

Declared, not faked:

- **logind / `systemd --user` / lingering** — VIDE uses a system unit (`User=%i`),
  so nothing under test needs them. No assertion pretends otherwise.
- **Real OOM-victim selection.** We assert `OOMScoreAdjust=500` is *applied*; that
  the kernel picks the IDE first is a VM/bare-metal claim.
- **Reboot persistence.** `systemctl is-enabled` proves the `WantedBy` symlink
  exists. "Survives a reboot" needs a VM — `tests/host-smoke/reboot-persistence.sh`
  is where that claim lives.
- **aarch64.** Booting an emulated arm64 systemd under `qemu-user` is fragile enough
  that a red result would not distinguish a VIDE bug from an emulation bug — worse
  than no test. arm64 stays covered by the arch-gate unit tests only, until a native
  arm64 runner exists.

## What this tier deliberately leaves to another

**The bare-root `vide`-fallback path.** This tier provisions an explicit,
pre-created non-root user, so it never takes the branch that auto-creates the
dedicated `vide` user, sets its login/sudo password and writes the `visudo`
drop-in (`src/vide/users.py`, and the `vide` branch of
`src/vide/install_flow.py`). That is the default when `install.sh` runs as bare
root with no `VIDE_USER`, and it is covered by its own gate —
`tests/vide-branch/run.sh`, on a minimal image where the sudo *package* is absent
while the sudo *group* exists, which is the fixture that once let a live walk die
at `visudo` while every hermetic tier stayed green.

## Running as root

`run.sh` **refuses to run as root** and exits `EX_NOPERM`. Rootful podman would put a
container escape from the upstream `curl | sh` installers onto host root, voiding the
containment the tier depends on. Run it as an unprivileged user with `subuid`/`subgid`
set (Debian sets these up for a normal user automatically). If you genuinely have no
such user — a throwaway VM you own outright — override per-invocation with
`VIDE_ITEST_ALLOW_ROOTFUL=1`, and only on disposable infrastructure.
