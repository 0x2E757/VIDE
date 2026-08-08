# Provenance of golden/durable-artifacts.txt

- **What it is:** the frozen reference shape of every durable artifact a
  password-mode install writes — the harvest `diff-artifacts.sh` diffs a fresh
  install against. It pins SHAPE, not behaviour: a field-set or permission
  difference is a finding even when the arbiter tier is green.
- **Originally captured:** 2026-07-11, from an all-green evidence run in the
  `vide-itest:debian` image (`VIDE_CODE_SERVER_PIN_LATEST=1 /vide/install.sh
  --user ittest`).
- **Re-blessed 2026-07-11** — the single-template unit gained
  `RuntimeDirectory`/`ExecStartPre` (the socket-group mechanism) and the launcher
  gained the `VIDE_SOCKET` branch. A password install writes those same shared
  files, so `=== unit file ===` and `=== launcher ===` necessarily changed. The
  re-bless was verified confined to exactly those two sections; every
  password-mode artifact — the `VIDE_PORT=` record, config.yaml, its stat,
  profile.d, bin layout, opt perms, the guard exit code, the snippet, the
  SHOWN-ONCE count — stayed byte-unchanged.
- **Re-blessed 2026-07-28** — the launcher gained the two shared flags
  `--app-name VIDE` and `--disable-workspace-trust`, so `=== launcher ===`
  changed again.
- **Re-blessed 2026-07-31, from an OBSERVED install** — the unit's
  `ExecStartPost` gained `[ ! -L "$${VIDE_SOCKET}" ]` and the comment block that
  says why. That guard is not cosmetic: the loop runs as root (the `+`) over a
  directory the INSTANCE USER owns, so without it a user can symlink the socket
  path at any socket on the box and root hands it to `vide-proxy` — the
  operator's internet-facing Caddy. A password-mode install writes the same
  shared unit, so `=== unit file ===` necessarily moved. Verified confined:
  `git diff` on the golden is ONE hunk, 9 insertions and 1 deletion, all of it
  that line and its comment. Every other section — the `VIDE_PORT=` record,
  config.yaml and its stat, the settings seed, the launcher, profile.d, bin
  layout, opt perms, the guard exit code, the snippet, the SHOWN-ONCE count —
  byte-unchanged.

- **Re-blessed 2026-07-31 (second), for the socket-directory FREEZE.** The
  previous entry's `[ ! -L ]` guard turned out to close only half of what it was
  credited with. It runs once, at start, in `ExecStartPost`; the routing hole it
  was written for is exercised at any later moment by a path Caddy re-resolves on
  every connection — and the guard and the `chgrp` it protects are two syscalls
  against a path whose directory the instance user owns, i.e. a check-then-act
  pair. `ExecStartPost` now waits for the socket, `chown root:vide-proxy`s the
  directory, re-asserts `2750`, and only then tests and relabels — failing the
  unit on every arm including loop exhaustion, where it used to fall out silently
  and exit 0. The unit also gained an explicit `TimeoutStartSec=120` to bound the
  45 s socket wait. A password-mode install writes the same shared unit, so
  `=== unit file ===` necessarily moved again; password instances themselves are
  untouched (the `test -z "$${VIDE_SOCKET}"` short-circuit is the first thing the
  line does, which is also what keeps the byte-frozen `tests/integration/` tier
  valid). Verified confined to that one section: every password-mode artifact —
  the `VIDE_PORT=` record, config.yaml and its stat, the settings seed, the
  launcher, profile.d, bin layout, opt perms, the guard exit code, the snippet,
  the SHOWN-ONCE count — byte-unchanged.

## The 2026-07-28 re-bless was recorded late, on 2026-07-30

Step 2 of the procedure below was skipped: the golden was updated, but this file
and `diff-artifacts.sh`'s header were not, so both went on describing the
previous shape while the fixture had already moved. Nothing was wrong with the
new bytes — they are byte-identical to `units/code-server-launch` — but for two
days the provenance record and the fixture disagreed, and only a reader
comparing them by hand would have noticed.

That is why step 2 names every file explicitly. A golden whose provenance is stale
is worse than a red diff: a red diff argues with you, a stale record agrees with
you for the wrong reason.

**That gap closed on 2026-07-31.** A parity run diffed the golden against a real
container install for the first time since the 2026-07-28 re-bless. It went red
on exactly one hunk — the unit guard above, a known deliberate change — and on
nothing else, which is what re-blessing by reading the diff was owed and had not
received.

## Known rot vector (upstream, not a VIDE regression)

`/etc/profile.d/vide-pnpm.sh` embeds the pnpm global-bin subdirectory learned
from the live pnpm at install time (`src/vide/node.py` — today `bin`). A future
pnpm release relocating its `add -g` shim directory changes that byte and the
gate goes red inside the `=== profile.d ===` hunk for an upstream reason. It is
deliberately NOT normalized away — the learned subdir is load-bearing (the
PATH-wiring bug class the parity tier exists to catch).

## Normalization

Produced by the `harvest()` function that still lives in `diff-artifacts.sh` —
port → `PORT`, argon2 hash → `HASH`, cookie suffix → `RAND`. That function is
frozen with the golden: any edit to it invalidates this file.

## Re-bless procedure

There is no bless flag, on purpose. If a red diff is investigated and judged a
legitimate upstream or deliberate shape change (never to silence a regression):

1. Verify the semantics manually — the hunk must be explainable line by line.
2. In the SAME commit, update `golden/durable-artifacts.txt`, the capture facts
   in **this file**, and the capture facts in **`diff-artifacts.sh`'s header**.
   All three, or the fixture and its record drift apart.
3. `tests/unit/test_harness_guards.py` (`TestParityGolden`) must stay green — it
   rejects a structurally corrupt bless.

## 2026-07-30 re-bless — `settings.json`, DERIVED not observed

`harvest()` gained a `=== user settings seed ===` section, because
`branding.seed_user_settings` writes that file ONCE and never converges: a wrong
seed is permanent per instance, fixable only by hand, and it was the highest
consequence durable artifact VIDE emits that no gate had ever seen.

**Step 2 of the procedure above was not walked, and this is the honest record of
that.** The container tier could not be run from the machine this landed on. The
hunk was instead derived from the source of truth — `json.dumps(DEFAULT_SETTINGS,
indent=2)`, executed against the real module, which is byte-for-byte what
`seed_user_settings` writes. So it is a *computed* expectation, not an *observed*
one.

The failure mode this leaves is benign and loud rather than silent: if the
derivation is wrong, the next parity run goes RED on a hunk that is not a
regression. Investigate that diff against `DEFAULT_SETTINGS` before assuming a
defect. The first real container run either confirms this fixture or corrects it,
and that run should update this note.

**CONFIRMED 2026-07-31.** That run happened. The `=== user settings seed ===`
section came back byte-identical from a real install, so the derivation was
right and this hunk is now observed rather than computed. It is recorded here
rather than quietly deleted above, because a fixture that was once derived and
then confirmed is a different thing from one that was captured — and the next
reader deciding how far to trust this file is owed the difference.

## Scope

The parity tier pins the debian shape only, and a shape can be equal-but-wrong by
design — this fixture must NOT be extended into new journeys or distros. New
coverage belongs in new gates, not in this file.
