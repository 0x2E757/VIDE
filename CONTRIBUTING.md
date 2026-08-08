# Contributing

VIDE is Python, stdlib only, ≥3.10. There is nothing to install to work on it and
nothing to build. The two entry points are thin bash shims; everything else is
`src/vide/`.

The one thing worth knowing before you start: **this project keeps its reasoning in
the source, next to what it describes.** Modules carry long doc-comments explaining
why a mechanism is shaped the way it is, including the bugs that shaped it. If you
change a mechanism whose comment explains a trap, update the comment in the same
change — a stale "why" is worse than none, because it argues for the wrong thing
convincingly.

## Running the tests

```bash
tests/unit/run.sh                 # unit tier — no root, no network, seconds
tests/unit/prove-teeth.sh         # mutation proofs — each historical bug re-introduced must go red
sudo ./install.sh --dry-run       # preview every action, mutate nothing
```

Those three need nothing but a Linux box with `python3`. Everything below costs
more and needs more:

```bash
tests/integration/run.sh          # container tier, the acceptance arbiter (rootless podman, network)
tests/parity/diff-artifacts.sh    # durable-artifact shape diff against the frozen golden
tests/vide-branch/run.sh          # the dedicated-'vide' bare-root journey
tests/sso-mode/run.sh             # SSO gate: real oauth2-proxy + real Caddy + fake RS256 IdP
tests/host-smoke/                 # gates that need a real disposable box
```

**Build the arbiter image first.** The parity, vide-branch and sso-mode gates all
run in the image `tests/integration/run.sh` builds, and exit `69` without it.

None of these tiers run natively on macOS or Windows. Use a Linux host or a
container.

## What a change has to keep green

`tests/unit/run.sh` and `tests/unit/prove-teeth.sh`, always. Beyond that, the tier
to run is the one that owns what you touched:

| You changed | Run |
|---|---|
| anything under `src/vide/` | unit + prove-teeth |
| `sso.py`, `oauth2proxy.py`, `caddy.py`, the SSO units or `tests/sso-mode/` | the sso-mode gate |
| `node.py`, `codeserver.py`, the toolchain path | the integration arbiter |
| `users.py` or the bare-root branch of `install_flow.py` | the vide-branch gate |
| anything that changes a durable artifact's shape | the parity diff |

## Three things that will surprise you

**1. Mutation proofs, not just tests.** `prove-teeth.sh` re-introduces each
historical bug and requires the suite to go **red**. A test that cannot fail is not
coverage, and this is where that gets enforced. If you add a guard against a real
defect, add its mutation too — the row is a few lines and it is the only thing that
proves your guard has teeth.

**2. The parity golden is frozen, and re-blessing it has a procedure.**
`tests/parity/golden/durable-artifacts.txt` is the reference shape of everything a
password-mode install writes. There is no bless flag on purpose. If a red diff turns
out to be a legitimate shape change, follow the procedure in
`tests/parity/golden/PROVENANCE.md` — and note that step 2 asks you to update three
files in the same commit. Skipping it has already happened once and is recorded
there.

**3. `--dry-run` is correct by construction.** Every durable mutation flows through
the one `Executor`; under dry-run its methods log a preview *derived from the real
operation*, so parity is definitional rather than policed. There are exactly two
typed escape hatches — `narrate()` for secret paths and value-producers, `verify()`
for post-mutation assertions — and a **pinned census of 9 residual dry-run reads**
in `tests/unit/test_invariants.py`. If your change adds a tenth, the census goes red
on purpose: come and argue for it, do not bump the number.

## Config is not control

`.env` is config: precedence is argv > env > `.env` > default, `KEY=VALUE`, no shell
expansion. Control levers are argv-only, structurally — the `Config` schema has no
`yes` field, so no `.env` line and no environment variable can waive
`vide destroy`'s confirmation. That is an `AttributeError`, not a policy, and it is
meant to stay that way: config and control must not share a channel.

## Exit codes

Stable and sysexits.h-shaped, because scripts and tiers assert them. The table is in
the [README](README.md#exit-codes). Adding a new failure mode means picking an
existing code, not inventing one.

## Documentation

`docs/` states outcomes and contracts. It is not a changelog and not a design
diary — that is what the source comments are for. One document has stricter
rules:

- `tests/parity/golden/PROVENANCE.md` must match the fixture beside it, always.

**The acceptance ledger is not in this repository.** It recorded which box each
tier last ran on, and that is operator infrastructure rather than anything a
reader of this source needs. Its rule outlived it and still governs every claim
here: **never state a result better than the last measurement.** If a tier has
not been re-run against the tree in front of you, saying so is the honest entry —
in a commit message, in a comment, in a review. A number quoted without a run
behind it is the defect this project has caught in itself more than once.

## Reporting a security defect

Not here — see [`SECURITY.md`](SECURITY.md). Deployments of this are live machines,
so an authorization or secret-handling defect should not land in a public issue.
