"""Shared test doubles. Fakes exist ONLY at the Executor / transport /
system-query boundaries; assertions target emitted artifacts and recorded
action sequences — which, for a provisioner, ARE the behavior — never internal
call graphs.
"""
from __future__ import annotations

import contextlib
import io
import shutil
import tempfile
import urllib.error
from pathlib import Path
from unittest import mock

from vide import system
from vide.errors import CommandFailed, SoftwareError
from vide.executor import Executor
from vide.reporter import Reporter


def quiet_reporter() -> Reporter:
    return Reporter(stream=io.StringIO())


def capturing_reporter() -> tuple[Reporter, io.StringIO]:
    """A reporter whose stream you can read back. `quiet_reporter` throws its
    StringIO away, which silently makes "did it warn?" unassertable — and for the
    best-effort paths (branding) the warning is the ONLY alarm, so a test that
    cannot see it is not covering the failure mode at all."""
    buf = io.StringIO()
    return Reporter(stream=buf), buf


class _BoxModel:
    """The half of a real box a double MUST model, because the product fails
    against it and a double that does not is more forgiving than the thing it
    stands in for.

    Three axes. Two of them have already shipped a crash on the first SSO
    install behind a fully green tier:

      parent    — atomic_write mkstemps into dest.parent and dies there
                  (508 rows green while a bare-box install crashed)
      identity  — `install -d -o/-g` resolves the names BEFORE it creates
                  anything and exits 1 on an unknown one, and atomic_write's
                  chown resolves through pwd/grp; the fix for the parent crash
                  reintroduced the same crash one line later, on this axis,
                  with 515 rows green
      sandbox   — a double that really mkdirs must never mkdir outside the
                  fixture tree: this tier runs on a box where /etc/vide is real

    DELIBERATELY BARE BY DEFAULT. "the box already has what VIDE creates" is
    precisely the assumption that hid both crashes, so a test that needs a
    provisioned box says so, in one argument, where it can be read.
    """

    def __init__(self, *, identities: tuple[str, ...] = (), sandbox=None) -> None:
        self.users = {"root", *identities}
        self.groups = {"root", *identities}
        self.sandbox = Path(sandbox) if sandbox is not None else None

    def note(self, argv) -> None:
        """The ledger is mutated by the SAME argv the product issues, never by a
        test helper: `groupadd --system vide-proxy` is what makes vide-proxy
        exist, here as on the box. `useradd` grants the same-named GROUP too —
        that is USERGROUPS_ENAB on Debian/Ubuntu, and it is why `vide-oauth2` is
        a usable group for proxy.toml and the union file without any explicit
        groupadd anywhere in the tree."""
        if argv[:1] == ["groupadd"]:
            self.groups.add(argv[-1])
        elif argv[:1] == ["useradd"]:
            self.users.add(argv[-1])
            self.groups.add(argv[-1])

    def require(self, owner, *, how: str) -> None:
        """`how` selects the failure the REAL path raises: the argv path exits 1
        (CommandFailed), the native chown resolves through pwd/grp and is mapped
        to SoftwareError (executor.Executor._chown). A double that raises the
        wrong TYPE is a double whose except-clauses do not match production's."""
        if owner is None:
            return
        user, group = owner
        if how == "argv":
            if user not in self.users or group not in self.groups:
                raise CommandFailed(("install", "-d", "-o", user, "-g", group), 1)
        else:
            missing = ("user", user) if user not in self.users else (
                ("group", group) if group not in self.groups else None)
            if missing is not None:
                raise SoftwareError(
                    f"cannot write owned by {user}:{group} — that identity does "
                    f"not exist yet (no such {missing[0]}: {missing[1]!r})")

    def inside(self, path) -> bool:
        """May the double actually TOUCH this path?

        The sandbox governs side effects only — never refusals. A double must
        refuse everything the product refuses no matter where the path points
        (that is the whole reason this class exists), but it must never create
        or overwrite anything outside the fixture tree: this tier runs on a real
        box, it may be run as root, and several product paths are hardcoded
        absolutes (/etc/sudoers.d, /usr/local/bin). Outside the tree the call is
        checked and recorded and nothing is written.

        The residual divergence this leaves is stated rather than hidden: for an
        out-of-tree destination there is no write-then-read-back, so a product
        branch that reads back what it just wrote takes the empty path. Every
        SSO artifact — where those branches live — is under make_config's tmp
        tree, so no current row depends on it."""
        root = self.sandbox or Path(tempfile.gettempdir())
        p = Path(path).resolve()
        return p == root or root in p.parents


#: Every system reader a double must answer for — A NAME, not a behaviour. The
#: answer beside each one lives in bare_host below; a row that means anything
#: else says so in its own patch.
#:
#: Lifted out of the contextmanager so it can be READ without entering it, which
#: is what lets test_invariants' I12 census walk doctor's own call graph and fail
#: when a new system reader reaches it without a double. That census is the only
#: thing standing between this list and the next silent host read: the failure
#: has now happened three times — path_is_denied, proc_no_new_privs, and the four
#: readers the port reservation added, which had four unit classes shelling out
#: to `ss` and `systemctl` on the machine running the tier while reading as
#: hermetic.
#:
#: `healthz` is here but is NOT answered from a constant: three rows are ABOUT
#: the probe, so it comes through bare_host's `probe=` argument instead. A fixed
#: default would have silently overridden every one of them.
HOST_SEAMS = (
    "unit_is_active",
    "unit_is_failed",
    "unit_state",
    "unit_enable_state",
    "unit_main_pid",
    "unit_listen_streams",
    "unit_n_restarts",
    "listening_ports",
    "hop_holders",
    "user_uid",
    "path_facts",
    "proc_no_new_privs",
    "proc_groups",
    "proc_start_realtime",
    "path_is_denied",
    "path_mtime",
    "group_exists",
    "group_entry",
    "user_exists",
    "healthz",
)


@contextlib.contextmanager
def bare_host(*modules, live=(), identities=(), members=(), starts_live=(),
              probe=None):
    """The hermetic default: on the box under test NOTHING is running and NO
    VIDE identity exists. A row that means otherwise says so, in one argument,
    where it can be read.

    A unit tier that consults the real box is a tier whose green is a property of
    the machine rather than of the tree — and since `prove-teeth.sh` requires a
    named test to be green on the pristine tree before it mutates, such a row does
    not merely prove nothing, it hard-FAILS wherever the box differs.

    It covers the IDENTITY seams as well as the unit ones, and that is the part
    worth reading twice. Moving the group reads to `grp.getgrnam` made them
    in-process libc: `mock.patch.object(system, "query", …)` stopped covering
    them, the argv census cannot see them, and a PATH shim that replaces
    `systemctl` does not touch them. Three ways of hiding a host read, and the
    commit that introduced them was the one whose purpose was to remove host
    reads. Every named seam goes through here so there is one place to add the
    next one.

    `members=` fills the group's supplementary list. It defaults to EMPTY rather
    than to "whatever the caller probably wants", and that default is load-bearing
    in the other direction: doctor's caddy-membership check fails on an empty
    member set, so a row asserting `not ok` passes for a reason it did not intend
    unless it names the members. An assertion that cannot distinguish its own
    subject from a fixture default is not an assertion.

    `starts_live=` models what `systemctl enable --now` does: units named there
    report inactive on the FIRST query and active afterwards. Liveness as a
    constant is what made two mutation rows unfalsifiable — the whole point of
    `was_active` is WHEN it is sampled, and a constant answers the same before
    and after the converge that starts the proxy.

    NOTHING here returns a synthetic handle into the real box. `unit_main_pid`
    answers None even for a live unit, because a fabricated PID sent
    `proc_no_new_privs` to read `/proc/<n>/status` on the machine running the
    tier — a host read introduced by the helper written to remove host reads,
    and one neither the argv census (a file read, no subprocess) nor a
    `systemctl` PATH shim can see. `proc_no_new_privs` is a seam here for the
    same reason.

    `probe=` is the /healthz seam, and it is an ARGUMENT rather than a constant
    because three rows in this tree are ABOUT the probe: they count the ports it
    is called with, or the paths. A fixed default here would have silently won
    over their own patches — mock.patch resolution is last-entered-wins, and two
    of those rows enter theirs BEFORE this contextmanager. It defaults to "no
    answer", which is what a bare box gives; a row that means "something answers"
    passes its own callable. Unseamed it is a real loopback connect with a 3 s
    timeout, twice per proxy_health."""
    import contextlib as _c
    live, identities, members = set(live), set(identities), set(members)
    pending = set(starts_live)

    def _active(unit):
        if unit in pending:
            pending.discard(unit)          # the `enable --now` this run performs
            return False
        return unit in live or unit in set(starts_live)

    if probe is None:
        def probe(port, *, path="/healthz", timeout=3.0):
            return False

    seams = (
        ("unit_is_active", _active),
        ("unit_is_failed", lambda u: False),
        # The WORD, not the boolean, and deliberately only the two
        # steady states. `activating`/`deactivating` are what a caller
        # must be able to tell apart from a fault, so a row that cares
        # about them names them itself rather than getting them from a
        # default nobody read.
        ("unit_state", lambda u: "active" if u in live else "inactive"),
        ("unit_enable_state",
         lambda u: "enabled" if u in live else "disabled"),
        ("unit_main_pid", lambda u: None),
        # What the .socket unit is configured to listen on. Empty, because a
        # bare box has no reservation unit at all — and unseamed this is a
        # `systemctl show -p Listen` against the tier's own manager.
        ("unit_listen_streams", lambda u: []),
        ("unit_n_restarts", lambda u: 0),
        # `ss -Htln` on the machine running the tier. A bare box holds nothing.
        ("listening_ports", lambda: set()),
        # set(), NOT None, and the distinction is the whole value of this
        # reader: None means "/proc/net/tcp could not be read at all", which on
        # a box where nothing is listening is an incoherent state — and
        # incoherent fixtures are how vacuous greens are born. A row that means
        # an unreadable kernel says so itself.
        ("hop_holders", lambda port, **kw: system.HopHolders(
            certain=frozenset(), possible=frozenset(), served=frozenset())),
        # pwd.getpwnam on the machine running the tier. A distinct constant from
        # group_entry's gid so a row that confuses the two says which it meant.
        ("user_uid", lambda u: 60001 if u in identities else None),
        # An lstat of whatever path the product hands it — on a converge that
        # is /etc/vide/sso/proxy.toml, a real path on the machine running the
        # tier. None is the bare box's answer (the file is not there), and it
        # is the answer that makes the posture repair a no-op rather than a
        # verdict about somebody else's box.
        ("path_facts", lambda p: None),
        ("proc_no_new_privs", lambda pid, **kw: True),
        ("proc_groups", lambda pid: set()),
        # Reached from the restart decision. Unseamed, a fabricated pid reads
        # the tier's own /proc — the exact crash the note above records, one
        # reader further down.
        ("proc_start_realtime", lambda pid, **kw: None),
        # A real lstat of /run/vide/<user> on the machine running the
        # tier if it is ever reached unpatched — the third named seam
        # to need adding here, which is the point of the list.
        ("path_is_denied", lambda p: False),
        # None is the coherent bare-box answer, not a refusal to look: the files
        # the restart decision stats live in /etc/systemd/system, and on a box
        # that never installed VIDE they are simply absent.
        ("path_mtime", lambda p: None),
        ("group_exists", lambda g: g in identities),
        ("group_entry",
         lambda g: (60000, set(members)) if g in identities else None),
        ("user_exists", lambda u: u in identities),
        ("healthz", probe),
    )
    # The list and the answers are ONE thing said twice, and the census reads
    # only the first — so a seam added here and forgotten there would leave I12
    # passing over a reader it cannot see.
    if {n for n, _ in seams} != set(HOST_SEAMS):
        raise AssertionError(
            "bare_host and HOST_SEAMS disagree: "
            f"{sorted({n for n, _ in seams} ^ set(HOST_SEAMS))}")
    # A NAME THAT NO LONGER RESOLVES IS A SEAM THAT SILENTLY DOES NOTHING. This
    # was `if hasattr(...): patch`, which skipped an entry whose reader had been
    # renamed — leaving the REAL reader unpatched and both guards above green.
    # This round renamed exactly such a reader twice (proc_start_mtime →
    # proc_start_realtime, socket_listener_pids → listener_uids), so the failure
    # is not hypothetical; it just happened to be caught by other rows.
    missing = sorted(n for n, _ in seams if not hasattr(system, n))
    if missing:
        raise AssertionError(
            f"HOST_SEAMS names readers that no longer exist in system.py: "
            f"{missing} — the double is patching nothing and the rows that rely "
            f"on it are reading the machine")
    with _c.ExitStack() as stack:
        for mod in modules:
            for name, fn in seams:
                stack.enter_context(mock.patch.object(mod.system, name, fn))
        yield


def _refuse_as_the_real_one_would(ex, dest, owner) -> None:
    """The refusals of Executor.atomic_write, for a destination outside the
    fixture tree where the double must perform nothing. Both of them are real
    questions about the box the tier is running on — does the parent exist, does
    the identity resolve — so they are asked, and only the WRITE is withheld."""
    if not Path(dest).parent.is_dir():
        raise FileNotFoundError(
            f"atomic_write: {Path(dest).parent} does not exist — the real "
            "Executor mkstemps there and would fail the same way")
    if owner is not None:
        ex._chown(str(dest), owner)


class _BaseFake(Executor):
    """Everything both doubles share.

    atomic_write is deliberately NOT here: both inherit the PRODUCT's own, which
    is the whole point of Executor._chown existing. A double that re-implements
    a thirty-line method to get around its one un-fakeable operation also
    re-implements the twenty-nine lines it had no business changing, and that is
    how both first-install crashes stayed invisible.
    """

    def __init__(self, *, identities: tuple[str, ...] = (), sandbox=None) -> None:
        super().__init__(dry_run=False, reporter=quiet_reporter(), cfg=None)
        self.box = _BoxModel(identities=identities, sandbox=sandbox)
        self.actions: list[tuple] = []

    def _chown(self, path, owner):  # type: ignore[override]
        # Same resolution order as the real one, same exception, no chown: the
        # only operation in atomic_write a unit tier cannot perform.
        self.box.require(owner, how="native")

    def run(self, argv, **kw):  # type: ignore[override]
        argv = list(argv)
        self.box.note(argv)
        self.actions.append(("run", tuple(argv)))
        # input_text (secrets) is deliberately NOT recorded — same rule as the
        # bash seam: traces must never carry a plaintext credential.

    def run_as(self, user, argv, **kw):  # type: ignore[override]
        self.actions.append(("run_as", user, tuple(argv)))

    def ensure_dir(self, path, *, mode, owner=None):  # type: ignore[override]
        # `install -d` resolves -o/-g during option parsing and exits 1 BEFORE
        # it creates anything, so the refusal comes first — the directory does
        # not appear on a box where the group is missing.
        self.box.require(owner, how="argv")
        super().ensure_dir(Path(path), mode=mode, owner=owner)   # records the argv
        if self.box.inside(path):
            Path(path).mkdir(parents=True, exist_ok=True)
            Path(path).chmod(mode)              # install -d ASSERTS the mode

    def ensure_dir_as_user(self, user, path, *, mode):  # type: ignore[override]
        super().ensure_dir_as_user(user, Path(path), mode=mode)
        if self.box.inside(path):
            Path(path).mkdir(parents=True, exist_ok=True)
            Path(path).chmod(mode)

    def write_as_user(self, user, dest, content, *, mode):  # type: ignore[override]
        # The real one runs `mktemp <dest.parent>/…` AS THE USER and raises
        # CommandFailed when that fails — so a missing parent dies there, before
        # any content exists. That is the first crash's own shape on the
        # user-tree half: branding and secrets both write into directories some
        # other call creates.
        if not Path(dest).parent.is_dir():
            raise CommandFailed(
                ("mktemp", f"{Path(dest).parent}/.{Path(dest).name}.XXXXXX"), 1)
        self.actions.append(("write_as_user", user, str(dest), mode))

    def idle(self, seconds):  # type: ignore[override]
        self.actions.append(("idle", seconds))   # never a real sleep

    def download(self, url, dest, override_var=None):  # type: ignore[override]
        self.actions.append(("download", url, str(dest)))

    def run_setup_script(self, url, override_var, runner, *, args=(), env=None,
                         clear_env=(), as_user=None, home=None,
                         throwaway_home=False, umask=0o022):  # type: ignore[override]
        self.actions.append(("run_setup_script", url, tuple(runner),
                             tuple(args), as_user))


class RecordingExecutor(_BaseFake):
    """Records every mutation as a tuple. It also PERFORMS the filesystem ones,
    through the product's own atomic_write: a double that records a write and
    does not perform it makes every write-then-read-back branch take a path
    production never takes — and the SSO converge is full of them."""

    def __init__(self, *, identities: tuple[str, ...] = (), sandbox=None) -> None:
        super().__init__(identities=identities, sandbox=sandbox)
        self.contents: dict[str, str] = {}
        self.verified: list[str] = []

    def atomic_write(self, dest, content, *, mode, owner=None):  # type: ignore[override]
        if self.box.inside(Path(dest).parent):
            super().atomic_write(Path(dest), content, mode=mode, owner=owner)  # the REAL one
        else:
            # Out of tree: run the product's refusals by hand, perform nothing.
            _refuse_as_the_real_one_would(self, dest, owner)
        self.actions.append(("atomic_write", str(dest), mode, owner))
        self.contents[str(dest)] = content

    def write_as_user(self, user, dest, content, *, mode):  # type: ignore[override]
        super().write_as_user(user, dest, content, mode=mode)
        self.contents[str(dest)] = content

    def verify(self, ok, msg, code=None):  # type: ignore[override]
        self.verified.append(msg)

    @property
    def verbs(self) -> list[str]:
        return [a[0] for a in self.actions]


class FsExecutor(_BaseFake):
    """Filesystem-backed: writes are real (through the product's atomic_write),
    systemctl/rm are recorded. `rm -rf <dir>` is modelled — the parser this
    replaced read only `-f`, so `rm -rf <dir>` called unlink() on the literal
    string "-rf" and then on a directory."""

    def run(self, argv, **kw):  # type: ignore[override]
        super().run(argv, **kw)
        argv = list(argv)
        if argv[:1] == ["rm"]:
            flags = "".join(a for a in argv[1:] if a.startswith("-"))
            for p in (a for a in argv[1:] if not a.startswith("-")):
                path = Path(p)
                if path.is_dir() and "r" in flags:
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)

    def atomic_write(self, dest, content, *, mode, owner=None):  # type: ignore[override]
        if self.box.inside(Path(dest).parent):
            super().atomic_write(Path(dest), content, mode=mode, owner=owner)  # the REAL one
        else:
            _refuse_as_the_real_one_would(self, dest, owner)
        self.actions.append(("atomic_write", str(dest), mode, owner))

    @property
    def ran(self) -> list[tuple]:
        return [a[1] for a in self.actions if a[0] == "run"]


class FakeHTTPResponse:
    def __init__(self, body: bytes = b"payload", url: str = "") -> None:
        self._body = body
        self._url = url
        self._done = False

    def read(self, n: int = -1) -> bytes:
        if self._done:
            return b""
        self._done = True
        return self._body

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    """Scripted per-attempt: each item is a FakeHTTPResponse to return or an
    Exception to raise. Records the number of attempts."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.calls = 0

    def open(self, url, timeout=None):
        self.calls += 1
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class ScriptedPrompter:
    """A Prompter whose answers are scripted per ask-point; unscripted asks
    fall to their defaults (the port's design: every ask has one). The
    vacuous-green trap is the LEFTOVER: a scripted answer nothing consumed
    means the question silently vanished from the journey — finish() raises
    on it, and tests can assert consumed() on paths that never finish."""

    def __init__(self, **answers) -> None:
        self.answers = dict(answers)
        self.asks: list[tuple] = []
        self.secrets: list[str] = []
        self.summary = None

    def _take(self, qid, default):
        return self.answers.pop(qid) if qid in self.answers else default

    def can_reask(self) -> bool:
        return False  # scripted answers must die, not loop, on a decline

    def acknowledge_exposure(self) -> None:
        self.asks.append(("exposure",))

    def choose_target_user(self, facts):
        self.asks.append(("target_user", facts.default))
        return self._take("target_user", facts.default)

    def existing_instance_action(self, inst):
        from vide.prompter import InstanceAction
        self.asks.append(("existing_instance", inst.user))
        return self._take("existing_instance", InstanceAction.CONVERGE)

    def toolchain_reinstall(self, facts, default):
        self.asks.append(("toolchain", facts.node_version))
        return self._take("toolchain", default)

    def password_choice(self, user):
        self.asks.append(("password", user))
        return self._take("password", None)

    def choose_fqdn(self, default, *, required=False):
        self.asks.append(("fqdn", default))
        return self._take("fqdn", default)

    def auth_mode(self, facts):
        self.asks.append(("auth_mode", facts.default))
        return self._take("auth_mode", facts.default)

    def sso_parent_domain(self, default):
        self.asks.append(("parent_domain", default))
        return self._take("parent_domain", default)

    def sso_credentials(self, default_client_id):
        from vide.prompter import SsoCredentials
        self.asks.append(("sso_credentials", default_client_id))
        return self._take("sso_credentials",
                          SsoCredentials(client_id=default_client_id or "cid.apps.googleusercontent.com",
                                         client_secret="GOCSPX-scripted"))

    def whitelist_email(self, user, default):
        self.asks.append(("whitelist_email", user))
        return self._take("whitelist_email", default or "scripted@example.com")

    def deliver_secret(self, line: str) -> None:
        self.secrets.append(line)

    def finish(self, summary) -> None:
        self.summary = summary
        if self.answers:
            raise AssertionError(
                f"scripted answers never consumed: {sorted(self.answers)} — "
                "a question silently vanished from the journey")

    def consumed(self) -> bool:
        return not self.answers


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


class FakeDlConfig:
    dl_retries = 3
    dl_retry_delay = 0.0
    dl_connect_timeout = 1.0
    dl_max_time = 5.0
    code_server_releases_latest_url = "https://github.com/coder/code-server/releases/latest"


def make_config(tmp: Path, **overrides):
    """A Config pointed entirely inside a sandbox tree."""
    from vide.config import SCHEMA, Config
    values = {}
    for s in SCHEMA:
        values[s.field] = s.cast(s.default)
    values.update(
        state_dir=tmp / "etc-vide",
        nvm_dir=tmp / "opt-nvm",
        pnpm_home=tmp / "opt-pnpm",
        bin_dir=tmp / "bin",
        launcher=tmp / "lib/code-server-launch",
        unit_path=tmp / "systemd/code-server@.service",
        cli_link=tmp / "bin/vide",
        pnpm_profile=tmp / "profile.d/vide-pnpm.sh",
        nvm_installer_url="https://example.test/nvm.sh",
        dl_retry_delay=0.0,
        sso_dir=tmp / "etc-vide" / "sso",
        oauth2_proxy_dir=tmp / "opt-oauth2-proxy",
    )
    values.update(overrides)
    return Config(values, repo_dir=tmp)
