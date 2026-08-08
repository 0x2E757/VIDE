"""Always-real READS. The other half of the executor's mutate/observe split.

Observation is safe in a preview, so nothing here consults dry-run — that is
what dissolves most of the bash `DRY-RUN ALLOWLIST` census: probes like
`run_as user test -x` no longer need a tagged branch, they just run and return
the honest answer (a missing user probes False, and the data-branch says
"would install", which is exactly the bash preview semantics without the tag).

Nothing here mutates. Mutations live in executor.py, full stop.
"""
from __future__ import annotations

import http.client
import os
import pwd
import re
import shutil
import socket
import stat as stat_mod
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


# runuser preferred (no sudo policy involvement), sudo -u fallback — detected
# once, then reused for every later call.
def _as_user_prefix() -> tuple[str, ...]:
    if shutil.which("runuser"):
        return ("runuser", "-u")
    return ("sudo", "-u")


_AS_USER = _as_user_prefix()


def euid() -> int:
    return os.geteuid()


def user_home(user: str) -> Path | None:
    """Home from passwd; None for a missing user (the empty-string-on-exit-0
    contract of the bash user_home, typed properly)."""
    try:
        return Path(pwd.getpwnam(user).pw_dir)
    except KeyError:
        return None


def user_exists(user: str) -> bool:
    return user_home(user) is not None


def group_exists(group: str) -> bool:
    """`grp.getgrnam`, not `getent group` — the precedent user_home/user_exists
    already set. NSS answers either way, so this is the same question; it just
    costs no subprocess on the install path and, the part that matters, it is a
    NAMED read a test can stub. A dependency that exists only as an argv inside
    another function is one no test can steer and no reader can grep, and two
    writers now depend on this group existing before they name it in an
    `install -d -g`, which resolves it at exec time and exits 1 when it cannot."""
    import grp
    try:
        grp.getgrnam(group)
    except KeyError:
        return False
    return True


def unit_is_active(unit: str) -> bool:
    """`systemctl is-active --quiet`: 0 for active (and reloading), non-zero for
    activating, inactive, deactivating and failed. That is exactly the question
    its three call sites ask — "was something already serving before I touched
    anything" — and `activating` answering False is correct rather than a
    rounding error: a unit still coming up has no old process whose config we
    might be invalidating.

    Named so the unit tier can stub it. As an inline query() inside a domain
    module it was a live-host read that made a green suite a property of the
    machine rather than of the tree: one row and one mutation proof passed only
    where a live vide-oauth2-proxy.service happened to exist, and prove-teeth's
    pristine-green precondition turns that from a soft problem into a hard fail
    everywhere else."""
    return query(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def is_root() -> bool:
    """Whether this process can read what root can read.

    Named here rather than spelled `os.geteuid() == 0` at the call sites for two
    reasons, and the first is not style: `registry` is a DOMAIN module and the
    import-boundary invariant (TestI1) forbids it importing `os` at all — a
    domain module reaching for a system API directly is the coupling that census
    exists to refuse. The second is that every caller of this is a diagnostic
    deciding between "unhealthy" and "I cannot see", which is a distinction the
    unit tier has to be able to drive from both sides."""
    return os.geteuid() == 0


def unit_state(unit: str) -> str:
    """The `systemctl is-active` WORD — active, activating, deactivating,
    inactive, failed, reloading — or "unknown" when systemd says nothing.

    Distinct from unit_is_active on purpose, and the distinction is the whole
    reason this exists. That helper collapses six states into a boolean, which is
    right for "was something already serving"; it is wrong for a diagnostic that
    must call `failed` a fault and `activating` a non-event. A doctor branching on
    the boolean goes red on every healthy box that happens to be mid-boot, and a
    cron hook that cries wolf once is a cron hook nobody reads again.

    Named for the I11 reason: doctor's liveness verdict must be stubbable, or the
    rows covering it become properties of the machine running the tier rather than
    of this tree."""
    return query(["systemctl", "is-active", unit]).stdout.strip() or "unknown"


def group_entry(group: str) -> tuple[int, set[str]] | None:
    """(gid, supplementary members) for a group, or None when it does not
    resolve. Named for the same reason as group_exists: doctor asks this to tell
    "caddy never joined vide-proxy" from "it joined but the live process predates
    the membership" — two failure modes with the identical "every SSO request
    502s" symptom — and a question that important should not live as an argv and
    a hand-written `split(":")` inside a diagnostic."""
    import grp
    try:
        g = grp.getgrnam(group)
    except KeyError:
        return None
    return g.gr_gid, set(g.gr_mem)


def unit_is_failed(unit: str) -> bool:
    """`systemctl is-failed --quiet`. A unit that has burned its restart budget
    is `failed`, not `activating`, so a waiter can stop early and say something
    useful instead of running out the clock."""
    return query(["systemctl", "is-failed", "--quiet", unit]).returncode == 0


def unit_enable_state(unit: str) -> str:
    """`systemctl is-enabled` stdout word: enabled / disabled / masked /
    masked-runtime / static / …. Returned raw so callers can match `masked*` —
    `systemctl mask --runtime` reports `masked-runtime`, and both mean the
    operator switched this off."""
    return query(["systemctl", "is-enabled", unit]).stdout.strip()


def query(argv: list[str] | tuple[str, ...], *, input_text: str | None = None,
          timeout: float | None = 10.0) -> subprocess.CompletedProcess[str]:
    """Run a READ-ONLY command, captured. Never raises on rc != 0 — callers
    branch on the result. A wedged binary cannot hang a diagnostic: default
    timeout 10s (doctor's probes pass 3, mirroring `timeout 3` in bash)."""
    try:
        return subprocess.run(list(argv), capture_output=True, text=True,
                              input=input_text, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        return subprocess.CompletedProcess(list(argv), 124, stdout="", stderr=str(e))


def query_as(user: str, argv: list[str] | tuple[str, ...], *,
             timeout: float | None = 10.0) -> subprocess.CompletedProcess[str]:
    return query([*_AS_USER, user, "--", *argv], timeout=timeout)


def probe_as(user: str, argv: list[str] | tuple[str, ...], *,
             timeout: float | None = 10.0) -> bool:
    return query_as(user, argv, timeout=timeout).returncode == 0


# A loopback probe must NOT inherit urllib's module-global opener, and must not
# borrow net._opener() either: both carry a ProxyHandler that reads http_proxy
# from the environment — which config.load_config deliberately populates from
# .env so an operator's proxy reaches the DOWNLOADS. CPython's
# proxy_bypass_environment has no automatic 127.0.0.1 carve-out (only no_proxy),
# so a proxied box sent every /healthz to the proxy, which tried to reach
# 127.0.0.1 from ITS host and failed. The worst consequence was not a red
# doctor: rotate_sso reads a failed ping as "the proxy rejected the new cookie
# secret" and RESTORES the secret it was invoked to burn.
_LOOPBACK_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def healthz(port: int, *, path: str = "/healthz", timeout: float = 3.0) -> bool:
    """Loopback probe. LITERAL 127.0.0.1, never `localhost`: getaddrinfo may
    resolve ::1 first and hard-fail against a v4-only bind. `path` is widened so
    the shared proxy's /ping is a plain GET — never a User-Agent carve-out,
    which was the GHSA-5hvv-m4w4-gf6v bypass. Proxy-free by construction — see
    _LOOPBACK_OPENER.

    THE ONE EXCEPTION TO THIS MODULE'S "nothing here mutates". Against a port
    held by a systemd .socket unit, making the listening descriptor readable IS
    the activation trigger — so a probe can START the unit it is asking about.
    That is benign in itself (it heals rather than harms) but it has two
    consequences a caller must handle rather than discover:
      * `doctor --quiet` is the documented cron hook. Probing unconditionally
        would turn it into a scheduled `systemctl start` that silently undoes an
        operator's deliberate stop, on every tick.
      * a probe that starts a unit invalidates manager state sampled BEFORE it,
        so any predicate mixing the two must sample once, up front.
    Both are handled in oauth2proxy.proxy_health, which probes only in states
    where a probe cannot trigger. Written here because this is where the
    no-mutation contract is claimed.

    And the negative changed shape: against a held-but-unaccepted port,
    connect(2) SUCCEEDS — the kernel completes the handshake into the accept
    queue — so this returns False only after `timeout` elapses. The instant
    ECONNREFUSED that poll loops were written around no longer exists."""
    try:
        with _LOOPBACK_OPENER.open(f"http://127.0.0.1:{port}{path}", timeout=timeout):
            return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose socket is an AF_UNIX stream to a fixed path. The
    standard stdlib pattern for HTTP-over-unix-socket (what requests-unixsocket
    et al. do): honest status-line parsing, no re-implemented HTTP framing."""

    def __init__(self, sock_path: str, *, timeout: float) -> None:
        super().__init__("127.0.0.1", timeout=timeout)
        self._sock_path = sock_path

    def connect(self) -> None:  # noqa: D401
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._sock_path)
        self.sock = s


def healthz_unix(sock_path: str, *, path: str = "/healthz", timeout: float = 3.0) -> bool:
    """/healthz over an AF_UNIX socket. Same never-raises discipline as healthz.
    NOTE: VIDE runs as root, and CAP_DAC_OVERRIDE lets root connect through a
    0660 socket regardless of group — so a True here does NOT prove caddy can
    connect. Always pair it with socket_stat (the perms are the authz policy)."""
    conn = _UnixHTTPConnection(sock_path, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": "127.0.0.1"})
        resp = conn.getresponse()
        return 200 <= resp.status < 400
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


@dataclass(frozen=True, slots=True)
class SocketStat:
    is_socket: bool
    uid: int
    gid: int
    mode: int  # permission bits only (S_IMODE)


def socket_stat(path: str | Path) -> SocketStat | None:
    """lstat of a unix socket path; None if it does not exist. The stat — not a
    root HTTP probe — is the caddy-can-connect check (see healthz_unix).

    `lstat`, not `stat`, for the reason `path_facts` below argues at length: the
    caller is asking about the ENTRY, and a symlink answers that question about
    itself. Following it would report the innocent target. This is a DETECTOR,
    not the control — the control is that the socket's directory is root-owned
    (units/code-server@.service) so nothing can plant a symlink there in the
    first place. It is switched anyway because the pre-freeze correctness rested
    on an UNSTATED fact: a symlinked socket reported the target's uid, which
    happened to mismatch, and the reason no attacker could dodge that was that
    `chgrp` to a group you are not in is EPERM. This tree does not leave a
    load-bearing assumption unwritten."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return SocketStat(is_socket=stat_mod.S_ISSOCK(st.st_mode),
                      uid=st.st_uid, gid=st.st_gid, mode=stat_mod.S_IMODE(st.st_mode))


@dataclass(frozen=True)
class PathFacts:
    is_symlink: bool
    is_dir: bool
    is_file: bool
    uid: int
    gid: int
    mode: int  # permission bits only (S_IMODE)


def path_facts(p: str | Path) -> PathFacts | None:
    """Ownership and mode of ONE path; None if it does not exist. `lstat`, not
    `stat`, deliberately: the caller asks "may a third party rewrite what root is
    about to execute", and a symlink answers that question about ITSELF — a
    root-owned `.env` symlinked from a world-writable directory is the whole
    attack. `stat` would follow it and report the innocent target."""
    try:
        st = os.lstat(p)
    except OSError:
        return None
    return PathFacts(is_symlink=stat_mod.S_ISLNK(st.st_mode),
                     is_dir=stat_mod.S_ISDIR(st.st_mode),
                     is_file=stat_mod.S_ISREG(st.st_mode),
                     uid=st.st_uid, gid=st.st_gid,
                     mode=stat_mod.S_IMODE(st.st_mode))


def path_is_denied(p: str | Path) -> bool:
    """True when an lstat of this path fails for PERMISSION reasons rather than
    absence.

    `path_facts` maps every OSError to None, which is the right answer to its
    callers' question ("what is this path") and the wrong one for a diagnostic's
    ("is it missing, or can I not look"). Reporting EACCES as MISSING is how a
    healthy box gets restarted: it is the same conflation the socket rows were
    just fixed for one level down, and it reappears one level up the moment a
    row is allowed to run without root.

    TWO lstats, TWO moments, and that is fine rather than a race worth closing:
    this one runs only on the failure path, after path_facts has already returned
    None, and the two answers it distinguishes ("gone" vs "not mine to read")
    cannot swap into each other under any principal a diagnostic is racing —
    /run/vide is systemd's root-owned 0755 parent. A single call returning both
    would need a second return type for one caller."""
    try:
        os.lstat(p)
    except PermissionError:
        return True
    except OSError:
        return False
    return False


def proc_no_new_privs(pid: int, proc_root: Path = Path("/proc")) -> bool | None:
    """`NoNewPrivs` from /proc/<pid>/status; None when it cannot be read.

    One field, chosen because it answers the question a marker file cannot:
    is the RUNNING process actually governed by the unit VIDE ships? A converge
    re-asserts the unit but never restarts, so the process can legitimately
    predate its own hardening for a while — and a recorded "restart pending"
    would then go stale the moment an operator restarts by hand, which is how a
    diagnostic teaches people to stop reading it. This observes the property
    itself and heals itself."""
    try:
        text = (proc_root / str(pid) / "status").read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("NoNewPrivs:"):
            return line.split()[1] == "1"
    return None


def group_writer_uids(gid: int) -> frozenset[int] | None:
    """Every uid that can write through this gid: the group's supplementary
    members PLUS anyone whose passwd primary gid is it. None when the group
    cannot be resolved, so callers fail closed.

    This exists because "group-writable" is not the same question as "someone
    else can write". Debian and Ubuntu default to a umask of 002 AND to
    user-private groups, so a plain `git clone` produces a 0775 tree owned by
    `alice:alice` — group-writable by a group whose only member is alice. A gate
    that refused 0o020 outright would refuse the README's own first command on a
    stock box, which is the exact outcome such a gate exists to avoid.

    Both halves are needed: gr_mem lists SUPPLEMENTARY members only, so a second
    account carrying the gid as its primary would be invisible in it."""
    import grp
    import pwd as _pwd
    try:
        g = grp.getgrgid(gid)
    except KeyError:
        return None
    uids: set[int] = set()
    for name in g.gr_mem:
        try:
            uids.add(_pwd.getpwnam(name).pw_uid)
        except KeyError:
            return None  # a member we cannot resolve is not a member we can clear
    uids.update(p.pw_uid for p in _pwd.getpwall() if p.pw_gid == gid)
    return frozenset(uids)


def socket_path(user: str, run_dir: Path = Path("/run/vide")) -> Path:
    """The one place a code-server socket path is minted. Guards the 108-byte
    sockaddr_un.sun_path ceiling (comfortable for any legal 32-char username,
    but the check is cheap and permanent)."""
    p = run_dir / user / "code-server.sock"
    if len(str(p).encode()) > 107:
        from .errors import ConfigError
        raise ConfigError(f"socket path too long for AF_UNIX (>107 bytes): {p}")
    return p


def proc_groups(pid: int) -> set[int]:
    """Supplementary + primary gids of a running process, from
    /proc/<pid>/status 'Groups:'. Supplementary groups are read at process
    start, so this LIVE check is the only honest way to tell that a caddy which
    was added to vide-proxy has not been restarted yet."""
    try:
        text = Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return set()
    out: set[int] = set()
    for line in text.splitlines():
        if line.startswith("Groups:"):
            out |= {int(x) for x in line.split()[1:] if x.isdigit()}
        elif line.startswith("Gid:"):
            out |= {int(x) for x in line.split()[1:] if x.isdigit()}
    return out


def unit_main_pid(unit: str) -> int | None:
    """MainPID of a systemd unit, or None when not running."""
    out = query(["systemctl", "show", "-p", "MainPID", "--value", unit], timeout=10.0)
    pid = out.stdout.strip()
    return int(pid) if pid.isdigit() and pid != "0" else None


def user_uid(user: str) -> int | None:
    """The numeric uid behind a name, or None when there is no such user.

    Named beside listener_uids because that is what it is for: the kernel
    answers "who owns this listening socket" in numbers, and the one legitimate
    non-root holder of the fleet's hop — the proxy itself, before the
    reservation lands — has to be recognised by the same currency."""
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


#: /proc/net/tcp's `st` field, two hex digits. LISTEN is the socket that OWNS
#: the address; ESTABLISHED on the same local address is an ACCEPTED connection,
#: i.e. somebody being served on the hop right now.
_TCP_LISTEN = "0A"
_TCP_ESTABLISHED = "01"


@dataclass(frozen=True)
class HopHolders:
    """Who is on a loopback hop, SPLIT BY HOW SURE WE ARE.

    The split is the whole point and it encodes one rule: a signal that may be
    attacker-influenced can raise a warning and may never grant health.

    `certain`   — uids of listeners the kernel's own tables prove are serving
                  this v4 hop. Only these can make a box read `reserved`.
    `possible`  — uids of `::` listeners that MIGHT be serving it. procfs
                  exposes no IPV6_V6ONLY flag, and a v6only `[::]:<port>` bind
                  needs no privilege and legally coexists with the reservation
                  (that is what makes sshd's 0.0.0.0:22 + :::22 pair possible).
                  So these may alarm and may never reassure.
    `served`    — uids holding ACCEPTED connections on the hop. Not a holder
                  question at all: it is "who is answering right now", which is
                  the state MSG_PROXY_PORT_SQUATTED's step 2 calls not optional
                  — an attacker that hands the listening socket back while
                  staying alive keeps answering everything Caddy already had
                  open, and every listener-only check goes green behind it."""

    certain: frozenset[int]
    possible: frozenset[int]
    served: frozenset[int]

    @property
    def on_hop(self) -> set[int]:
        """Everything that may be listening on the hop. For alarms only."""
        return set(self.certain) | set(self.possible)


def _hex_addr(packed: bytes) -> str:
    """An address as /proc/net/tcp prints it: the kernel does `%08X` (or four of
    them for v6) over the in-memory u32 words, WITHOUT converting byte order, so
    the rendering is host-endian and 127.0.0.1 reads `0100007F` on every machine
    this project supports and `7F000001` on a big-endian one. Derived rather
    than hardcoded for exactly that reason — a hardcoded constant would be a
    silent mis-compare on the first BE box, i.e. a listener that matches nothing
    and a reservation that reads as absent."""
    return "".join(f"{int.from_bytes(packed[i:i + 4], sys.byteorder):08X}"
                   for i in range(0, len(packed), 4))


def _sock_uids(text: str, wanted: set[str], state: str) -> set[int]:
    """The uid column of every row in `state` whose local address is in `wanted`.

    Field order is fixed by the kernel's own seq_printf: sl(0) local(1) rem(2)
    st(3) tx:rx(4) tr:when(5) retrnsmt(6) **uid(7)**."""
    uids: set[int] = set()
    for line in text.splitlines()[1:]:          # [0] is the column header
        f = line.split()
        if len(f) < 8 or f[3].upper() != state:
            continue
        if f[1].upper() in wanted and f[7].isdigit():
            uids.add(int(f[7]))
    return uids


def hop_holders(port: int, *, addr: str = "127.0.0.1",
                proc_root: Path = Path("/proc")) -> HopHolders | None:
    """Who is on <addr>:<port>, by UID. None only when the kernel could not be
    read at all.

    THE ONE SIGNAL IN THIS SECTION AN ATTACKER DOES NOT SUPPLY, and that is the
    whole reason it exists. The reader this replaced parsed `ss -Htlnp`, whose
    process column renders `users:(("<comm>",pid=N,fd=M))` — and <comm> is set
    by the process itself through prctl(PR_SET_NAME), no privilege required. So
    a squatter naming itself the five characters `pid=1` put a 1 into any regex
    over that line, cleared the usurpation suspicion, and thereby RESTORED the
    affirmative reservation row over a live squat: the absence of a
    negative was load-bearing in the green direction, which is the inversion
    this project keeps paying for. Here the answer is a kernel-formatted integer
    in its own column, and the threat this release names — "any local account,
    no VIDE instance, no role, no sudo" — cannot make it read 0.

    NO PRIVILEGE REQUIRED, which is the second thing it buys. /proc/net/tcp is
    world-readable, so attribution stops being a root-only capability and a
    non-root `vide doctor` no longer has to choose between assuming the good
    case and reddening a healthy fleet. `doctor --quiet` is the documented cron
    hook; it now gets the real answer.

    THE ADDRESS IS PART OF THE QUESTION. `ss "sport = :<port>"` matches every
    local address, so a PID-1 listener on some unrelated `[::1]:<port>` merged
    into the same answer and exonerated a squatter on the fleet's actual hop.
    Here the compare is against the exact rendering of <addr>:<port>, plus every
    other address that genuinely carries v4 traffic to it: 0.0.0.0, the
    v4-mapped forms ::ffff:<addr> and ::ffff:0.0.0.0 (an AF_INET6 socket bound
    to a mapped address serves v4 and only v4), and — conditionally — ::.

    WHY :: IS RANKED RATHER THAN COUNTED, and this is the subtle half. A `::`
    listener serves the fleet's v4 hop only when it is NOT IPV6_V6ONLY, and the
    kernel makes those two cases distinguishable from this very read:

      * a NON-v6only `[::]:<port>` bind CONFLICTS with a bound `<addr>:<port>`
        (ipv6_rcv_saddr_equal's wildcard branch) and gets EADDRINUSE, so while
        the reservation is in effect a dual-stack wildcard cannot exist;
      * a V6ONLY one binds happily alongside it — that is the entire purpose of
        IPV6_V6ONLY, and it is what makes stock sshd's 0.0.0.0:22 + :::22 pair
        possible. It needs no privilege and it carries no v4 traffic at all.

    So a `::` row that coexists with a v4 match is PROVABLY v6only and provably
    harmless. Counting it unconditionally handed any local account a one-bind
    way to put a second uid into the answer on a correctly reserved box — which
    clears `root_held`, sets `usurped`, and fires a containment ladder whose
    first step is `systemctl stop caddy`. That is a deliberate fleet outage,
    caused by a listener that cannot receive a single forward_auth sub-request.
    Hence: discard `::` entirely when anything definite answered.

    AND WHEN NOTHING DEFINITE ANSWERED, `::` GOES INTO `possible`, NEVER INTO
    `certain`. It may be dual-stack and really serving the hop — so it must be
    able to raise an alarm — and it may be v6only and serving nothing — so it
    must never be able to say "reserved". That is the same rule this module
    applies to every attacker-influenced signal, and putting a `::` row into
    `certain` would be the mirror image of the bug above: a false GREEN instead
    of a false alarm.

    The residual is a microsecond race — the v4 holder closing between the two
    reads, which would promote a harmless v6only row into `possible`. It errs
    toward not-reassuring rather than toward silence, which is the right
    direction.

    PER NETWORK NAMESPACE, like the sockets themselves — which is correct: the
    question is about the namespace VIDE and Caddy live in."""
    try:
        packed = socket.inet_aton(addr)
    except OSError:
        return None
    port_hex = f"{port:04X}"
    # Built OUTSIDE the f-strings: a backslash inside an f-string expression is
    # a SyntaxError before 3.12, and this project's floor is 3.10.
    v4_wanted = {_hex_addr(packed) + ":" + port_hex,
                 _hex_addr(bytes(4)) + ":" + port_hex}
    # v4-MAPPED rows live in the v6 table and are unambiguous: __inet6_bind sets
    # inet_rcv_saddr from the embedded v4 address, so these serve v4 traffic and
    # nothing else. Both forms — the specific address and the wildcard.
    mapped_wanted = {_hex_addr(bytes(10) + b"\xff\xff" + packed) + ":" + port_hex,
                     _hex_addr(bytes(10) + b"\xff\xff" + bytes(4)) + ":" + port_hex}
    any6_wanted = {_hex_addr(bytes(16)) + ":" + port_hex}
    # THE TWO TABLES ARE NOT SYMMETRIC, and treating them as if they were was the
    # last place this section guessed. /proc/net/tcp is MANDATORY: it is the v4
    # table, it is where the fleet's hop lives, and a box without it is a box
    # this reader cannot answer about. /proc/net/tcp6 is OPTIONAL: it is simply
    # absent on a kernel built without IPv6, which is a normal box.
    #
    # Read the other way — "if either opened, answer" — an unreadable v4 table
    # produced an EMPTY certain set, which doctor reads as "nothing is listening
    # on the fleet's hop" and answers with "the fleet's authorization port is
    # open right now", whose remedy restarts the gate. A measurement that never
    # happened, prescribing an outage.
    try:
        v4_text = (proc_root / "net/tcp").read_text()
    except OSError:
        return None
    tables = {"net/tcp": v4_text}
    try:
        tables["net/tcp6"] = (proc_root / "net/tcp6").read_text()
    except OSError:
        pass
    certain: set[int] = set()
    possible: set[int] = set()
    served: set[int] = set()
    certain |= _sock_uids(tables["net/tcp"], v4_wanted, _TCP_LISTEN)
    served |= _sock_uids(tables["net/tcp"], v4_wanted, _TCP_ESTABLISHED)
    if "net/tcp6" in tables:
        certain |= _sock_uids(tables["net/tcp6"], mapped_wanted, _TCP_LISTEN)
        possible = _sock_uids(tables["net/tcp6"], any6_wanted, _TCP_LISTEN)
        served |= _sock_uids(tables["net/tcp6"],
                             mapped_wanted | any6_wanted, _TCP_ESTABLISHED)
    # The ranking, argued above: a `::` row that coexists with a definite one is
    # provably v6only, so it is not merely demoted — it is dropped.
    return HopHolders(certain=frozenset(certain),
                      possible=frozenset() if certain else frozenset(possible),
                      served=frozenset(served))


def path_mtime(p: Path) -> float | None:
    """Last-modified time of a path, or None when it cannot be read.

    Named here for the I11 reason and one sharper one: this stat decides whether
    the fleet's sole authorization gate restarts, and while it lived inside
    oauth2proxy the unit tier could only cover the decision by mocking the whole
    predicate — which is how a predicate that restarted on every run shipped
    green. A seam the tier can stub is what lets the decision be tested as a
    decision.

    None is "I could not look", never "it is old": the caller must not treat an
    unreadable input as evidence about the running process."""
    try:
        return p.stat().st_mtime
    except OSError:
        return None


#: /proc/<pid>/stat field 22 (`starttime`), as an index into the fields AFTER
#: comm. proc_pid_stat(5) numbers fields from 1, and field 3 (`state`) is the
#: first one past comm, so field N sits at index N - 3. Written as the
#: subtraction rather than as a bare 19 because that off-by-three is the single
#: most likely thing here to rot, and a wrong index is SILENT: the neighbouring
#: fields (num_threads, itrealvalue, cutime) are small integers that yield a
#: perfectly plausible timestamp somewhere near the box's boot instant.
_STAT_STARTTIME_IDX = 22 - 3


def _btime(proc_root: Path) -> float | None:
    """CLOCK_REALTIME seconds at which this kernel's boot clock read zero, from
    /proc/stat's `btime` line — "boot time, in seconds since the Epoch"
    (proc(5)). None when the line is absent or unparseable.

    RE-READ EVERY TIME, NEVER CACHED, and that is load-bearing rather than lazy.
    The kernel computes it at each read as (realtime offset - suspend offset), so
    a settimeofday step MOVES it: getboottime64's own kernel-doc says "Calls to
    settimeofday will affect the value returned (which basically means that
    however wrong your real time clock is at boot time, you get the right time
    here)". That is what makes btime + starttime a start time in the CURRENT
    realtime frame — the frame a file's st_mtime was stamped in — and it is why
    the clock-step caveat on oauth2proxy._restart_reasons is about the FILES and
    not about this number. Suspend-invariant for the same reason: a suspend
    advances realtime and boottime by the same interval, so their difference
    does not move. The clock-STEP consequence — one restart, self-clearing — is
    argued at oauth2proxy._restart_reasons, which is where the comparison this
    number feeds actually happens.

    ONE KNOWN SHAPE WHERE THIS RETURNS None ON A HEALTHY BOX: lxcfs has a
    standing class of bugs in which /proc/stat is truncated before the `btime`
    line on wide machines. Inside such a container the reader answers None
    permanently, so `upgrade-sso` reports "these inputs did not settle it" on
    every run rather than restarting — fail-safe and loud, which is the design
    working, but it is a PERMANENT unreadable rather than a transient one. (The
    arithmetic itself survives lxcfs: it copies every non-cpuN line verbatim, so
    btime passes through as the host's, which is the frame `starttime` is in
    because lxcfs does not overlay /proc/<pid>/stat. A reader built on
    /proc/uptime instead would be wrong there, which is part of why this one is
    not.)"""
    try:
        text = (proc_root / "stat").read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("btime "):
            parts = line.split()
            return float(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    return None


def proc_start_realtime(pid: int, proc_root: Path = Path("/proc")) -> float | None:
    """When the process behind `pid` started, in CLOCK_REALTIME seconds since the
    epoch — the SAME clock st_mtime is in, which is the only reason the two can
    be compared at all. None when the answer cannot be established.

    The live answer to "is the RUNNING process older than the config it is
    supposed to be running with" — a question a file comparison structurally
    cannot answer, because the thing that writes those files is a converge, and
    by the time the operator reaches the verb that applies them the files are
    already current. Comparing them against each other then says "nothing
    changed" on precisely the box that has not applied anything.

    NOT THE MTIME OF /proc/<pid>, WHICH IS WHAT THIS REPLACES, and the old
    version failed in the quiet direction. procfs allocates a pid's inode
    lazily, at lookup, and stamps it with current_time(); the dentry for a LIVE
    task is reclaimable, so ordinary memory pressure — or a plain
    `echo 2 > /proc/sys/vm/drop_caches`, an unremarkable ops action — recreates
    it with a FRESH timestamp. The recorded time could therefore only ever be
    LATER than the true start, so the caller's `mtime > started` went False and
    the staleness check declined to restart exactly the box it was written for,
    intermittently and with nothing to see.

    THE PARSE, which is the part that must not be "simplified" into a split().
    Field 2 is comm, printed RAW between parentheses by the kernel: it may
    contain spaces and it may contain ')', because it is a filename (or whatever
    the process handed to prctl(PR_SET_NAME)). Every field after it is numeric,
    so the LAST ')' on the line is comm's closing paren. Same idiom as
    executor._stopped, which reads field 3 the same way. BYTES, not text: comm is
    arbitrary bytes, and read_text() would raise on a process whose name is not
    valid UTF-8.

    THE UNITS. Field 22 is in CLOCK TICKS since boot — proc_pid_stat(5): "Since
    Linux 2.6, the value is expressed in clock ticks (divide by
    sysconf(_SC_CLK_TCK))". That is USER_HZ (100 everywhere this project runs)
    and NOT CONFIG_HZ, which is why it is asked for rather than assumed. Since
    Linux 5.5 the field is taken from task->start_boottime, i.e. CLOCK_BOOTTIME,
    which counts suspended time — and btime is realtime-minus-boottime, so the
    two terms are in matching frames and the sum survives a suspend/resume. The
    supported floor (Ubuntu 22.04 ships 5.15) is comfortably above that. Both
    terms also carry the same time-namespace offset (timens_add_boottime_ns in
    fs/proc/array.c, timens_sub_boottime in fs/proc/stat.c), so the pair stays
    self-consistent inside a container as well as on the host — but note that
    the timens half landed LATER than 5.5 (~5.11), so on 5.6-5.10 btime was
    timens-shifted while starttime was not and the sum was off by the namespace
    offset inside a time namespace. Out of the supported span, and recorded
    because a future floor change would otherwise re-read the 5.5 above and
    conclude wrongly. time_namespaces(7) does not list either file among the
    affected interfaces; the man page is behind the kernel here, so cite the
    source rather than the page.

    None ON ANYTHING UNREADABLE OR UNPARSEABLE — a dead pid, hidepid=, a masked
    or absent /proc, a /proc/stat with no btime line, a sysconf that will not
    answer. The caller decides what an unknown means; this returns "I do not
    know" rather than a number that looks like an answer."""
    try:
        raw = (proc_root / str(pid) / "stat").read_bytes()
    except OSError:
        return None
    tail = raw.rpartition(b")")[2].split()
    if len(tail) <= _STAT_STARTTIME_IDX:
        return None
    try:
        ticks = int(tail[_STAT_STARTTIME_IDX])
    except ValueError:
        return None
    # THE /proc READ ABOVE MUST STAY ABOVE THIS CALL. `os.sysconf` does not
    # exist on non-Unix and `except (ValueError, OSError)` does not catch
    # AttributeError — hoisting this out of the function as a "compute the
    # constant once" tidy-up turns a clean None on a Windows checkout into an
    # import-time crash. It is cheap here: the /proc read has already failed and
    # returned by then.
    try:
        hz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError):
        return None
    if hz <= 0:
        return None
    btime = _btime(proc_root)
    if btime is None:
        return None
    return btime + ticks / hz


def unit_listen_streams(unit: str) -> list[str]:
    """The addresses the LOADED .socket unit is configured for, as systemd holds
    them — which is not the same as the unit file on disk, and not the same as
    what is bound.

    WHAT THIS ANSWERS IS THE CONFIGURATION, NOT THE BINDING, and getting that
    backwards in this docstring while the caller's comment said the opposite cost
    a round. `property_get_listen` iterates the unit's `ports` list, so
    `systemctl show -p Listen` reports the address the LOADED UNIT CONFIGURES —
    whether or not anything is bound to it.

    Which is exactly why it is worth reading, and why it must be paired with a
    kernel read rather than trusted alone. Two different states both end with the
    fleet's real hop free, and only the pair tells them apart:

      * the unit was RE-RENDERED and reloaded onto a new address — systemd
        re-claims a serialized listening fd only for an address that still
        matches the reloaded configuration, so a CHANGED address drops the old
        descriptor and binds nothing. This reader then answers the NEW address
        while the manager holds neither;
      * the pin moved and the unit was never re-rendered — this reader answers
        the OLD address, which is still genuinely held.

    Both read healthy on every manager-side signal, which is the FALSE CLOSURE
    this reader exists inside of. `_covers_port` compares what comes back against
    the pin; `hop_holders` says whether anything is actually there.

    `--value` is passed, so the lines carry NO `Listen=` prefix: each is
    `127.0.0.1:4180 (Stream)`. That matters to the caller — _covers_port
    compares `ln.split()[0]` against the address and DEPENDS on there being no
    prefix. The address is returned verbatim; parsing is the caller's."""
    out = query(["systemctl", "show", "-p", "Listen", "--value", unit], timeout=10.0)
    return [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]


def unit_n_restarts(unit: str) -> int | None:
    """How many times systemd has restarted this unit, or None if unreadable.

    This exists because the shared proxy's start limiter had to be turned off: a
    limiter that fires makes systemd close the listening descriptor and hand the
    fleet's authorization port back to the box. The cost of turning it off is
    that a permanently broken proxy no longer rests in `failed` where a status
    line would show it — it rests in `activating (auto-restart)`, forever, which
    looks far more alive than it is. NRestarts is what replaces that signal.

    Available since systemd 235, so it is safe across the whole supported span."""
    out = query(["systemctl", "show", "-p", "NRestarts", "--value", unit], timeout=10.0)
    n = out.stdout.strip()
    return int(n) if n.isdigit() else None


def https_ok(url: str, *, timeout: float = 5.0) -> bool:
    """Read-only HTTPS reachability probe, through the SAME hardened opener as
    downloads (product UA — Cloudflare 403s Python-urllib; https-only
    redirects — no silent downgrade even on a probe)."""
    from . import net
    try:
        with net._opener().open(url, timeout=timeout):
            return True
    except Exception:  # noqa: BLE001 — a probe answers yes/no, never raises
        return False


@dataclass(frozen=True, slots=True)
class OsRelease:
    id: str
    id_like: str
    pretty_name: str


def os_release(path: Path) -> OsRelease | None:
    """Parse, never source (bash had to subshell-contain the sourcing because
    os-release leaks VERSION etc. into a `set -u` scope; Python just parses).
    The field fact survives the port: Debian ships NO ID_LIKE — every consumer
    must tolerate missing keys (a whitespace-misalignment here once slid
    PRETTY_NAME into id_like in bash)."""
    try:
        text = path.read_text()
    except OSError:
        return None
    kv: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        kv[k.strip()] = v
    return OsRelease(id=kv.get("ID", ""), id_like=kv.get("ID_LIKE", ""),
                     pretty_name=kv.get("PRETTY_NAME", ""))


def uname_m(override: str = "") -> str:
    """Machine hardware name; VIDE_UNAME_M seam mirrors the bash one so the
    arch gate stays a pure predicate drivable without special hardware."""
    if override:
        return override
    return os.uname().machine


def systemd_present() -> bool:
    """sd_booted(3) semantics: /run/systemd/system exists iff systemd is PID 1."""
    return Path("/run/systemd/system").is_dir()


def have_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def visudo_cmd() -> str | None:
    """Resolve visudo the way ldconfig_has resolves ldconfig: it lives in
    /usr/sbin on Debian/Ubuntu, and a PATH without sbin would misread
    'package missing' even with the sudo package installed."""
    found = shutil.which("visudo")
    if found:
        return found
    for cand in ("/usr/sbin/visudo", "/sbin/visudo"):
        if os.access(cand, os.X_OK):
            return cand
    return None


def ldconfig_has(soname: str) -> bool:
    """Shared-library probe via ldconfig -p (NOT dpkg: a box that got the .so
    another way must not be forced to install a package). ldconfig lives in
    /sbin — a PATH without sbin would silently miss it."""
    ldconfig = shutil.which("ldconfig") or "/sbin/ldconfig"
    out = query([ldconfig, "-p"], timeout=15.0)
    return out.returncode == 0 and soname in out.stdout


def listening_ports() -> set[int]:
    """Every locally-listening TCP port, via the same `ss -Htln` the bash used
    (and the arbiter itself uses). Column-based and tolerant: iproute2's
    address forms vary (`*:22`, `[::]:22`, `127.0.0.1:9797`)."""
    out = query(["ss", "-Htln"], timeout=10.0)
    ports: set[int] = set()
    if out.returncode != 0:
        return ports
    for line in out.stdout.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        addr = cols[3]
        _, _, tail = addr.rpartition(":")
        if tail.isdigit():
            ports.add(int(tail))
    return ports


def port_free(port: int) -> bool:
    out = query(["ss", "-Htln", f"sport = :{port}"], timeout=10.0)
    return out.returncode == 0 and not out.stdout.strip()


def pnpm_global_bin_dir(pnpm_bin: Path, pnpm_home: Path) -> str:
    """Observe where `pnpm add -g` drops shims: `pnpm bin -g` under a throwaway
    HOME with XDG_CONFIG_HOME/XDG_DATA_HOME/npm_config_globalbindir REMOVED —
    otherwise a host-local global-bin-dir override in root's own config would
    be baked into every user's profile, where that config does not exist.
    Returns '' on any failure (the caller degrades to the safe default)."""
    import tempfile
    home = tempfile.mkdtemp(prefix="vide-probe.")
    try:
        env = {k: v for k, v in os.environ.items()
               if k not in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "npm_config_globalbindir")}
        env["HOME"] = home
        env["PNPM_HOME"] = str(pnpm_home)
        out = subprocess.run([str(pnpm_bin), "bin", "-g"], capture_output=True,
                             text=True, env=env, timeout=15, check=False)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""
    finally:
        shutil.rmtree(home, ignore_errors=True)
