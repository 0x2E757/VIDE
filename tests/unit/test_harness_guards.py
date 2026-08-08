"""Static guards over the container and host-smoke gates (tests/integration/*,
tests/vide-branch/*, tests/sso-mode/*, tests/parity/*).

Why they live in the unit tier rather than inside each gate: these are the rules
a gate must hold to in order to be TRUSTWORTHY — never `--privileged`, never
`--network=host`, the repo mounted read-only, no secret on argv. A gate cannot be
the sole judge of its own containment, and these guards must be green even when
the expensive gates are not run at all.

They read the shell sources as text and cost milliseconds. All but one are pure
stdlib; TestTheDocumentedTestSeamStillWorks imports vide, because the claim it
guards is exactly that a gate's value and the product's acceptance of it agree —
which cannot be checked from either side alone.

A forbidden construct mentioned in a COMMENT is not a violation — these files
deliberately discuss what they forbid. Only code lines count.
"""
from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# Self-sufficient on purpose (see the guard below that enforces exactly this):
# a bare `from vide import …` would make this module importable only through
# run.py, silently defeating every prove-teeth row that names one of its tests.
sys.path.insert(0, str(REPO / "src"))
IT = REPO / "tests" / "integration"


def code_lines(path: Path) -> list[str]:
    """Each line with any trailing comment stripped (naive '#' split — the
    same soundness ceiling the bash `^[^#]*` greps had, stated as they stated
    it: a grep over shell cannot be sound; the arbiter itself is the backstop)."""
    out = []
    for line in path.read_text().splitlines():
        out.append(line.split("#", 1)[0])
    return out


def code_text(path: Path) -> str:
    return "\n".join(code_lines(path))


class TestBlackBoxBoundary(unittest.TestCase):
    """The arbiter may touch only VIDE's external surface. A gate that reaches
    into internals starts passing for the wrong reason: red must mean "the
    behaviour is wrong", never "the test knew too much"."""

    def test_never_sources_lib(self) -> None:
        pat = re.compile(r"(^|\s)(\.|source)\s+\S*lib/[a-z]+\.sh")
        for sh in sorted(IT.glob("*.sh")):
            for n, line in enumerate(code_lines(sh), 1):
                self.assertIsNone(pat.search(line), f"{sh.name}:{n} sources lib/*.sh")

    def test_calls_no_internal_vide_function(self) -> None:
        internals = (
            "ensure_node_pnpm", "ensure_config", "ensure_code_server",
            "claim_port", "get_port", "toolchain_ok", "toolchain_report",
            "resolve_target_user", "emit_caddy_snippet", "_write_config",
            "_nvm_resolve_bindir", "_pnpm_resolve_bin",
        )
        pat = re.compile(r"\b(" + "|".join(internals) + r")\b")
        body = IT / "in-container.sh"
        for n, line in enumerate(code_lines(body), 1):
            self.assertIsNone(pat.search(line), f"in-container.sh:{n} calls a VIDE internal")


class TestHostSafety(unittest.TestCase):
    """i2 — run.sh is the only host-touching file; these flags would put a real
    code-server (real password, shell behind it) on a real interface, or hand a
    container escape host root."""

    def _forbid(self, pattern: str, why: str) -> None:
        pat = re.compile(pattern)
        for n, line in enumerate(code_lines(IT / "run.sh"), 1):
            self.assertIsNone(pat.search(line), f"run.sh:{n}: {why}")

    def test_never_privileged(self) -> None:
        self._forbid(r"--privileged", "--privileged disables seccomp/AppArmor")

    def test_never_host_network(self) -> None:
        self._forbid(r"--network[= ]host", "host network = live IDE on the public interface")

    def test_never_publishes_ports(self) -> None:
        self._forbid(r"podman run.*(\s-p\s|--publish)|^\s*(-p|--publish)[\s=]",
                     "published port = IDE reachable from outside the netns")

    def test_never_adds_capabilities(self) -> None:
        self._forbid(r"--cap-add", "rootless + --systemd=always needs no capability")

    def test_never_disables_tls_verification(self) -> None:
        for sh in sorted(IT.glob("*.sh")):
            for n, line in enumerate(code_lines(sh), 1):
                self.assertIsNone(re.search(r"--insecure|curl[^|]*\s-k\s", line),
                                  f"{sh.name}:{n} disables TLS verification")

    def test_repo_mounted_read_only(self) -> None:
        self.assertIn(":/vide:ro", code_text(IT / "run.sh"),
                      "the repo mount must be read-only")

    def test_refuses_rootful_by_default(self) -> None:
        text = code_text(IT / "run.sh")
        self.assertIn("VIDE_ITEST_ALLOW_ROOTFUL", text)
        self.assertIn("exit 77", text, "rootful refusal must fail closed (EX_NOPERM)")


class TestContainerRefusal(unittest.TestCase):
    """i3 — in-container.sh mutates /opt, /etc, /usr/local and systemd; invoked
    on a host by mistake it must abort before the first write."""

    def test_refusal_exists(self) -> None:
        text = (IT / "in-container.sh").read_text()
        self.assertIn("containerenv", text)
        self.assertIn("VIDE_IN_THROWAWAY_CONTAINER", text)

    def test_refusal_precedes_every_mutation(self) -> None:
        first_logic = first_refusal = None
        for n, line in enumerate(code_lines(IT / "in-container.sh"), 1):
            if first_logic is None and re.match(r"^(if|[a-zA-Z_]+=)", line):
                first_logic = n
            if first_refusal is None and "containerenv" in line:
                first_refusal = n
        self.assertIsNotNone(first_refusal, "no refusal guard found")
        self.assertEqual(first_logic, first_refusal,
                         "the refusal must be the FIRST logic in the file")


class TestSecretHandling(unittest.TestCase):
    """i4 — the one-time password must never reach argv (/proc/<pid>/cmdline is
    world-readable)."""

    def test_password_reaches_curl_off_argv(self) -> None:
        self.assertIn('--data-urlencode "password@',
                      (IT / "in-container.sh").read_text())

    def test_no_password_interpolated_into_data_value(self) -> None:
        pat = re.compile(r"--data[a-z-]*\s+[\"']?password=\$")
        for n, line in enumerate(code_lines(IT / "in-container.sh"), 1):
            self.assertIsNone(pat.search(line), f"in-container.sh:{n} puts the password on argv")


class TestLoadBearingAssertions(unittest.TestCase):
    """i5 — every historical toolchain bug was invisible to root and visible
    only to the target user through a LOGIN shell; the negative controls are
    what keep the greens from being vacuous."""

    def test_toolchain_proven_through_login_shell(self) -> None:
        self.assertRegex(code_text(IT / "in-container.sh"),
                         re.compile(r"^as_user\(\)\s*\{\s*su - ", re.M),
                         "as_user must be a LOGIN shell (su - user)")

    def test_nologin_control_exists(self) -> None:
        self.assertIn("as_user_nologin", (IT / "in-container.sh").read_text())

    def test_traversal_negative_control(self) -> None:
        self.assertIn("chmod 700 /opt/nvm", code_text(IT / "in-container.sh"))

    def test_wrong_password_negative_control(self) -> None:
        self.assertIn("a wrong password does NOT authenticate",
                      (IT / "in-container.sh").read_text())

    def test_containerfiles_assert_systemd_init(self) -> None:
        for distro in ("debian", "ubuntu"):
            cf = IT / f"Containerfile.{distro}"
            self.assertIn("readlink -f /sbin/init", cf.read_text(),
                          f"{cf.name} must assert /sbin/init is systemd at build time")


class TestVideBranchGateSafety(unittest.TestCase):
    """The vide-branch gate (tests/vide-branch/) runs the same untrusted
    `curl | sh` installers under the same threat model as the arbiter — the
    identical host-safety and container-refusal rules apply to it."""

    VB = REPO / "tests" / "vide-branch"

    def _forbid(self, pattern: str, why: str) -> None:
        pat = re.compile(pattern)
        for sh in sorted(self.VB.glob("*.sh")):
            for n, line in enumerate(code_lines(sh), 1):
                self.assertIsNone(pat.search(line), f"{sh.name}:{n}: {why}")

    def test_never_privileged(self) -> None:
        self._forbid(r"--privileged", "--privileged disables seccomp/AppArmor")

    def test_never_host_network(self) -> None:
        self._forbid(r"--network[= ]host", "host network = live IDE on the public interface")

    def test_never_publishes_ports(self) -> None:
        self._forbid(r"podman run.*(\s-p\s|--publish)|^\s*(-p|--publish)[\s=]",
                     "published port = IDE reachable from outside the netns")

    def test_never_adds_capabilities(self) -> None:
        self._forbid(r"--cap-add", "rootless + --systemd=always needs no capability")

    def test_never_disables_tls_verification(self) -> None:
        self._forbid(r"--insecure|curl[^|]*\s-k\s", "TLS verification stays on")

    def test_repo_mounted_read_only(self) -> None:
        self.assertIn(":/vide:ro", code_text(self.VB / "run.sh"))

    def test_refuses_rootful_by_default(self) -> None:
        text = code_text(self.VB / "run.sh")
        self.assertIn("VIDE_ITEST_ALLOW_ROOTFUL", text)
        self.assertIn("exit 77", text)

    def test_in_container_refusal_precedes_every_mutation(self) -> None:
        first_logic = first_refusal = None
        for n, line in enumerate(code_lines(self.VB / "in-container.sh"), 1):
            if first_logic is None and re.match(r"^(if|[a-zA-Z_]+=)", line):
                first_logic = n
            if first_refusal is None and "containerenv" in line:
                first_refusal = n
        self.assertIsNotNone(first_refusal, "no refusal guard found")
        self.assertEqual(first_logic, first_refusal,
                         "the container-marker refusal must be the first logic")


class TestTheInstallerUrlRemedyNamesAVerbThatReadsIt(unittest.TestCase):
    """`vide toolchain` converges Node and pnpm only. `cfg.code_server_installer_url`
    has exactly one consumer, in codeserver.py, reached from `vide upgrade` and
    from a first install — never from `toolchain`. So both registers published a
    one-line fix that, on the day the code-server URL actually moved, would have
    exited 0 having done nothing.

    A CONSTRAINT ON A COLLISION rather than a positive match on a wording, so the
    prose can be rewritten freely and only the untrue pairing is refused. And not
    a flat ban on the two appearing together: the corrected text names both verbs
    on purpose, precisely to say they are different — which the first draft of
    this guard refused, and it was the guard that was wrong."""

    def test_the_toolchain_verb_is_never_the_only_one_offered_for_that_row(self) -> None:
        for name in ("README.md", ".env.example"):
            body = (REPO / name).read_text()
            for para in body.split("\n\n"):
                if "VIDE_CODE_SERVER_INSTALLER_URL" not in para:
                    continue
                if "vide toolchain" not in para:
                    continue
                self.assertIn(
                    "vide upgrade", para,
                    f"{name}: a passage names VIDE_CODE_SERVER_INSTALLER_URL and "
                    f"offers `vide toolchain` without `vide upgrade`. That verb "
                    f"never reads that row — its only consumer is reached from "
                    f"`vide upgrade` and from a first install — so on the day the "
                    f"URL moves, the published fix exits 0 having done nothing.")

    def test_the_guard_is_looking_at_something(self) -> None:
        # A negative pair over paragraphs that do not exist passes trivially.
        for name in ("README.md", ".env.example"):
            self.assertIn("VIDE_CODE_SERVER_INSTALLER_URL", (REPO / name).read_text(),
                          f"{name} no longer mentions the row this guard is about")


class TestHostTiersInstallFromATreeTheGateAccepts(unittest.TestCase):
    """A host tier that installs VIDE from a world-writable ancestor cannot pass,
    because the checkout gate refuses exactly that with exit 78 — and it is right
    to: anyone could swap what root is about to execute.

    This exists because `host-smoke/rollback.sh` cloned into `/var/tmp/...` for
    months. `/var/tmp` is 1777, so the tier could not have passed on any stock box,
    and nobody reading it noticed — the gate it was tripping is one of the things
    that tier exists to exercise, so the failure looked like the subject. It needs a DURABLE
    path (the installed `/usr/local/bin/vide` symlinks into the tree that
    installed it), and durable is what made `/var/tmp` tempting.

    The sanctioned prefixes are root-owned on a stock Debian/Ubuntu box and
    survive a reboot. `/tmp` and `/var/tmp` are neither of those things at once."""

    ROOT_OWNED = ("/opt/", "/usr/local/", "/root/")

    def test_no_host_tier_clones_where_the_gate_would_refuse(self) -> None:
        import re as _re
        seen = 0
        for path in sorted((REPO / "tests" / "host-smoke").glob("*.sh")):
            body = path.read_text()
            for m in _re.finditer(r"^([A-Z_]+)=(/[\w./-]+)\s*$", body, _re.M):
                var, value = m.group(1), m.group(2)
                if "clone" not in value.lower() and "CLONE" not in var:
                    continue
                seen += 1
                self.assertTrue(
                    value.startswith(self.ROOT_OWNED),
                    f"{path.name}: {var}={value} is a checkout root under a "
                    f"directory that is not root-owned on a stock box. The "
                    f"checkout gate refuses it with exit 78, so the tier cannot "
                    f"pass anywhere. Use one of {self.ROOT_OWNED}.")
        # A census that finds nothing is a census that cannot fail.
        self.assertGreater(seen, 0, "no clone root found in tests/host-smoke — "
                                    "this guard has stopped looking at anything")


class TestSsoModeGateSafety(unittest.TestCase):
    """The sso-mode gate (tests/sso-mode/) runs the same untrusted installers
    under the same threat model as the arbiter, and additionally mints real
    OIDC tokens — the host-safety rules apply, plus IdP-specific ones."""

    SM = REPO / "tests" / "sso-mode"

    def _forbid(self, pattern: str, why: str) -> None:
        pat = re.compile(pattern)
        for sh in sorted(self.SM.glob("*.sh")):
            for n, line in enumerate(code_lines(sh), 1):
                self.assertIsNone(pat.search(line), f"{sh.name}:{n}: {why}")

    def test_never_privileged(self) -> None:
        self._forbid(r"--privileged", "--privileged disables seccomp/AppArmor")

    def test_never_host_network(self) -> None:
        self._forbid(r"--network[= ]host", "host network = live IDE on the public interface")

    def test_never_publishes_ports(self) -> None:
        self._forbid(r"podman run.*(\s-p\s|--publish)|^\s*(-p|--publish)[\s=]",
                     "published port = the gate's IdP and IDE reachable from outside the netns")

    def test_never_adds_capabilities(self) -> None:
        self._forbid(r"--cap-add", "rootless + --systemd=always needs no capability")

    def test_never_disables_tls_verification(self) -> None:
        # The gate speaks real HTTPS to caddy through its internal CA (--cacert),
        # never --insecure: a gate that skips TLS verification cannot assert that
        # cookie_secure=true actually works.
        self._forbid(r"--insecure|curl[^|]*\s-k\s", "TLS verification stays on (use --cacert)")

    def test_repo_mounted_read_only(self) -> None:
        self.assertIn(":/vide:ro", code_text(self.SM / "run.sh"))

    def test_refuses_rootful_by_default(self) -> None:
        text = code_text(self.SM / "run.sh")
        self.assertIn("VIDE_ITEST_ALLOW_ROOTFUL", text)
        self.assertIn("exit 77", text)

    def test_in_container_refusal_precedes_every_mutation(self) -> None:
        first_logic = first_refusal = None
        for n, line in enumerate(code_lines(self.SM / "in-container.sh"), 1):
            if first_logic is None and re.match(r"^(if|[a-zA-Z_]+=)", line):
                first_logic = n
            if first_refusal is None and "containerenv" in line:
                first_refusal = n
        self.assertIsNotNone(first_refusal, "no refusal guard found")
        self.assertEqual(first_logic, first_refusal,
                         "the container-marker refusal must be the first logic")

    def test_idp_is_never_the_real_google(self) -> None:
        # A gate that reached accounts.google.com would be neither hermetic nor
        # honest — and would put a real OAuth client in a throwaway container.
        for f in sorted(self.SM.glob("*.sh")) + sorted(self.SM.glob("*.py")):
            for n, line in enumerate(code_lines(f), 1):
                self.assertNotIn("accounts.google.com", line,
                                 f"{f.name}:{n} points the gate at the real Google")

    def test_idp_binds_loopback_only(self) -> None:
        # The fake IdP mints signed identity tokens: bound to 0.0.0.0 it would be
        # an unauthenticated token minter on whatever network the container joins.
        text = (self.SM / "fake-idp.py").read_text()
        self.assertIn('ThreadingHTTPServer(("127.0.0.1"', text)
        self.assertNotIn('("0.0.0.0"', text)

    def test_idp_verifies_the_client_secret(self) -> None:
        # Without this the gate's crown row stays 200 while VIDE has recorded a
        # WRONG or EMPTY client secret — the one production failure that only a
        # completed login can witness would be the one thing the live gate is
        # blind to. Real Google enforces it; the fixture must too, or the tier's
        # green says less than it is quoted as saying.
        text = (self.SM / "fake-idp.py").read_text()
        self.assertIn("invalid_client", text)
        self.assertIn("secret != CLIENT_SECRET", text)

    def test_no_key_material_checked_in(self) -> None:
        for f in sorted(self.SM.iterdir()):
            if f.is_file():
                self.assertNotIn("-----BEGIN", f.read_text(errors="ignore"),
                                 f"{f.name} carries key material (keys are generated per run)")

    def test_load_bearing_assertions_survive(self) -> None:
        # The anti-drift manifest: this gate COPIED its invariant shapes from the
        # frozen arbiter (a sibling gate cannot source a linear script), so the
        # copies are pinned here or they rot silently.
        body = (self.SM / "in-container.sh").read_text()
        for needle, why in (
            ("chmod 0666", "the socket-perm negative control (a green without it is vacuous)"),
            ("no TCP listener", "the inverse-of-password bind assertion"),
            ("deny@vide.invalid", "the empty-set fail-open sentinel row"),
            ("%2B", "the '+'-address silent-never-match row"),
            ("--max-redirs 5", "the 403-is-not-a-redirect-loop row"),
            ("pre-rotation cookie is DEAD", "rotate-sso's kill-switch proof"),
            ("respond", "the destroy tombstone (a dangling import kills every site)"),
            ("cookie_refresh", "the forbidden-key absence pins"),
            ("refusal before mutation", "the §0.5 usage-error-mutates-nothing section"),
            ("after the --", "the §0.5 per-case witness sweep (a green without it is vacuous)"),
            ("PRE-FIX CONTROL", "§13b's pre-fix arms — without them 'the attack failed' "
                                "is satisfied by a dead instance or a typo'd path"),
            ("the sed expression rotted", "with_unit_mutation's rot check: a sed that "
                                          "stopped matching produces a green meaning the "
                                          "opposite of what it says"),
            ("/run/caddy/admin.sock $SOCK", "the Critical, executed rather than argued"),
            ("2750 root:vide-proxy", "the freeze posture — the byte that proves it landed"),
            ("did not bind", "§13c: the fail-closed refusal must reach the journal, or "
                             "the row passes for an unrelated failure"),
            ("while the user still owns it", "§13c's window row — the directory the "
                                             "instance user owns during the wait must "
                                             "not be one Caddy can walk"),
            # §13d had NO needle of its own: its PRE-FIX CONTROL is satisfied by
            # §13b's, so the entire port-reservation section could be deleted
            # with this guard green. These four are its load-bearing rows.
            ("the reservation stays up — THIS is the whole fix",
             "§13d's separating row — an arrangement where the service AND the "
             "reservation are both down is simply the old world, and proves nothing"),
            ("an unprivileged bind on the fleet's port is REFUSED",
             "§13d's squat attempt, which is the section's entire subject"),
            ("a NON-ROOT caller gets the same answer, not an unknown",
             "the only row anywhere that executes the unprivileged attribution "
             "path — §13d otherwise runs as root from top to bottom, and half "
             "the reason the holder reader moved to /proc/net/tcp is that it "
             "needs no privilege"),
            ("doctor names a live squatter on the fleet's hop",
             "the ONLY end-to-end evidence the detection story has: every other "
             "squat row hands proxy_health a uid set directly, so the path "
             "/proc/net/tcp -> parse -> usurped -> containment ladder is walked "
             "nowhere else in the tree"),
            ("the start-time reader lands inside a wall-clock bracket",
             "the frame check `ps` cannot be — procps computes the same sum "
             "from the same two files, so it settles the field index and "
             "nothing about the clock the answer is expressed in"),
            ("a unit file newer than the running gate IS a restart",
             "the only place the mtime clause is observed firing POSITIVELY on "
             "a real kernel; §16c's content edit is carried by the `wrote` "
             "clause instead, which touches no host read at all"),
            ("proxy.toml is 0640 root:vide-oauth2",
             "the posture no tier asserted while its only re-assertion was "
             "retired — a widening is invisible to every other check because "
             "the byte compare still matches"),
            ("a converge does not make the next upgrade-sso bounce the gate",
             "§16c — the converge restamping proxy.toml and arming the next "
             "upgrade-sso to bounce the fleet's gate. Both halves of it were "
             "green in isolation while exactly that shipped"),
            ("while it is holding NEITHER address",
             "§16d's premise row — the ONLY measurement anywhere of the "
             "behaviour all four of this release's move refusals are built on: "
             "that a daemon-reload over a changed ListenStream= releases the old "
             "address and binds nothing. Everything else about it is an argument "
             "from systemd's source, and if it were false the refusals would "
             "defend against nothing while every unit row stayed green"),
            ("the unit file on disk still names the OLD address",
             "§16d's refusal, executed against a real manager — the unit tier "
             "can only stub the reader that decides it"),
            ("a removed unit file is still a LOADED reservation until the reload",
             "§16d-b — the box the manager-first ordering exists for. The unit "
             "tier MODELS that state and pins it (T149); what no hermetic row "
             "can do is show a real systemd actually behaving that way, and a "
             "model of a premise nobody measured is worth exactly what the "
             "premise is. This is the measurement it stands on"),
            ("a daemon-reload over an ABSENT fragment releases the descriptor",
             "§16d-c — the premise the PERMIT arm rests on, and the mirror of "
             "§16d's changed-address measurement. If a gone fragment did NOT "
             "release, the documented move's consent gesture would be a no-op "
             "and the refusal would be unescapable"),
            ("THIS BOX'S OWN reservation",
             "§16d's holder ATTRIBUTION on the one box where the abandoned "
             "address is genuinely held by this box's own PID-1 reservation — "
             "the state the refusal family deliberately parks operators in, and "
             "the state the row described as a squatter for two rounds"),
            ("the converge refuses to repoint the auth body off the gate",
             "the lock that arrived when the auth host became a VIDE-owned "
             "import. Re-rendering that body can REPOINT every instance's "
             "authorization sub-request, so on a moved-pin box — where the "
             "reservation has refused to follow — writing it at the new pin "
             "would aim the fleet's login host at a port nobody serves. A unit "
             "fixture can only stub the permit; this row drives it against a "
             "real manager on a box where the pin has genuinely moved. It "
             "REPLACED 'vide info warns before it prints a moved-pin block', "
             "whose subject was retired with the caveat itself: the pasted "
             "block names no port now, so there is no dangerous paste to warn "
             "about. That swap is why this list exists — the old needle sat "
             "here pointing at a deleted row, and nothing noticed until the "
             "unit tier was next run"),
        ):
            self.assertIn(needle, body, f"the sso gate lost {why}")

    def test_refusal_section_precedes_the_install(self) -> None:
        # §0.5's whole value is positional: once §1 provisions the shared proxy the
        # missing-credential refusals are unobservable, so it must run on the
        # pristine box BEFORE the install.
        body = (self.SM / "in-container.sh").read_text()
        self.assertLess(body.index("refusal before mutation"),
                        body.index("== 1. sso install =="),
                        "§0.5 must run before §1 (a provisioned proxy hides the cells)")


class TestParityGateSafety(unittest.TestCase):
    """The parity gate (tests/parity/) boots the same untrusted-installer
    container as the arbiter — the identical host-safety rules apply. Plus its
    own load-bearing shape: the frozen normalization seds that produced the
    checked-in golden must survive verbatim, or the golden silently rots."""

    PA = REPO / "tests" / "parity"

    def _forbid(self, pattern: str, why: str) -> None:
        pat = re.compile(pattern)
        for sh in sorted(self.PA.glob("*.sh")):
            for n, line in enumerate(code_lines(sh), 1):
                self.assertIsNone(pat.search(line), f"{sh.name}:{n}: {why}")

    def test_never_privileged(self) -> None:
        self._forbid(r"--privileged", "--privileged disables seccomp/AppArmor")

    def test_never_host_network(self) -> None:
        self._forbid(r"--network[= ]host", "host network = live IDE on the public interface")

    def test_never_publishes_ports(self) -> None:
        self._forbid(r"podman run.*(\s-p\s|--publish)|^\s*(-p|--publish)[\s=]",
                     "published port = IDE reachable from outside the netns")

    def test_never_adds_capabilities(self) -> None:
        self._forbid(r"--cap-add", "rootless + --systemd=always needs no capability")

    def test_never_disables_tls_verification(self) -> None:
        self._forbid(r"--insecure|curl[^|]*\s-k\s", "TLS verification stays on")

    def test_repo_mounted_read_only(self) -> None:
        self.assertIn(":/vide:ro", code_text(self.PA / "diff-artifacts.sh"))

    def test_refuses_rootful_by_default(self) -> None:
        text = code_text(self.PA / "diff-artifacts.sh")
        self.assertIn("VIDE_ITEST_ALLOW_ROOTFUL", text)
        self.assertIn("exit 77", text)

    def test_container_marker_is_set(self) -> None:
        # No in-container.sh here (the script execs into the container itself),
        # so the refusal-first analog is: the boot must carry the throwaway
        # marker the product's own guard keys on.
        self.assertIn("VIDE_IN_THROWAWAY_CONTAINER=1",
                      code_text(self.PA / "diff-artifacts.sh"))

    def test_normalization_seds_survive(self) -> None:
        # The golden was produced by exactly these normalizations; dropping one
        # makes the next run red for a non-reason (or hides real drift behind a
        # "cleanup"). Anchor all three.
        text = (self.PA / "diff-artifacts.sh").read_text()
        self.assertIn("s/127.0.0.1:$port/127.0.0.1:PORT/", text)
        self.assertIn('hashed-password: \\"HASH\\"', text)
        self.assertIn("cookie-suffix: vide-ittest-RAND", text)

    def test_script_diffs_against_the_golden(self) -> None:
        self.assertIn("golden/durable-artifacts.txt",
                      (self.PA / "diff-artifacts.sh").read_text())


class TestParityGolden(unittest.TestCase):
    """Integrity pins on the checked-in golden fixture — the frozen reference
    shape of every durable artifact a password-mode install writes. A re-bless
    that corrupts the structure or un-normalizes a secret-bearing token must go
    red here, not pass silently."""

    GOLDEN = REPO / "tests" / "parity" / "golden" / "durable-artifacts.txt"

    SENTINELS = [
        "=== port-record ===",
        "=== config.yaml (normalized) ===",
        "=== config.yaml stat ===",
        # seed_user_settings writes this once and never converges, so a wrong
        # seed is permanent per instance — the highest-consequence durable
        # artifact VIDE emits, and until 2026-07-30 the only one outside the
        # shape gate.
        "=== user settings seed ===",
        "=== unit file ===",
        "=== launcher ===",
        "=== profile.d ===",
        "=== bin layout ===",
        "=== opt perms ===",
        "=== guard exit code ===",
        "=== snippet (normalized) ===",
        "=== SHOWN-ONCE count ===",
    ]

    def test_exists_and_nonempty(self) -> None:
        self.assertTrue(self.GOLDEN.is_file(), "golden fixture missing")
        self.assertGreater(self.GOLDEN.stat().st_size, 0)

    def test_sentinels_present_in_captured_order(self) -> None:
        lines = self.GOLDEN.read_text().splitlines()
        found = [ln for ln in lines if ln.startswith("=== ")]
        self.assertEqual(found, self.SENTINELS)

    def test_normalized_tokens_present(self) -> None:
        text = self.GOLDEN.read_text()
        self.assertIn("=PORT", text)
        self.assertIn('hashed-password: "HASH"', text)
        self.assertIn("cookie-suffix: vide-ittest-RAND", text)

    def test_no_unnormalized_leftovers(self) -> None:
        text = self.GOLDEN.read_text()
        self.assertIsNone(re.search(r"127\.0\.0\.1:\d", text),
                          "a live port leaked into the golden")
        self.assertNotIn("$argon2", text, "a real hash leaked into the golden")
        for ln in text.splitlines():
            if ln.startswith("cookie-suffix: vide-ittest-"):
                self.assertEqual(ln, "cookie-suffix: vide-ittest-RAND")


class TestUnitModulesAreStandalone(unittest.TestCase):
    """prove-teeth.sh names ONE test per mutation and runs it with
    `python3 -m unittest <id>` — outside run.py, which is the only place the
    unit tier's sys.path is assembled. Three modules relied on that setup for a
    bare `from fakes import …`, so they could not be imported at all under the
    proof harness; the resulting ModuleNotFoundError is a non-zero exit, which
    prove-teeth read as "the mutation went red". Every row naming those modules
    was a vacuous proof — it would have passed against a no-op mutation.

    Measured, not theorised: 20 of the 51 rows were in that state."""

    UNIT = Path(__file__).resolve().parent

    @staticmethod
    def _imports(tree: ast.AST) -> set[str]:
        """Top-level names imported ANYWHERE, including inside functions — a
        function-level import still needs its path set at import time."""
        names: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.module:
                names.add(n.module.split(".")[0])
            elif isinstance(n, ast.Import):
                names.update(a.name.split(".")[0] for a in n.names)
        return names

    @staticmethod
    def _unconditional_path_inserts(tree: ast.Module) -> str:
        """sys.path.insert calls that really run on import: MODULE body only.
        Walking the whole tree would accept one inside a method (which runs too
        late) or under `if __name__ == "__main__"` (which never runs at all
        under `python3 -m unittest`) — both were live in this repo, and both
        read as compliant to a plain substring search."""
        out = []
        for node in tree.body:
            if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and "sys.path.insert" in ast.unparse(node.value)):
                out.append(ast.unparse(node.value))
        return "\n".join(out).replace('"', "'")

    def _check(self, module: str, needle: str, why: str) -> None:
        for f in sorted(self.UNIT.glob("test_*.py")):
            tree = ast.parse(f.read_text())
            if module not in self._imports(tree):
                continue
            self.assertIn(needle, self._unconditional_path_inserts(tree),
                          f"{f.name} imports `{module}` but never puts {why} on "
                          "sys.path at module level — it then runs only under "
                          "run.py, and any harness naming one of its tests gets "
                          "an ImportError it may read as a failing test")

    def test_every_module_that_uses_fakes_puts_it_on_the_path_itself(self) -> None:
        self._check("fakes", "'unit'", "tests/unit")

    def test_every_module_that_imports_vide_puts_src_on_the_path_itself(self) -> None:
        self._check("vide", "'src'", "src")


class TestTheDocumentedTestSeamStillWorks(unittest.TestCase):
    """VIDE_SSO_ISSUER_URL is documented as the fake-IdP seam (config.py,
    .env.example) and is what tests/sso-mode, tests/host-smoke/run.sh and
    live-fleet.sh all drive. A product-side tightening that refuses the value
    those three gates set does not fail a single unit row — it makes the three
    tiers that would have caught it unrunnable, which is how a change that broke
    every SSO gate shipped behind 515 green rows and was found by reading.

    The literal is read out of the gates THEMSELVES rather than restated here,
    so the product and the harness cannot drift apart in either direction: move
    the fake IdP and this row follows it; tighten the product past it and this
    row goes red before the tier is ever booked."""

    SEAMS = ("tests/sso-mode/in-container.sh",
             "tests/host-smoke/run.sh",
             "tests/host-smoke/live-fleet.sh")

    def _issuer(self, rel: str) -> str:
        text = (REPO / rel).read_text()
        port = re.search(r"^IDP_PORT=(\d+)", text, re.M)
        raw = re.search(r"^IDP_ISSUER=(\S+)", text, re.M)
        self.assertIsNotNone(port, f"{rel}: no IDP_PORT= to read")
        self.assertIsNotNone(raw, f"{rel}: no IDP_ISSUER= to read")
        return (raw.group(1).replace("$IDP_PORT", port.group(1))
                            .replace("${IDP_PORT}", port.group(1)))

    def test_every_tier_issuer_is_accepted_by_the_renderer(self) -> None:
        from vide import oauth2proxy
        for rel in self.SEAMS:
            issuer = self._issuer(rel)
            with self.subTest(rel=rel, issuer=issuer):
                oauth2proxy.check_url(issuer, "VIDE_SSO_ISSUER_URL")   # must not raise

    def test_a_public_plaintext_issuer_is_still_refused(self) -> None:
        """The carve-out must be a carve-out, not a hole. The reason check_url
        exists at all is that fleet.env is 0644 and a hand-edited row must not
        reach a rendered config unchecked — and a cleartext issuer that is not on
        loopback is the fleet's root of trust fetched over a network anyone can
        answer."""
        from vide import oauth2proxy
        from vide.errors import ConfigError
        for bad in ("http://idp.example.test", "http://127.0.0.1.example.test",
                    "https://ok.example.test\n", "https://ok.example.test ",
                    "ftp://idp.example.test", "http://127.0.0.1:8555\nfoo = 1"):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                oauth2proxy.check_url(bad, "VIDE_SSO_ISSUER_URL")


if __name__ == "__main__":
    unittest.main()
