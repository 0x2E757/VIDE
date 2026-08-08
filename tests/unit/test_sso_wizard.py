"""SSO wizard screens + bracketed-paste parsing. Pure/scripted — no curses."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from vide.tui import widgets  # noqa: E402


class _ScriptedGetch:
    """A minimal session.scr with a scripted getch queue for _read_key."""
    def __init__(self, keys) -> None:
        self.keys = list(keys)

    def getch(self) -> int:
        return self.keys.pop(0) if self.keys else -1


class _Sess:
    def __init__(self, keys) -> None:
        self.scr = _ScriptedGetch(keys)


def _seq(s: str) -> list[int]:
    return [ord(c) for c in s]


class TestBracketedPaste(unittest.TestCase):
    def test_filter_strips_crlf_and_controls(self) -> None:
        self.assertEqual(widgets.filter_paste_text("GOCSPX-a\r\nb\tc"), "GOCSPX-abc")

    def test_read_key_extracts_paste_payload(self) -> None:
        # ESC[200~ GOCSPX-abc ESC[201~  -> ("paste", "GOCSPX-abc"), markers gone
        keys = [27] + _seq("[200~") + _seq("GOCSPX-abc") + [27] + _seq("[201~")
        ev = widgets._read_key(_Sess(keys))
        self.assertEqual(ev, ("paste", "GOCSPX-abc"))

    def test_pasted_newline_does_not_leak_as_enter(self) -> None:
        keys = [27] + _seq("[200~") + _seq("line1\nline2") + [27] + _seq("[201~")
        ev = widgets._read_key(_Sess(keys))
        self.assertEqual(ev, ("paste", "line1line2"))  # newline stripped, not Enter

    def test_lone_esc_is_discarded_not_wedged(self) -> None:
        self.assertEqual(widgets._read_key(_Sess([27])), -1)

    def test_plain_key_passes_through(self) -> None:
        self.assertEqual(widgets._read_key(_Sess([ord("a")])), ord("a"))


class _TwinStub:
    dry_run = False

    def __init__(self) -> None:
        self.notes: list[str] = []
        self.secrets: list[str] = []

    def defer_note(self, line): self.notes.append(line)
    def defer_secret(self, line): self.secrets.append(line)
    def set_status(self, text): pass
    def modal_confirm(self, text): return True


class _ScriptedMenu:
    def __init__(self, answers) -> None:
        self.answers = list(answers)

    def __call__(self, session, title, options, default=0):
        return self.answers.pop(0) if self.answers else 0


class TestSsoScreens(unittest.TestCase):
    def _pr(self):
        from vide.tui.screens import TuiPrompter
        return TuiPrompter(_TwinStub())

    def test_auth_mode_sso_sets_flag(self) -> None:
        from vide.prompter import SsoFacts
        from vide.tui import screens as sm
        pr = self._pr()
        with mock.patch.object(sm, "menu", _ScriptedMenu([1])):
            got = pr.auth_mode(SsoFacts(default="password", proxy_configured=False,
                                        parent_domain=""))
        self.assertEqual(got, "sso")
        self.assertIn("--auth sso", pr.equivalent_command())

    def test_credentials_twin_has_client_id_never_secret(self) -> None:
        from vide.tui import screens as sm
        pr = self._pr()
        cid = "abc.apps.googleusercontent.com"
        with mock.patch.object(sm, "text_field", return_value=cid), \
             mock.patch.object(sm, "password_field", return_value="GOCSPX-topsecret"):
            creds = pr.sso_credentials("")
        self.assertEqual(creds.client_secret, "GOCSPX-topsecret")
        twin = pr.equivalent_command()
        self.assertIn(f"--sso-client-id {cid}", twin)
        self.assertIn("--sso-secrets-stdin", twin)
        self.assertNotIn("GOCSPX-topsecret", twin)   # the secret is NEVER in a twin
        self.assertIn("paste VIDE_SSO_CLIENT_SECRET", twin)  # the re-solicit comment
        # …and how to END it. Both stdin flags read to EOF; piped, EOF arrives on
        # its own, which is why no automated tier could ever have found this. On
        # a terminal the operator pastes the line, presses Enter, and faces a
        # program that looks hung. Walked and reported by a human, 2026-08-08.
        self.assertIn("Ctrl-D", twin)

    def test_the_password_twin_also_says_how_to_end_stdin(self) -> None:
        """The password-mode sibling of the row above. It had the same defect and
        is fixed with it — a fix applied to one of two identical notes is a
        coin-flip on which path the next operator takes."""
        from vide.tui.screens import TuiPrompter
        pr = TuiPrompter(_TwinStub())
        pr._flags["--password-stdin"] = ""
        twin = pr.equivalent_command()
        self.assertIn("supply the password on stdin", twin)
        self.assertIn("Ctrl-D", twin)

    def test_a_no_gui_refusal_does_not_blame_a_missing_terminal(self) -> None:
        """It used to say "running without a terminal, so there is nobody to
        ask" — and that is false on the path this message is most read from: the
        resume command VIDE itself prints carries --no-gui, and the operator
        pastes it into the terminal they are sitting at. They then hunt for a tty
        problem that does not exist. The message must name the behaviour, not
        assert a fact about the caller's environment."""
        from vide.prompter import require_answer
        from vide.errors import UsageError
        with self.assertRaises(UsageError) as ctx:
            require_answer("", "--sso-allow")
        msg = str(ctx.exception)
        self.assertIn("--sso-allow", msg)
        self.assertIn("--no-gui", msg)
        self.assertNotIn("without a terminal", msg)

    def test_an_abort_on_the_secret_field_keeps_the_client_id(self) -> None:
        """FOUND BY WALKING THE MANUAL GATE, 2026-08-08, and it is the reason the
        two flags are recorded before the secret is asked for rather than after.

        Ctrl-C on the secret field is the single most likely place to abort — it
        is where the operator goes hunting for a value — and the resume note used
        to come back carrying NEITHER flag, so they re-entered a client id VIDE
        had already validated and stored for prefill one line earlier. A note
        whose whole job is to save re-entry may not drop the one value it already
        trusts enough to prefill.

        `--sso-secrets-stdin` is asserted here too, and not as decoration: the
        client id alone would produce a resume command that dies at "missing
        required value: pass --sso-secrets-stdin". The flag does not claim a
        secret was given; it states that the resume run must supply one."""
        from vide.tui import screens as sm
        pr = self._pr()
        cid = "abc.apps.googleusercontent.com"
        # KeyboardInterrupt out of the secret prompt — what Ctrl-C really does.
        with mock.patch.object(sm, "text_field", return_value=cid), \
             mock.patch.object(sm, "password_field", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                pr.sso_credentials("")
        twin = pr.equivalent_command()
        self.assertIn(f"--sso-client-id {cid}", twin)
        self.assertIn("--sso-secrets-stdin", twin)
        self.assertNotIn("GOCSPX", twin)

    def test_an_abort_on_the_client_id_field_records_nothing(self) -> None:
        """The opposite sign, and the half that keeps the fix honest: a value the
        operator never finished giving must not appear in a command they are
        invited to paste. Aborting ON the client id screen leaves both flags off."""
        from vide.tui import screens as sm
        pr = self._pr()
        with mock.patch.object(sm, "text_field", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                pr.sso_credentials("")
        twin = pr.equivalent_command()
        self.assertNotIn("--sso-client-id", twin)
        self.assertNotIn("--sso-secrets-stdin", twin)

    def test_whitelist_email_normalizes_and_twins(self) -> None:
        from vide.tui import screens as sm
        pr = self._pr()
        with mock.patch.object(sm, "text_field", return_value="  Alice@Example.COM "):
            got = pr.whitelist_email("alice", "")
        self.assertEqual(got, "alice@example.com")
        self.assertIn("--sso-allow alice@example.com", pr.equivalent_command())

    def test_finish_sso_facts_have_no_password_promise(self) -> None:
        from vide.prompter import InstallSummary, InstanceAction
        from vide.tui import screens as sm
        pr = self._pr()
        summ = InstallSummary(
            user="u", port=None, fqdn="u.example.com", version="4.x",
            config_path="/home/u/.config/code-server/config.yaml",
            toolchain="ok", action=InstanceAction.CONVERGE, dry_run=False,
            mode="sso", binding="socket /run/vide/u/code-server.sock",
            whitelist="a@example.com", parent_domain="example.com",
            signout_url="https://auth.example.com/oauth2/sign_out")
        captured = {}

        def fake_menu(session, body, options, default=0):
            captured["body"] = body
            return 0
        with mock.patch.object(sm, "menu", fake_menu):
            pr.finish(summ)
        body = captured["body"]
        self.assertIn("socket /run/vide/u/code-server.sock", body)
        self.assertIn("a@example.com", body)
        self.assertIn("EVERY SSO instance", body)
        self.assertNotIn("SHOWN-ONCE password", body)   # no password promise
        self.assertIn("30 days", body)


class TestArgvSeedsPrefillWizard(unittest.TestCase):
    """--sso-client-id / --sso-allow must arrive as field PREFILLS (the wizard
    still shows the ask — argv is a default, never a skip)."""

    def test_seeds_arrive_as_field_prefills(self) -> None:
        from vide.tui import screens as sm
        from vide.tui.screens import TuiPrompter
        pr = TuiPrompter(_TwinStub(),
                         sso_client_id="argv.apps.googleusercontent.com",
                         sso_allow="Argv@Example.com")

        def echo_field(session, prompt, label, initial=""):
            return initial   # the operator just hits Enter on the prefill

        with mock.patch.object(sm, "text_field", echo_field), \
             mock.patch.object(sm, "password_field", return_value="GOCSPX-x"):
            creds = pr.sso_credentials("")
            email = pr.whitelist_email("u", "")
        self.assertEqual(creds.client_id, "argv.apps.googleusercontent.com")
        self.assertEqual(email, "argv@example.com")   # normalization still applies

    def test_seeds_survive_a_retry(self) -> None:
        # acknowledge_exposure resets the command-builder transcript on retry;
        # the prefills live in _prev and must survive it.
        from vide.tui import screens as sm
        from vide.tui.screens import TuiPrompter
        pr = TuiPrompter(_TwinStub(), sso_allow="a@x.com")
        with mock.patch.object(sm, "menu", lambda *a, **k: 0):
            pr.acknowledge_exposure()

        def echo_field(session, prompt, label, initial=""):
            return initial

        with mock.patch.object(sm, "text_field", echo_field):
            self.assertEqual(pr.whitelist_email("u", ""), "a@x.com")


class TestExposureBannerModeAgnostic(unittest.TestCase):
    def test_banner_no_longer_claims_one_password_is_the_gate(self) -> None:
        from vide.prompter import EXPOSURE_BANNER
        # the old password-mode-only sentence must be gone (it is false under SSO)
        self.assertNotIn("one\nhigh-entropy password", EXPOSURE_BANNER)
        self.assertNotIn("only remaining gate is one", EXPOSURE_BANNER)
        self.assertIn("loopback ONLY", EXPOSURE_BANNER)


if __name__ == "__main__":
    unittest.main()
