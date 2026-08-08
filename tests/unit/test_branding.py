"""Branding of the vendored code-server tree: the favicon, the pinned webfont,
and the seed-if-absent user settings.

None of this is load-bearing at RUNTIME — every step downgrades to a warning —
which is exactly why it needs pinning here instead: a silent no-op is the
expected failure mode, so nothing on the box would ever tell you it broke.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import RecordingExecutor, capturing_reporter, quiet_reporter  # noqa: E402
from vide import branding, contract  # noqa: E402


class TestTheMarkHasOneSource(unittest.TestCase):
    def test_standalone_svg_and_inline_mark_draw_the_same_curves(self) -> None:
        # Three renderings consume MARK_PATHS. A mark that drifts between the
        # page, the data-URI favicon and the code-server file stops being a mark.
        svg = contract.standalone_mark_svg()
        for d in contract.MARK_PATHS:
            self.assertIn(d, svg)
            self.assertIn(d, contract._MARK)

    def test_the_data_uri_favicon_draws_them_too(self) -> None:
        # The THIRD rendering, and the one that used to be able to drift unseen:
        # it was a hand-written percent-encoded literal, so a changed MARK_PATHS
        # left it silently drawing the OLD mark. It is derived now — this row
        # stays because "derived" is a property of the code that a future edit
        # can quietly undo by pasting a literal back.
        for d in contract.MARK_PATHS:
            self.assertIn(quote(d, safe=""), contract._FAVICON, d)

    def test_the_favicon_carries_the_geometry_too_not_only_the_curves(self) -> None:
        # The curves were pinned above and their neighbours were not: the favicon
        # also carries the viewBox, the colour and the fill rule. Miss any one and
        # the standalone SVG and the inline mark move while the favicon on the
        # auth root and /vide keeps the old geometry.
        for value in (contract.MARK_VIEWBOX, contract.MARK_COLOR,
                      contract.MARK_FILL_RULE):
            self.assertIn(quote(value, safe=""), contract._FAVICON, value)

    def test_the_v_is_a_hole_and_not_a_second_shape(self) -> None:
        """The two properties the filled mark stands on, asserted by VALUE rather
        than against the constants — an assertion that reads
        `fill-rule="{MARK_FILL_RULE}"` follows the constant wherever it goes and
        certifies nothing.

        `evenodd` is what subtracts the V from the shield. Under `nonzero` the
        same two subpaths render as a solid shield: right silhouette, right
        colour, no letter — a mark that looks almost correct.

        ONE path, not two. The subpaths must share a single `d`; split them and
        each gets its own <path>, evenodd has nothing to subtract, and the V
        fills in exactly as if the rule had been lost."""
        self.assertEqual(len(contract.MARK_PATHS), 1)
        self.assertIn('fill-rule="evenodd"', contract.standalone_mark_svg())
        self.assertIn("fill-rule='evenodd'", contract._MARK)

    def test_the_art_fills_the_viewbox_on_its_long_axis(self) -> None:
        """FOUND BY EYE, not by a tier: the mark sat in x 12..52, y 10..55 of a
        64-square — 62% x 70% — so a 16px favicon drew a 10 x 11 mark and handed
        back the rest as margin. Nothing measured that, because every rendering
        was byte-correct; the geometry was simply small inside its own box.

        Asserted on the LONG axis only. The shield is taller than it is wide, so
        it cannot touch all four edges of a square without being stretched, and
        the ~5.6% left at each side is the shape rather than padding. Pinning the
        long axis at exactly 0..64 is what stops the art drifting inward again."""
        import re
        toks = re.findall(r"[MLCVZ]|-?\d+\.?\d*", contract.MARK_PATHS[0])
        xs, ys, i, mode = [], [], 0, None
        while i < len(toks):
            t = toks[i]
            if t in "MLCVZ":
                mode = t; i += 1; continue
            if mode == "V":
                ys.append(float(t)); i += 1; continue
            xs.append(float(t)); ys.append(float(toks[i + 1])); i += 2
        self.assertEqual((min(ys), max(ys)), (0.0, 64.0),
                         "the art no longer reaches top and bottom of the viewBox")
        # …and the short axis is centred, so the optical weight does not drift.
        self.assertAlmostEqual(min(xs), 64 - max(xs), places=1)

    def test_the_favicon_decodes_to_exactly_the_standalone_file(self) -> None:
        """The strongest form of the two rows above, and the one only possible
        once the favicon stopped being re-typed: not "it mentions the same
        curves" but "it IS the same document". Anything that moves one and not
        the other fails here first, in one assertion instead of a list."""
        from urllib.parse import unquote
        payload = contract._FAVICON.split("svg+xml,", 1)[1][:-2]
        self.assertEqual(unquote(payload), contract.standalone_mark_svg().strip())

    def test_the_favicon_payload_cannot_escape_its_caddy_token(self) -> None:
        """It is interpolated into a single-quoted href inside a Caddy `respond`
        argument. A bare apostrophe would close the href, a double quote would
        end the token and take every site in the operator's config with it, and a
        literal brace would be read as a placeholder. Encoding makes that
        impossible BY CONSTRUCTION — this row is what keeps it that way."""
        payload = contract._FAVICON.split("svg+xml,", 1)[1][:-2]
        for ch in ('"', "'", "<", ">", "{", "}"):
            self.assertNotIn(ch, payload, f"{ch!r} survived encoding")

    def test_standalone_svg_names_its_colour(self) -> None:
        # currentColor has nothing to inherit from in a standalone favicon: it
        # resolves to black and the mark disappears on a dark browser tab.
        svg = contract.standalone_mark_svg()
        self.assertIn(contract.MARK_COLOR, svg)
        self.assertNotIn("currentColor", svg)

    def test_standalone_svg_is_a_self_contained_document(self) -> None:
        svg = contract.standalone_mark_svg()
        self.assertIn('xmlns="http://www.w3.org/2000/svg"', svg)
        # No intrinsic size, so it scales to whatever asks for it — a favicon is
        # requested at several sizes.
        self.assertNotIn(" width=", svg)
        # FILLED, and the rule that makes the V a hole rather than a second
        # shape. Lose it and the mark renders as a solid shield: still a mark,
        # still teal, still the right silhouette — and no longer the letter.
        self.assertIn(f'fill-rule="{contract.MARK_FILL_RULE}"', svg)
        self.assertNotIn('fill="none"', svg)


class TestFontPins(unittest.TestCase):
    def test_every_face_carries_a_real_sha256(self) -> None:
        # A pin that is not a hash is not a pin. This catches the placeholder
        # someone leaves behind while wiring a fourth face in.
        self.assertTrue(branding.FONTS)
        for name, digest, weight, style in branding.FONTS:
            self.assertRegex(digest, r"^[0-9a-f]{64}$", name)
            self.assertTrue(name.endswith(".woff2"), name)
            self.assertIn(style, ("normal", "italic"))
            self.assertRegex(weight, r"^\d{3}$")

    def test_pins_are_distinct(self) -> None:
        # Same digest twice means the same file was pinned under two names —
        # copy-paste, and two of the three faces would render wrong.
        digests = [d for _, d, _, _ in branding.FONTS]
        self.assertEqual(len(digests), len(set(digests)))

    def test_the_source_is_pinned_to_a_tag_not_a_branch(self) -> None:
        # A branch would let the bytes move under the pin, turning every future
        # install into a hash mismatch — or, if the pin were ever relaxed, into
        # an unreviewed third-party update.
        self.assertIn(branding.FONT_TAG, branding.FONT_BASE)
        self.assertNotIn("/master/", branding.FONT_BASE)
        self.assertNotIn("/main/", branding.FONT_BASE)
        self.assertTrue(branding.FONT_BASE.startswith("https://"))


class TestTheLicenceTravelsWithTheFont(unittest.TestCase):
    """OFL-1.1 obliges the copyright notice and the licence to accompany every
    copy of the Font Software. This module makes copies — three faces written
    into the code-server tree, which then serves them from `/_static` — so the
    licence has to land beside them. OFL.txt's first line IS the notice, so the
    one file discharges both halves."""

    def _place(self, licence_digest: str | None = None) -> RecordingExecutor:
        # RecordingExecutor.download writes no file, so the hashes cannot be
        # taken for real; they are answered by name instead.
        digests = {n: d for n, d, _, _ in branding.FONTS}
        digests[branding.OFL_FILE] = licence_digest or branding.OFL_SHA256
        ex = RecordingExecutor()
        with mock.patch.object(branding, "_hash_file",
                               side_effect=lambda p: digests[Path(p).name]):
            branding._webfont(ex, quiet_reporter(), "alice",
                              Path("/srv/code-server-1.2.3"))
        return ex

    def test_the_paths_that_decide_whether_any_of_this_is_served(self) -> None:
        """Pinned to LITERALS, because every other assertion in this file builds
        its expected path out of these same constants and is therefore a
        tautology over them. Set MEDIA to anything at all and the whole suite
        stays green while the faces and the favicon land where code-server never
        looks — and branding downgrades every failure to a warning, so no box
        would report it either. These three strings are what makes the module do
        anything at all.

        `src/browser/media` is what code-server serves at /_static/…; the
        workbench path is upstream's vendored entry document."""
        self.assertEqual(branding.MEDIA, "src/browser/media")
        self.assertEqual(
            branding.WORKBENCH,
            "lib/vscode/out/vs/code/browser/workbench/workbench.html")
        # Exactly the two workbench.html references: the SVG is rel="icon", the
        # dark-support variant its sibling. The .ico and the PWA PNGs stay
        # upstream's — replacing them means shipping binaries.
        self.assertEqual(branding.FAVICONS,
                         ("favicon.svg", "favicon-dark-support.svg"))

    def test_the_licence_is_placed_beside_the_faces(self) -> None:
        ex = self._place()
        installed = [a[2][-1] for a in ex.actions if a[0] == "run_as"]
        self.assertIn(f"/srv/code-server-1.2.3/{branding.MEDIA}/{branding.OFL_FILE}",
                      installed)
        # Beside, not somewhere else: same directory as the faces it covers.
        for name, _, _, _ in branding.FONTS:
            self.assertIn(f"/srv/code-server-1.2.3/{branding.MEDIA}/{name}", installed)

    def test_the_licence_comes_from_the_same_pinned_tag(self) -> None:
        # A licence fetched off a branch could drift away from the faces it is
        # supposed to describe.
        ex = self._place()
        urls = [a[1] for a in ex.actions if a[0] == "download"]
        self.assertIn(branding.OFL_URL, urls)
        self.assertIn(branding.FONT_TAG, branding.OFL_URL)
        self.assertRegex(branding.OFL_SHA256, r"^[0-9a-f]{64}$")

    def test_an_unverifiable_FACE_stops_the_install_too(self) -> None:
        # Symmetry with the licence row below, and it was missing: only the
        # licence digest was ever corrupted in a test, so the per-face mismatch
        # branch — the actual supply-chain guard — went unexercised.
        digests = {n: d for n, d, _, _ in branding.FONTS}
        digests[branding.OFL_FILE] = branding.OFL_SHA256
        first_face = branding.FONTS[0][0]
        digests[first_face] = "f" * 64
        ex = RecordingExecutor()
        with mock.patch.object(branding, "_hash_file",
                               side_effect=lambda p: digests[Path(p).name]), \
             self.assertRaises(ValueError):
            branding._webfont(ex, quiet_reporter(), "alice",
                              Path("/srv/code-server-1.2.3"))
        # The licence landed first, but no FACE may have.
        installed = [a[2][-1] for a in ex.actions if a[0] == "run_as"]
        self.assertNotIn(f"/srv/code-server-1.2.3/{branding.MEDIA}/{first_face}",
                         installed)

    def test_an_unverifiable_licence_stops_the_faces_landing(self) -> None:
        # The whole point: a face on disk without its licence is the omission
        # being closed, so no webfont at all is the correct answer here — and
        # nothing may have been installed by the time it raises.
        with self.assertRaises(ValueError):
            self._place(licence_digest="0" * 64)
        digests = {n: d for n, d, _, _ in branding.FONTS}
        digests[branding.OFL_FILE] = "0" * 64
        ex = RecordingExecutor()
        with mock.patch.object(branding, "_hash_file",
                               side_effect=lambda p: digests[Path(p).name]), \
             self.assertRaises(ValueError):
            branding._webfont(ex, quiet_reporter(), "alice",
                              Path("/srv/code-server-1.2.3"))
        self.assertEqual([], [a for a in ex.actions if a[0] == "run_as"])


class TestFontFaceCss(unittest.TestCase):
    def _css(self) -> str:
        return branding.font_face_css(
            tuple((n, w, s) for n, _, w, s in branding.FONTS))

    def test_urls_go_through_the_workbench_base_placeholder(self) -> None:
        # Hardcoding "/" breaks any code-server served under a sub-path. {{BASE}}
        # is workbench.html's own placeholder, substituted per request.
        css = self._css()
        self.assertIn("{{BASE}}/_static/", css)
        self.assertNotIn("src:url('/_static", css)

    def test_one_rule_per_face_and_all_are_woff2(self) -> None:
        css = self._css()
        self.assertEqual(len(branding.FONTS), css.count("@font-face"))
        self.assertEqual(len(branding.FONTS), css.count("format('woff2')"))

    def test_the_block_is_bounded_by_its_markers(self) -> None:
        # The markers are the idempotency handle AND the way back out: one grep
        # says whether a tree is branded, and the block can be cut at them.
        css = self._css()
        self.assertTrue(css.startswith(branding.MARK_BEGIN))
        self.assertTrue(css.endswith(branding.MARK_END))

    def test_no_double_quotes_reach_the_style_block(self) -> None:
        # workbench.html attributes are double-quoted; a stray double quote in
        # the injected CSS would close one and corrupt the document.
        self.assertNotIn('"', self._css())


class TestSeedUserSettings(unittest.TestCase):
    def _seed(self, exists: bool):
        ex = RecordingExecutor()
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(branding.system, "user_home",
                                   return_value=Path(td)), \
                 mock.patch.object(branding.system, "probe_as", return_value=exists):
                branding.seed_user_settings(ex, quiet_reporter(), "alice")
        return ex

    def test_an_existing_settings_file_is_left_alone(self) -> None:
        # This file is the OPERATOR's. Converging it would revert their edits —
        # the same defect class the config.yaml never-regenerate guard prevents.
        self.assertEqual([], self._seed(exists=True).actions)

    def test_absent_settings_are_seeded_with_a_fallback_stack(self) -> None:
        ex = self._seed(exists=False)
        written = [c for p, c in ex.contents.items() if p.endswith("settings.json")]
        self.assertEqual(1, len(written), f"expected one settings.json, got {ex.contents!r}")
        body = written[0]
        self.assertIn(branding.FONT_FAMILY, body)
        self.assertIn("editor.fontFamily", body)
        self.assertIn("terminal.integrated.fontFamily", body)
        # The webfont is best-effort, so the stack must still name something
        # real when it did not land.
        self.assertIn("monospace", body)

    def test_the_seeded_file_is_valid_json(self) -> None:
        # It is read by code-server at startup; a malformed file is not a
        # cosmetic failure there, it drops the operator's whole settings layer.
        import json
        ex = self._seed(exists=False)
        body = next(c for p, c in ex.contents.items() if p.endswith("settings.json"))
        self.assertEqual(branding.DEFAULT_SETTINGS, json.loads(body))


class TestLigaturesAreOn(unittest.TestCase):
    """JetBrains Mono's coding ligatures live in `calt`; its `liga` feature is
    EMPTY (checked with fontTools against the exact pinned woff2 files). VS Code
    does not merely default ligatures off — it ships
    OFF = '"liga" off, "calt" off', so it actively disables the feature this
    font's headline behaviour depends on. Shipping the font without these two
    keys therefore looks like a broken font rather than a missing setting, which
    is exactly the kind of defect nobody attributes correctly."""

    def test_editor_and_terminal_both_enable_ligatures(self) -> None:
        self.assertIs(True, branding.DEFAULT_SETTINGS["editor.fontLigatures"])
        self.assertIs(
            True, branding.DEFAULT_SETTINGS["terminal.integrated.fontLigatures.enabled"])

    def test_the_font_family_is_the_one_the_ligatures_belong_to(self) -> None:
        # Enabling calt against some other family would be a no-op nobody notices.
        for key in ("editor.fontFamily", "terminal.integrated.fontFamily"):
            self.assertIn(branding.FONT_FAMILY, branding.DEFAULT_SETTINGS[key])


class TestChatSurfaceIsOff(unittest.TestCase):
    def test_the_three_chat_keys_are_disabled(self) -> None:
        for key in ("chat.titleBar.openInAgentsWindow.enabled",
                    "chat.titleBar.signIn.enabled",
                    "chat.agent.enabled"):
            self.assertIs(False, branding.DEFAULT_SETTINGS[key], key)


class TestTreeResolution(unittest.TestCase):
    def test_the_versioned_root_comes_from_the_symlink_not_a_glob(self) -> None:
        # A box that has been upgraded carries several code-server-<ver> dirs;
        # a glob picks by string order and would brand the wrong one on exactly
        # the longest-running boxes.
        src = (REPO / "src/vide/branding.py").read_text()
        self.assertIn('"readlink", "-f"', src)
        self.assertNotIn(".glob(", src)

    def test_resolution_degrades_instead_of_raising(self) -> None:
        with mock.patch.object(branding.system, "user_home", return_value=None):
            self.assertIsNone(branding.code_server_root("alice"))


class TestFaviconActuallyRuns(unittest.TestCase):
    """`_favicon` was mocked out at all three of its call sites and executed by
    no test at all — the half the module docstring leads with had zero executed
    coverage: not the filenames, not the mode, not that it writes twice."""

    def setUp(self) -> None:
        # A REAL tree, because write_as_user runs `mktemp <parent>/…` as the
        # user and dies when the parent is missing — the double now models that.
        # code-server ships src/browser/media/; _favicon writes into it and does
        # not create it, so a fixture that invents a path proves nothing about
        # the box.
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name) / "code-server-1.2.3"
        self.media = self.root / "src" / "browser" / "media"
        self.media.mkdir(parents=True)

    def _run(self):
        ex = RecordingExecutor(sandbox=self.root.parent)
        rep, buf = capturing_reporter()
        branding._favicon(ex, rep, "u", self.root)
        return ex, buf.getvalue()

    def test_it_writes_both_faces_0644_into_the_served_media_dir(self) -> None:
        ex, _ = self._run()
        writes = [a for a in ex.actions if a[0] == "write_as_user"]
        self.assertEqual(len(writes), 2, "both workbench.html references or neither")
        for name in ("favicon.svg", "favicon-dark-support.svg"):
            match = [w for w in writes if str(w[2]) == str(self.media / name)]
            self.assertEqual(len(match), 1, f"{name} not written to the media dir")
            self.assertEqual(match[0][-1], 0o644, f"{name} not world-readable")

    def test_what_it_writes_is_the_mark_not_an_empty_file(self) -> None:
        ex, _ = self._run()
        body = ex.contents[str(self.media / "favicon.svg")]
        self.assertIn("<svg", body)
        self.assertIn(contract.MARK_COLOR, body)


class TestPatchWorkbench(unittest.TestCase):
    """The only code in VIDE that edits a vendored upstream HTML file. It had no
    test at all: every branch here could break and the sole symptom would be an
    editor with a slightly different font."""

    HTML = "<html><head><title>x</title></head><body>b</body></html>"
    FACES = (("JetBrainsMono-Regular.woff2", "400", "normal"),)

    def setUp(self) -> None:
        # The document is written back to the directory it was read from, so on
        # a real box that directory exists by construction. The fixture has to
        # say so too, now that the double refuses a missing parent the way
        # `mktemp <parent>/…` does.
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name) / "code-server-1.2.3"
        (self.root / "lib/vscode/out/vs/code/browser/workbench").mkdir(parents=True)

    def _patch(self, html: str, rc: int = 0):
        ex = RecordingExecutor(sandbox=self.root.parent)
        done = subprocess.CompletedProcess(args=[], returncode=rc, stdout=html)
        self.read_argv: list = []

        def spy(user, argv, **kw):
            self.read_argv.append((user, list(argv)))
            return done
        with mock.patch.object(branding.system, "query_as", spy):
            branding._patch_workbench(ex, quiet_reporter(), "alice",
                                      self.root, self.FACES)
        return ex

    def test_it_reads_and_writes_the_upstream_entry_document(self) -> None:
        """The read was mocked with a bare return_value and nothing asserted the
        path, so WORKBENCH was unpinned here too: point it anywhere and this
        class stayed green while the editor kept upstream's document."""
        want = str(self.root / "lib/vscode/out/vs/code/browser/workbench"
                               "/workbench.html")
        ex = self._patch(self.HTML)
        self.assertEqual(self.read_argv[0][0], "alice", "read as the instance user")
        self.assertIn(want, self.read_argv[0][1])
        writes = [a for a in ex.actions if a[0] == "write_as_user"]
        self.assertEqual([w[2] for w in writes], [want],
                         "the patched document must go back where it came from")

    def test_the_block_lands_inside_head(self) -> None:
        ex = self._patch(self.HTML)
        written = next(iter(ex.contents.values()))
        self.assertIn(branding.MARK_BEGIN, written)
        # Before </head>, not merely present: a <style> after it is ignored by
        # some parsers and would fail invisibly.
        self.assertLess(written.index(branding.MARK_BEGIN), written.index("</head>"))
        self.assertIn("<body>b</body>", written)

    def test_an_already_branded_tree_is_not_rewritten(self) -> None:
        # Idempotency is what makes `vide upgrade` safe to re-run; a second block
        # would also mean two @font-face sets fighting.
        ex = self._patch(self.HTML.replace("<title>", branding.MARK_BEGIN + "<title>"))
        self.assertEqual([], ex.actions)

    def test_html_without_a_head_anchor_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._patch("<html><body>no head here</body></html>")

    def test_an_unreadable_workbench_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._patch("", rc=1)


class TestTheWarningIsTheOnlyAlarm(unittest.TestCase):
    """Branding is best-effort: every step downgrades to a warning. That makes the
    warning the entire alarm, so it has to be asserted — with `quiet_reporter` it
    could not be, because that helper discards its stream."""

    def test_a_dead_font_mirror_warns_and_names_the_fallback(self) -> None:
        rep, buf = capturing_reporter()
        ex = RecordingExecutor()
        with mock.patch.object(branding, "code_server_root",
                               return_value=Path("/srv/code-server-1.2.3")), \
             mock.patch.object(branding, "_favicon"), \
             mock.patch.object(branding, "_webfont", side_effect=OSError("mirror down")):
            branding.apply(ex, rep, "alice")
        out = buf.getvalue()
        self.assertIn("WARN", out)
        self.assertIn("mirror down", out)
        # Naming the consequence is the point: a warning that does not say the
        # editor falls back to another font reads as noise and gets ignored.
        self.assertIn("monospace", out)

    def test_an_unresolvable_tree_warns_instead_of_passing_quietly(self) -> None:
        rep, buf = capturing_reporter()
        ex = RecordingExecutor()
        with mock.patch.object(branding, "code_server_root", return_value=None):
            branding.apply(ex, rep, "alice")
        self.assertIn("WARN", buf.getvalue())
        self.assertEqual([], ex.actions)


class TestFailureIsNeverFatal(unittest.TestCase):
    def test_apply_survives_an_unresolvable_tree(self) -> None:
        # A cosmetic step must not undo a successful install.
        ex = RecordingExecutor()
        with mock.patch.object(branding, "code_server_root", return_value=None):
            branding.apply(ex, quiet_reporter(), "alice")   # must not raise
        self.assertEqual([], ex.actions)

    def test_apply_survives_a_favicon_write_that_blows_up(self) -> None:
        ex = RecordingExecutor()
        with mock.patch.object(branding, "code_server_root",
                               return_value=Path("/nonexistent/code-server-1.2.3")), \
             mock.patch.object(branding, "_favicon", side_effect=OSError("boom")), \
             mock.patch.object(branding, "_webfont", side_effect=OSError("boom")):
            branding.apply(ex, quiet_reporter(), "alice")   # must not raise

    def test_the_two_halves_are_caught_separately(self) -> None:
        # A dead font mirror must still leave the favicon in place.
        ex = RecordingExecutor()
        with mock.patch.object(branding, "code_server_root",
                               return_value=Path("/nonexistent/code-server-1.2.3")), \
             mock.patch.object(branding, "_favicon") as fav, \
             mock.patch.object(branding, "_webfont", side_effect=OSError("mirror down")):
            branding.apply(ex, quiet_reporter(), "alice")
        self.assertEqual(1, fav.call_count)


if __name__ == "__main__":
    unittest.main()
