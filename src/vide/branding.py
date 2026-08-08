"""Post-install branding of the code-server tree: the VIDE mark as the favicon,
and JetBrains Mono shipped as a WEBFONT so the default editor/terminal font
renders on whatever machine the operator opens the IDE from.

WHY A WEBFONT AND NOT A PACKAGE. code-server renders in a browser, so
`editor.fontFamily` resolves against fonts on the CLIENT. Installing a font on
the server — with apt or anything else — is invisible to the editor. The bytes
have to be SERVED and declared with @font-face in the workbench document. The
serving half is free: code-server mounts its own root at `/_static`
(out/node/routes/index.js: `app.router.use("/_static", express.static(rootPath))`),
so a file dropped beside the other media is already reachable.

WHY THIS IS RE-APPLIED RATHER THAN DONE ONCE. Everything here patches a VENDORED
tree under ~<user>/.local/lib/code-server-<version>/, and `vide upgrade` installs
a NEW versioned directory — no edit survives it. So this hangs off the one choke
point install and upgrade share, codeserver._install_code_server(). Anything
added here must therefore be idempotent and cheap.

NOTHING HERE IS LOAD-BEARING. Every step is best-effort and downgrades to a
warning: a missing favicon or an unreachable font mirror must never cost the
operator an IDE. That posture is also why the font is DOWNLOADED rather than
vendored — the repo stays text-only, see .gitattributes — and why each file is
pinned to a hash baked in HERE rather than one fetched beside the asset, which
would only prove that the host agrees with itself.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from .executor import Executor
from .reporter import Reporter
from . import contract, system

# JetBrains Mono v2.304, OFL-1.1 (redistributable). Three faces, not the full
# family of sixteen: regular carries the body, bold carries syntax emphasis and
# italic carries comments. Bold-italic is rare enough that the browser's
# synthetic slant is an acceptable answer, and every extra face is another
# ~95 KB download and another pin to keep honest.
FONT_TAG = "v2.304"
FONT_REPO = f"https://raw.githubusercontent.com/JetBrains/JetBrainsMono/{FONT_TAG}"
FONT_BASE = f"{FONT_REPO}/fonts/webfonts"
FONT_FAMILY = "JetBrains Mono"
FONTS: tuple[tuple[str, str, str, str], ...] = (
    # file, sha256, css weight, css style
    ("JetBrainsMono-Regular.woff2",
     "a9cb1cd82332b23a47e3a1239d25d13c86d16c4220695e34b243effa999f45f2",
     "400", "normal"),
    ("JetBrainsMono-Bold.woff2",
     "c503cc5ec5f8b2c7666b7ecda1adf44bd45f2e6579b2eba0fc292150416588a2",
     "700", "normal"),
    ("JetBrainsMono-Italic.woff2",
     "cb6a1b246318ed3885d7dffa14a2609297fe80e9b8e500bea33b52fa312a36a4",
     "400", "italic"),
)

# OFL-1.1 obliges every copy of the Font Software to carry the copyright notice
# and the licence, and this module makes copies: three faces onto the box, which
# code-server then serves from `/_static`. So the licence travels with them.
# ONE file discharges both halves of that obligation — OFL.txt's first line IS
# the copyright notice. Pinned exactly like the faces, from the same tag: an
# unpinned licence file would also be an unreviewed third-party download.
OFL_FILE = "OFL.txt"
OFL_URL = f"{FONT_REPO}/{OFL_FILE}"
OFL_SHA256 = "30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad"

# Paths inside the versioned code-server tree.
MEDIA = "src/browser/media"
WORKBENCH = "lib/vscode/out/vs/code/browser/workbench/workbench.html"
# The two favicons workbench.html actually references: the SVG is `rel="icon"`
# for every modern browser, the .ico is only the `alternate`. The .ico and the
# PWA PNGs are left upstream's — replacing them means shipping binaries, which
# is the one thing this module is built to avoid.
FAVICONS = ("favicon.svg", "favicon-dark-support.svg")

# Idempotency marker AND uninstall handle: one grep says whether a tree is
# already branded, and the block is bounded so it can be cut back out.
MARK_BEGIN = "<!-- VIDE branding: begin -->"
MARK_END = "<!-- VIDE branding: end -->"


def code_server_root(user: str) -> Path | None:
    """The versioned directory the `code-server` shim points into.

    Resolved through the symlink rather than globbed for: a box that has been
    upgraded carries SEVERAL code-server-<ver> directories, and a glob would
    pick by string order — branding the wrong one, silently, on exactly the
    boxes that have been running longest.
    """
    home = system.user_home(user)
    if home is None:
        return None
    probe = system.query_as(user, ["readlink", "-f", str(home / ".local/bin/code-server")])
    if probe.returncode != 0 or not probe.stdout.strip():
        return None
    # <root>/bin/code-server -> <root>
    return Path(probe.stdout.strip()).parent.parent


def apply(ex: Executor, rep: Reporter, user: str) -> None:
    """Brand the tree for `user`. Best-effort end to end: the caller's install
    has already succeeded and must not be undone by cosmetics. The two halves
    are caught SEPARATELY so a font mirror being down still leaves the favicon."""
    if ex.narrate(f"would brand code-server for '{user}' (favicon + {FONT_FAMILY} webfont)"):
        return
    root = code_server_root(user)
    if root is None:
        rep.warn(f"branding skipped for '{user}': no resolvable code-server tree")
        return
    try:
        _favicon(ex, rep, user, root)
    except Exception as exc:                                # noqa: BLE001
        rep.warn(f"favicon branding skipped: {exc}")
    try:
        faces = _webfont(ex, rep, user, root)
        if faces:
            _patch_workbench(ex, rep, user, root, faces)
    except Exception as exc:                                # noqa: BLE001
        rep.warn(f"{FONT_FAMILY} webfont skipped: {exc} — the editor falls back "
                 "to whatever monospace the browser has")


def _favicon(ex: Executor, rep: Reporter, user: str, root: Path) -> None:
    svg = contract.standalone_mark_svg()
    for name in FAVICONS:
        ex.write_as_user(user, root / MEDIA / name, svg, mode=0o644)
    rep.info(f"favicon: VIDE mark written to {root / MEDIA}")


def _webfont(ex: Executor, rep: Reporter, user: str,
             root: Path) -> tuple[tuple[str, str, str], ...]:
    """Download, verify and place the faces, and the OFL licence beside them.
    Returns the (file, weight, style) triples that actually landed — raising
    instead of returning a partial set is deliberate: half a family would produce
    @font-face rules that 404 on every page load, which is worse than no webfont
    at all."""
    staging = Path(tempfile.mkdtemp(prefix="vide-font."))
    landed: list[tuple[str, str, str]] = []
    try:
        # The faces are BINARY, so they are copied by a subprocess rather than
        # piped through Executor.write_as_user, which is a text/`tee` path and
        # would mangle them. The copy runs AS THE USER — root must not write
        # into a tree the user controls (the symlink-attack reasoning on
        # Executor.atomic_write) — so the staging dir is opened to 0755/0644
        # for exactly as long as the copy takes, then destroyed. Nothing secret
        # passes through it: these are public font files.
        ex.run(["chmod", "0755", str(staging)])
        # The licence goes down FIRST, and a failure here raises rather than
        # warns: a face sitting on disk without it is precisely the omission
        # this closes, so "no webfont at all" is the correct answer to a licence
        # that will not verify. `apply` catches it and the editor falls back to
        # the browser's monospace — the same degradation as a dead font mirror.
        # No override_var on either fetch, deliberately, and unlike every other
        # download in VIDE: these files are pinned by sha256 to one tag, so a
        # redirected base could not satisfy the pins anyway. Naming a knob here
        # would advertise an escape hatch that cannot exist — the failure to fix
        # is a moved upstream tag, and that needs a re-pin, not an env var.
        licence = staging / OFL_FILE
        ex.download(OFL_URL, licence, None)
        got = _hash_file(licence)
        if got != OFL_SHA256:
            raise ValueError(f"{OFL_FILE} sha256 mismatch "
                             f"(want {OFL_SHA256}, got {got})")
        ex.run(["chmod", "0644", str(licence)])
        ex.run_as(user, ["install", "-m", "0644", str(licence),
                         str(root / MEDIA / OFL_FILE)])
        for name, want, weight, style in FONTS:
            local = staging / name
            ex.download(f"{FONT_BASE}/{name}", local, None)
            got = _hash_file(local)
            if got != want:
                raise ValueError(f"{name} sha256 mismatch (want {want}, got {got})")
            ex.run(["chmod", "0644", str(local)])
            ex.run_as(user, ["install", "-m", "0644", str(local),
                             str(root / MEDIA / name)])
            landed.append((name, weight, style))
        rep.info(f"webfont: {len(landed)} {FONT_FAMILY} faces + {OFL_FILE} "
                 "verified and placed")
        return tuple(landed)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def font_face_css(faces: tuple[tuple[str, str, str], ...]) -> str:
    """The @font-face block. `{{BASE}}` is workbench.html's own placeholder for
    the deployment path, substituted per request — hardcoding `/` here would
    break any code-server served under a sub-path."""
    rules = "".join(
        f"@font-face{{font-family:'{FONT_FAMILY}';"
        f"src:url('{{{{BASE}}}}/_static/{MEDIA}/{name}') format('woff2');"
        f"font-weight:{weight};font-style:{style};font-display:swap}}"
        for name, weight, style in faces)
    return f"{MARK_BEGIN}<style>{rules}</style>{MARK_END}"


def _patch_workbench(ex: Executor, rep: Reporter, user: str, root: Path,
                     faces: tuple[tuple[str, str, str], ...]) -> None:
    path = root / WORKBENCH
    probe = system.query_as(user, ["cat", str(path)])
    if probe.returncode != 0:
        raise ValueError(f"cannot read {path}")
    html = probe.stdout
    if MARK_BEGIN in html:
        rep.debug("workbench.html already carries the VIDE font block")
        return
    if "</head>" not in html:
        raise ValueError("workbench.html has no </head> to anchor the font block")
    # Last </head> would be wrong in a document with a commented-out one; there
    # is exactly one here, and split on the FIRST keeps the block in the real
    # head if upstream ever adds another below.
    head, sep, rest = html.partition("</head>")
    ex.write_as_user(user, path, head + font_face_css(faces) + "\n" + sep + rest,
                     mode=0o644)
    rep.info(f"webfont: @font-face block added to {path.name}")


# The font stack. The fallbacks after the family are load-bearing: the webfont
# download is best-effort, so this has to still name something real when it did
# not land.
FONT_STACK = f"'{FONT_FAMILY}', Menlo, Monaco, 'Courier New', monospace"

# VIDE's opinionated defaults for a fresh instance. Seeded ONCE — see
# seed_user_settings — so this is the only chance to get them right.
DEFAULT_SETTINGS: dict[str, object] = {
    "editor.fontFamily": FONT_STACK,
    "terminal.integrated.fontFamily": FONT_STACK,
    # JetBrains Mono's coding ligatures live in `calt`, NOT in `liga` — its
    # `liga` feature is empty (verified with fontTools against the exact woff2
    # files pinned above). That matters because VS Code does not merely leave
    # ligatures off by default, it actively DISABLES them: the shipped build
    # carries OFF = '"liga" off, "calt" off' and ON = '"liga" on, "calt" on'.
    # So without this line the font renders with its headline feature switched
    # off, and the cause is invisible — it looks like the font lacks them.
    "editor.fontLigatures": True,
    "terminal.integrated.fontLigatures.enabled": True,
    # Chat/agent surface off by default: an instance that advertises a sign-in
    # VIDE has no part in is noise at best. Seeded, not converged, so an operator
    # who wants it back just flips these three keys in their own settings.json.
    "chat.titleBar.openInAgentsWindow.enabled": False,
    "chat.titleBar.signIn.enabled": False,
    "chat.agent.enabled": False,
}


def seed_user_settings(ex: Executor, rep: Reporter, user: str) -> None:
    """Write VIDE's default settings ONCE, and only if the file is absent.

    Seed-if-absent, never converge: this file is the operator's, not VIDE's.
    Re-asserting it on every run would silently revert their own edits — the
    same defect class the config.yaml never-regenerate guard in secrets.py
    exists to prevent.

    TWO CONSEQUENCES, both accepted and both worth stating because they are the
    kind that surprise you later:
      * an operator who already has a settings.json gets NONE of these defaults;
      * changing DEFAULT_SETTINGS does not reach any instance that has already
        been seeded. A new default is a new-instance default. Existing boxes
        need the key added by hand.
    """
    home = system.user_home(user)
    if home is None:
        return
    dest = home / ".local/share/code-server/User/settings.json"
    if system.probe_as(user, ["test", "-e", str(dest)]):
        rep.debug(f"settings.json already exists for '{user}' — left alone")
        return
    if ex.narrate(f"would seed {dest} with VIDE's defaults ({FONT_FAMILY}, "
                  "ligatures on, chat surface off)"):
        return
    body = json.dumps(DEFAULT_SETTINGS, indent=2) + "\n"
    ex.ensure_dir_as_user(user, dest.parent, mode=0o755)
    ex.write_as_user(user, dest, body, mode=0o644)
    rep.info(f"seeded {dest.name} with VIDE's defaults "
             f"({FONT_FAMILY}, ligatures on, chat surface off)")


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()
