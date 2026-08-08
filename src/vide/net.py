"""download() on urllib + the /releases/latest redirect resolver.

Failure classifier: 4xx (except 408/429) is "the URL
moved" — the ONLY accepted breakage — and fails fast naming the override var;
5xx / timeout / connection error / TLS blip / EMPTY BODY retry with linear
backoff. The empty-body rule exists because a broken proxy can close cleanly
with 200 and no payload; trusting that would execute a zero-byte installer
(the rc=99 integer-guard bug class).

Two curl behaviors urllib does NOT give for free, both restored here:
- curl --proto '=https' forbids redirect downgrades; urllib's default handler
  happily follows https -> http. _HttpsOnlyRedirect refuses.
- curl --max-time is a TOTAL wall-clock ceiling; urlopen(timeout=) is per
  blocking socket op (a slow-drip server defeats it). The read loop enforces a
  monotonic deadline.
"""
from __future__ import annotations

import http.client
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Protocol

from .errors import UnavailableError
from .reporter import Reporter


class DlSettings(Protocol):
    """The download tunables — satisfied by Config and by test fakes alike."""
    dl_retries: int
    dl_retry_delay: float
    dl_connect_timeout: float
    dl_max_time: float
    code_server_releases_latest_url: str

_TRANSIENT_4XX = frozenset({408, 429})

# Cloudflare fronts code-server.dev and 403s the default `Python-urllib/3.x`
# User-Agent while passing any product UA (verified empirically: urllib's
# default → 403, `vide/1` and `curl/8` → 302 to the installer). bash never hit
# this because curl ships its own UA. An honest product identifier, not a
# spoof — do not "simplify" this away or every code-server install 403s.
# No `+URL` comment token: that convention points at the software's own home
# page, and naming one we do not own would attribute every install's fetches —
# and any abuse complaint about them — to a stranger. The product token is the
# whole mechanism here; the URL never was.
USER_AGENT = "vide/1 (provisioner)"


class _Transient(Exception):
    pass


def _backoff(seconds: float, tick: Callable[[], None] | None) -> None:
    """Retry sleep. With a tick, sleep in tick-paced slices — a flat
    time.sleep would freeze the wizard for attempt*delay seconds."""
    if tick is None:
        time.sleep(seconds)
        return
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        tick()  # the tick blocks briefly (getch timeout) — it IS the sleep


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()          # verifies chain + hostname
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # explicit floor (curl --tlsv1.2)
    return ctx


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise UnavailableError(f"refusing redirect off https: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    # build_opener keeps the default ProxyHandler, so http_proxy/https_proxy/
    # no_proxy keep working exactly as they did for curl.
    op = urllib.request.build_opener(
        _HttpsOnlyRedirect, urllib.request.HTTPSHandler(context=_tls_context()))
    op.addheaders = [("User-Agent", USER_AGENT)]
    return op


def download(url: str, dest: Path, override_var: str | None, *,
             cfg: DlSettings, rep: Reporter,
             opener: urllib.request.OpenerDirector | None = None,
             tick: Callable[[], None] | None = None) -> None:
    """`tick` is the TUI heartbeat (see Executor): called once per received
    chunk and while backoff-sleeping, so a download never freezes the screen
    for longer than one blocking read (bounded by dl_connect_timeout)."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise UnavailableError(f"refusing non-https URL: {url}")
    hint = (f" — the installer URL may have moved; set {override_var}=<new-url>"
            " in .env and re-run" if override_var else "")
    op = opener or _opener()
    last = "?"
    # The body streams into a same-directory .part sibling and is renamed into
    # place only once complete: a mid-body failure (connection reset, deadline)
    # must never leave a truncated file at dest — a later run, or an operator,
    # would mistake it for the real artifact.
    tmp = dest.with_name(dest.name + ".part")
    try:
        for attempt in range(1, cfg.dl_retries + 1):
            try:
                with op.open(url, timeout=cfg.dl_connect_timeout) as resp:
                    deadline = time.monotonic() + cfg.dl_max_time
                    with open(tmp, "wb") as out:
                        while chunk := resp.read(1 << 16):
                            if time.monotonic() > deadline:
                                raise TimeoutError("download exceeded total time ceiling")
                            out.write(chunk)
                            if tick is not None:
                                tick()
                if tmp.stat().st_size == 0:
                    rep.warn(f"download returned an empty body: {url}")
                    raise _Transient()
                os.replace(tmp, dest)
                return
            except urllib.error.HTTPError as e:
                if 400 <= e.code < 500 and e.code not in _TRANSIENT_4XX:
                    raise UnavailableError(
                        f"download failed with HTTP {e.code} (permanent): {url}{hint}") from e
                last = f"http {e.code}"
            except (urllib.error.URLError, TimeoutError, ConnectionError,
                    http.client.HTTPException, ssl.SSLError, OSError, _Transient) as e:
                if isinstance(e, UnavailableError):
                    raise
                last = type(e).__name__
            if attempt < cfg.dl_retries:
                rep.warn(f"download attempt {attempt}/{cfg.dl_retries} failed "
                         f"({last}): {url} — retrying")
                _backoff(attempt * cfg.dl_retry_delay, tick)  # linear backoff
        raise UnavailableError(
            f"download failed after {cfg.dl_retries} attempts (last: {last}): {url}{hint}")
    finally:
        # No-op after the replace; on any failure it removes the partial.
        # Guarded: a cleanup hiccup must never mask the in-flight error.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


_TAG_RE = re.compile(r"/tag/v(\d+\.\d+\.\d+)/?$")


def resolve_latest_version(cfg: DlSettings, opener: urllib.request.OpenerDirector | None = None,
                           *, url: str = "") -> str:
    """Latest tag from a /releases/latest REDIRECT (the trick code-server's own
    installer uses): no GitHub API, no token, no rate limit. `url` defaults to
    code-server's; oauth2-proxy passes its own. Returns '' on ANY failure —
    resolution must never block provisioning (durability directive), which is
    why this carries the codebase's one sanctioned broad except."""
    try:
        target = url or cfg.code_server_releases_latest_url
        # THE SAME REFUSAL download() MAKES, AND FOR THE SAME REASON. Both release
        # URLs are .env rows, so whoever can write .env can point this anywhere.
        # The prize is smaller than a cleartext download — only \d+.\d+.\d+ is ever
        # taken from the answer — but it still lets a network position choose which
        # version the next step installs, and docs/threat-model.md states the
        # refusal with no exception carved out for this path.
        #
        # RAISED INSIDE THE TRY on purpose: a misconfigured URL then degrades
        # exactly the way an unreachable one does — '' and unpinned latest — rather
        # than becoming the one resolution failure that can stop a provision. What
        # the test pins is not the '' (every failure yields that) but that the
        # opener is NEVER invoked, so nothing is read over cleartext.
        if urllib.parse.urlsplit(target).scheme != "https":
            raise UnavailableError(f"refusing non-https URL: {target}")
        op = opener or _opener()
        req = urllib.request.Request(target, method="HEAD")
        with op.open(req, timeout=cfg.dl_connect_timeout) as resp:
            effective = resp.geturl()
        m = _TAG_RE.search(effective)
        return m.group(1) if m else ""
    except Exception:  # noqa: BLE001 — sanctioned: never block provisioning
        return ""
