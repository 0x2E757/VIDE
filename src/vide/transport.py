"""Optional install-time end-to-end seam probe. WARN-ONLY: never fails the
install — the perimeter (TLS, DNS, whitelist) is the operator's."""
from __future__ import annotations

from .config import Config
from .executor import Executor
from .reporter import Reporter
from . import system


def _bind_desc(binding) -> str:
    if binding.kind == "unix":
        return f"socket {binding.socket}"
    return f"loopback 127.0.0.1:{binding.port}"


def _probe_local(binding) -> bool:
    if binding.kind == "unix":
        return system.healthz_unix(str(binding.socket), timeout=2.0)
    return system.healthz(binding.port, timeout=2.0)


def probe_transport(cfg: Config, ex: Executor, rep: Reporter, binding, fqdn: str = "") -> None:
    # Read-only diagnostic against a live service a preview never started.
    if ex.narrate(f"probe {_bind_desc(binding)}{f' and public https://{fqdn}' if fqdn else ''}"):
        return

    # Retry: `systemctl enable --now` on a Type=exec unit returns at execve,
    # not at "listening", so a single immediate probe can false-negative a
    # healthy cold start. Poll briefly before warning.
    ok = False
    attempts = 0
    for attempts in range(1, 11):
        if _probe_local(binding):
            ok = True
            break
        ex.idle(1.0)  # tick-paced under the wizard: the screen stays alive
    if ok:
        rep.info(f"probe: {_bind_desc(binding)}/healthz OK")
    else:
        rep.warn(f"probe: {_bind_desc(binding)}/healthz did not answer after "
                 f"~{attempts}s — check 'vide status'")

    if binding.kind == "unix":
        # In socket mode the socket's perms ARE the authz policy; root's probe
        # bypasses 0660, so pair the health check with the stat.
        st = system.socket_stat(binding.socket)
        if st is None or not st.is_socket or st.mode != 0o660:
            rep.warn(f"probe: socket {binding.socket} is not a 0660 socket — "
                     "check 'vide doctor'")

    if not fqdn:
        return

    if binding.kind == "unix":
        # Under SSO the public endpoint is behind the auth gate: an
        # unauthenticated request 302s to the login (or the proxy). A
        # following-redirects "200" here would just be Google's login page — not
        # a health signal — and the WS-upgrade probe cannot pass the gate. So
        # the perimeter is the operator's to verify; VIDE says so and stops.
        rep.info(f"probe: SSO instance — reachability of https://{fqdn} through the "
                 "auth gate is verified by a real browser login (the operator's layer)")
        return

    if system.https_ok(f"https://{fqdn}/healthz"):
        rep.info(f"probe: public https://{fqdn}/healthz OK")
    else:
        rep.warn(f"probe: public https://{fqdn}/healthz failed (DNS/TLS/proxy not "
                 "ready yet, or whitelist blocks this host) — this is the operator's layer")

    # WebSocket upgrade check: a correct proxy answers with HTTP 101. This one
    # probe stays a curl subprocess — urllib manages the Connection header
    # itself and cannot send an honest Upgrade request. curl is on the tool
    # floor; the probe is warn-only and must time out rather than hang.
    out = system.query(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "5",
                        "-H", "Connection: Upgrade", "-H", "Upgrade: websocket",
                        "-H", "Sec-WebSocket-Version: 13",
                        "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                        f"https://{fqdn}/"], timeout=10.0)
    code = out.stdout.strip() if out.returncode == 0 else ""
    if code == "101":
        rep.info(f"probe: WebSocket upgrade through https://{fqdn} OK (101)")
    else:
        # A non-101 at "/" is often benign (code-server may 302 the root
        # without a real WS handshake) — inconclusive, not a failure.
        rep.info(f"probe: WebSocket upgrade at https://{fqdn}/ was inconclusive "
                 f"(HTTP {code or '?'}, not 101). This is often normal; only "
                 "investigate if terminals fail to connect in the browser "
                 "(see docs/reverse-proxy.md).")
