#!/usr/bin/env python3
"""A minimal OIDC provider for the sso-mode gate — stdlib only, real RS256.

Google's IdP cannot live inside a hermetic container, but the authz boundary
this slice ships (login -> 200, non-whitelisted -> never 200, revoke -> denied,
rotate-sso -> old cookie dead) is unassertable without a completed login. So
the gate runs its own IdP and points VIDE's rendered oidc_issuer_url at it
(VIDE_SSO_ISSUER_URL — the same URL-override seam the product uses for every
other upstream).

Strict-stdlib binds src/, not the harness: this file may shell out to openssl
for the RSA signature (there is no stdlib RSA), which is exactly what the
harness already does for the keypair.

WHICH IDENTITY LOGS IN is read fresh from the control file on every /authorize,
so ONE IdP serves alice, mallory, MixedCase@ and user+tag@ across the gate's
sections without a restart.

Named failure modes this file defends against (each one is a debugging
landmine otherwise):
  * issuer mismatch — go-oidc compares the discovery `issuer` byte-for-byte
    with the configured issuer URL, trailing slash included: ONE value feeds
    both (--issuer), never two spellings.
  * padded base64url in the JWK or the JWT — go-jose rejects it; every b64
    here is urlsafe and stripped of '='.
  * nonce not echoed — oauth2-proxy rejects the id_token; /authorize stores
    it with the code and /token echoes it into the claims.
  * email_verified absent/false — redeem is refused. That is a FEATURE the
    gate exploits as a positive control (the unverified-email row), so it is
    controllable per login via the control file.
  * text-mode subprocess mangling the signature — openssl I/O is binary only.
  * lazy JWKS fetch — go-oidc fetches the keys at first verify, not at
    discovery, so this server must outlive the whole gate, not just §1.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

KID = "vide-fake-1"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def arg(name: str, default: str = "") -> str:
    flag = f"--{name}="
    for a in sys.argv[1:]:
        if a.startswith(flag):
            return a[len(flag):]
    return default


ISSUER = arg("issuer").rstrip("/")
PORT = int(arg("port", "8555"))
KEYFILE = arg("key")
CLIENT_ID = arg("client-id")
CLIENT_SECRET = arg("client-secret")
CONTROL = arg("control")  # file: "<email>" or "<email> unverified"


def client_credentials(headers: Any, form: dict) -> tuple[str, str]:
    """The (client_id, client_secret) pair a redeem presented. RFC 6749 §2.3.1
    permits BOTH channels and oauth2-proxy picks by `--client-secret` handling,
    so accept either — checking only one would let the check be bypassed by
    choosing the other, which is worse than not checking at all. Basic-auth
    values are form-urlencoded per the RFC, hence the unquote_plus."""
    auth = headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            blob = auth[6:].strip()
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode()
        except Exception:
            return "", ""
        cid, sep, sec = raw.partition(":")
        if not sep:
            return "", ""
        return (urllib.parse.unquote_plus(cid), urllib.parse.unquote_plus(sec))
    return (form.get("client_id", [""])[0], form.get("client_secret", [""])[0])


def modulus_n() -> str:
    """JWK 'n' from the PEM, via openssl (no stdlib RSA)."""
    out = subprocess.run(
        ["openssl", "rsa", "-in", KEYFILE, "-noout", "-modulus"],
        capture_output=True, check=True).stdout.decode()
    hex_mod = out.strip().split("Modulus=", 1)[1]
    return b64u(bytes.fromhex(hex_mod))


def sign_rs256(header: dict, claims: dict) -> str:
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}".encode()
    # `openssl dgst -sha256 -sign` is PKCS#1 v1.5 over SHA-256 — that IS RS256.
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", KEYFILE],
        input=signing_input, capture_output=True, check=True).stdout
    return f"{signing_input.decode()}.{b64u(sig)}"


def current_identity() -> tuple[str, bool]:
    """(email, email_verified) — read fresh, so the harness can switch users."""
    raw = open(CONTROL).read().strip().split()
    email = raw[0] if raw else "nobody@example.test"
    verified = not (len(raw) > 1 and raw[1] == "unverified")
    return email, verified


CODES: dict[str, dict] = {}  # single-use: a reused code must 400, never re-mint


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the gate's output readable
        pass

    def _json(self, obj: dict, code: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        q = urllib.parse.parse_qs(query)

        if path == "/.well-known/openid-configuration":
            self._json({
                "issuer": ISSUER,                      # byte-equal to the configured issuer
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/jwks",
                "userinfo_endpoint": f"{ISSUER}/userinfo",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "email", "profile"],
                "claims_supported": ["sub", "email", "email_verified", "aud", "iss"],
            })
        elif path == "/jwks":
            self._json({"keys": [{
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                "n": modulus_n(), "e": "AQAB",
            }]})
        elif path == "/authorize":
            redirect_uri = q.get("redirect_uri", [""])[0]
            state = q.get("state", [""])[0]
            nonce = q.get("nonce", [""])[0]
            email, verified = current_identity()
            code = b64u(f"{email}:{time.time()}".encode())
            CODES[code] = {"email": email, "verified": verified, "nonce": nonce}
            sep = "&" if "?" in redirect_uri else "?"
            loc = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
            self.send_response(302)
            self.send_header("Location", loc)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/userinfo":
            email, verified = current_identity()
            self._json({"sub": email, "email": email, "email_verified": verified})
        else:
            self._json({"error": "not_found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?")[0] != "/token":
            self._json({"error": "not_found"}, 404)
            return
        n = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(n).decode())
        # The redeem must PROVE the client secret, exactly as Google does.
        # Without this the gate's crown row ("whitelisted alice reaches the IDE,
        # 200") stayed green while VIDE had recorded a wrong, truncated or empty
        # OAUTH2_PROXY_CLIENT_SECRET — i.e. the one production failure only a
        # live login can witness was the one thing the live tier could not see.
        # CLIENT_ID is already checked downstream (it is the `aud` claim); the
        # secret had no witness at all.
        cid, secret = client_credentials(self.headers, form)
        if cid != CLIENT_ID or secret != CLIENT_SECRET:
            self._json({"error": "invalid_client"}, 401)
            return
        code = form.get("code", [""])[0]
        rec = CODES.pop(code, None)          # single-use by construction
        if rec is None:
            self._json({"error": "invalid_grant"}, 400)
            return
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": rec["email"],
            "email": rec["email"],
            "email_verified": rec["verified"],
            "nonce": rec["nonce"],
            "iat": now,
            "exp": now + 3600,
        }
        id_token = sign_rs256({"alg": "RS256", "typ": "JWT", "kid": KID}, claims)
        self._json({
            "access_token": b64u(b"fake-access-token"),
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        })


if __name__ == "__main__":
    # 127.0.0.1 only — a gate IdP that listened on 0.0.0.0 would be a real
    # unauthenticated token minter on whatever network the container joins.
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
