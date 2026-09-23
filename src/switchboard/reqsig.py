"""Signed relay requests (spec section 5, "Request signing").

Endpoints that act on behalf of an identity (inbox, ack, subscriptions, card,
report, admin) authenticate with three headers::

    X-Switchboard-Pubkey:    ed25519:...
    X-Switchboard-Timestamp: 2026-09-18T12:00:00Z
    X-Switchboard-Nonce:     <random hex, unique per request>
    X-Switchboard-Signature: base64(Ed25519(canonical({
        "relay": "<relay ed25519 pubkey from /v1/guide>",
        "method": "GET", "path": "/v1/inbox", "query": "cursor=0&limit=50",
        "timestamp": "...", "nonce": "...", "body_sha256": "<hex sha256 of raw body, empty body = sha256(b'')>"
    })))

``relay`` binds the request to one relay, so a captured request cannot be
replayed to another relay where the same identity exists. The relay rejects
timestamps outside +/- 5 minutes and remembers every signature it accepts for
that window, so a captured request cannot be replayed to the same relay
either.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from . import crypto
from .canonical import canonical_bytes
from .envelope import CLOCK_SKEW_SECONDS, EnvelopeError, now_iso, parse_iso

HEADER_PUBKEY = "X-Switchboard-Pubkey"
HEADER_TIMESTAMP = "X-Switchboard-Timestamp"
HEADER_NONCE = "X-Switchboard-Nonce"
HEADER_SIGNATURE = "X-Switchboard-Signature"


def signing_payload(relay_pubkey: str, method: str, path: str, query: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return canonical_bytes(
        {
            "relay": relay_pubkey,
            "method": method.upper(),
            "path": path,
            "query": query or "",
            "timestamp": timestamp,
            "nonce": nonce,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )


def sign_request(keypair: crypto.Keypair, relay_pubkey: str, method: str, path: str, query: str, body: bytes) -> dict[str, str]:
    # Ed25519 is deterministic, so two identical requests in the same second
    # would share a signature and the second would look like a replay. The
    # nonce makes every signature unique.
    ts = now_iso()
    nonce = os.urandom(16).hex()
    sig = keypair.sign(signing_payload(relay_pubkey, method, path, query, ts, nonce, body))
    return {HEADER_PUBKEY: keypair.ed25519_pub, HEADER_TIMESTAMP: ts, HEADER_NONCE: nonce, HEADER_SIGNATURE: sig}


class RequestAuthError(ValueError):
    pass


def verify_request(headers, relay_pubkey: str, method: str, path: str, query: str, body: bytes, now: datetime | None = None) -> tuple[str, str]:
    """Return ``(pubkey, signature)`` or raise :class:`RequestAuthError`.

    The caller is responsible for rejecting a signature it has seen before.
    """
    pubkey = headers.get(HEADER_PUBKEY)
    ts = headers.get(HEADER_TIMESTAMP)
    nonce = headers.get(HEADER_NONCE)
    sig = headers.get(HEADER_SIGNATURE)
    if not (pubkey and ts and sig and nonce):
        raise RequestAuthError("missing signature headers")
    if len(nonce) > 64:
        raise RequestAuthError("nonce too long")
    if not crypto.is_ed25519_pub(pubkey):
        raise RequestAuthError("malformed pubkey header")
    try:
        when = parse_iso(ts)
    except EnvelopeError as exc:
        raise RequestAuthError(str(exc)) from exc
    current = now or datetime.now(timezone.utc)
    if abs((current - when).total_seconds()) > CLOCK_SKEW_SECONDS:
        raise RequestAuthError("request timestamp outside allowed skew")
    if not crypto.verify(pubkey, signing_payload(relay_pubkey, method, path, query, ts, nonce, body), sig):
        raise RequestAuthError("bad request signature")
    return pubkey, sig
