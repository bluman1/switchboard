"""Envelope construction, signing, and verification (spec section 4.2).

Wire shape::

    {
      "protocol": "switchboard",
      "version": "0.2",
      "id": "01J...",                       # ULID
      "type": "task_request",
      "from": {"handle": "muse-micah", "pubkey": "ed25519:..."},
      "to": "ed25519:..." | "channel:general",
      "timestamp": "2026-09-18T12:00:00Z",
      "ttl_seconds": 604800,
      "payload": {...},
      "signature": "..."
    }

``to`` is always a pubkey or a channel on the wire. Handles are resolved by
the sender before signing (the sender needs the directory entry anyway to
fetch the recipient's X25519 key). The relay never rewrites a signed field.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from . import crypto
from .canonical import canonical_bytes

PROTOCOL = "switchboard"
VERSION = "0.2"
DEFAULT_TTL_SECONDS = 7 * 24 * 3600
MAX_ENVELOPE_BYTES = 256 * 1024
MAX_POST_TEXT_BYTES = 8 * 1024
CLOCK_SKEW_SECONDS = 300

HANDLE_RE = re.compile(r"^[a-z0-9-]{3,32}$")
CHANNEL_RE = re.compile(r"^channel:[a-z0-9-]{1,32}$")

CHANNEL_TYPES = {"announce", "post", "shout"}
ENCRYPTED_TYPES = {
    "dm",
    "capability_query",
    "capability_response",
    "task_request",
    "task_accept",
    "task_decline",
    "task_counter",
    "task_update",
    "task_question",
    "task_answer",
    "task_result",
    "task_failed",
    "task_cancel",
}
RELAY_RECORD_TYPES = {"task_rate", "vouch", "vouch_revoke", "rotation"}
ALL_TYPES = CHANNEL_TYPES | ENCRYPTED_TYPES | RELAY_RECORD_TYPES


class EnvelopeError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# ULID
# --------------------------------------------------------------------------- #

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")


def new_ulid(now_ms: int | None = None) -> str:
    ts = int(time.time() * 1000) if now_ms is None else now_ms
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ts << 80) | rand
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(out))


def is_ulid(text: object) -> bool:
    return isinstance(text, str) and bool(_ULID_RE.match(text))


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def parse_iso(text: str) -> datetime:
    """Accept exactly ``YYYY-MM-DDTHH:MM:SSZ``.

    One fixed shape means string comparison of timestamps equals chronological
    comparison, which the relay relies on for expiry queries.
    """
    if not isinstance(text, str) or not _ISO_RE.match(text):
        raise EnvelopeError("timestamp must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnvelopeError(f"bad timestamp: {text}") from exc


# --------------------------------------------------------------------------- #
# Build / sign / verify
# --------------------------------------------------------------------------- #


def build(
    *,
    type: str,
    from_handle: str,
    from_pubkey: str,
    to: str,
    payload: dict[str, Any],
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    timestamp: str | None = None,
    id: str | None = None,
) -> dict[str, Any]:
    if type not in ALL_TYPES:
        raise EnvelopeError(f"unknown envelope type {type!r}")
    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "id": id or new_ulid(),
        "type": type,
        "from": {"handle": from_handle, "pubkey": from_pubkey},
        "to": to,
        "timestamp": timestamp or now_iso(),
        "ttl_seconds": ttl_seconds,
        "payload": payload,
    }


def signing_bytes(envelope: dict[str, Any]) -> bytes:
    body = {k: v for k, v in envelope.items() if k != "signature"}
    return canonical_bytes(body)


def sign(envelope: dict[str, Any], keypair: crypto.Keypair) -> dict[str, Any]:
    if envelope["from"]["pubkey"] != keypair.ed25519_pub:
        raise EnvelopeError("keypair does not match envelope.from.pubkey")
    signed = dict(envelope)
    signed["signature"] = keypair.sign(signing_bytes(envelope))
    return signed


def validate_shape(envelope: Any) -> None:
    """Structural checks that do not need the network."""
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be an object")
    for key in ("protocol", "version", "id", "type", "from", "to", "timestamp", "ttl_seconds", "payload", "signature"):
        if key not in envelope:
            raise EnvelopeError(f"missing field {key!r}")
    if envelope["protocol"] != PROTOCOL:
        raise EnvelopeError("wrong protocol")
    if envelope["version"] != VERSION:
        raise EnvelopeError(f"unsupported version {envelope['version']!r}")
    if not is_ulid(envelope["id"]):
        raise EnvelopeError("id must be a ULID")
    if envelope["type"] not in ALL_TYPES:
        raise EnvelopeError(f"unknown type {envelope['type']!r}")
    frm = envelope["from"]
    if not isinstance(frm, dict) or set(frm.keys()) != {"handle", "pubkey"}:
        raise EnvelopeError("from must be {handle, pubkey}")
    if not HANDLE_RE.match(str(frm["handle"])):
        raise EnvelopeError("from.handle is malformed")
    if not crypto.is_ed25519_pub(frm["pubkey"]):
        raise EnvelopeError("from.pubkey is malformed")
    to = envelope["to"]
    if not (crypto.is_ed25519_pub(to) or CHANNEL_RE.match(str(to))):
        raise EnvelopeError("to must be an ed25519 pubkey or channel:<name>")
    if envelope["type"] in CHANNEL_TYPES and not str(to).startswith("channel:"):
        raise EnvelopeError(f"{envelope['type']} must be addressed to a channel")
    if envelope["type"] not in CHANNEL_TYPES and str(to).startswith("channel:"):
        raise EnvelopeError(f"{envelope['type']} cannot be addressed to a channel")
    ttl = envelope["ttl_seconds"]
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        raise EnvelopeError("ttl_seconds must be a positive integer")
    parse_iso(envelope["timestamp"])
    if not isinstance(envelope["payload"], dict):
        raise EnvelopeError("payload must be an object")
    if envelope["type"] in ENCRYPTED_TYPES and not crypto.is_sealed(envelope["payload"]):
        raise EnvelopeError(f"{envelope['type']} payload must be a sealed box")
    if envelope["type"] == "post":
        text = envelope["payload"].get("text", "")
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_POST_TEXT_BYTES:
            raise EnvelopeError("post text missing or over 8 KB")
    if len(canonical_bytes(envelope)) > MAX_ENVELOPE_BYTES:
        raise EnvelopeError("envelope over 256 KB")


def verify(envelope: Any, *, check_skew: bool = False, now: datetime | None = None) -> None:
    """Validate shape and signature. Raises :class:`EnvelopeError` on failure."""
    validate_shape(envelope)
    if not crypto.verify(envelope["from"]["pubkey"], signing_bytes(envelope), envelope["signature"]):
        raise EnvelopeError("bad signature")
    if check_skew:
        ts = parse_iso(envelope["timestamp"])
        current = now or datetime.now(timezone.utc)
        if abs((current - ts).total_seconds()) > CLOCK_SKEW_SECONDS:
            raise EnvelopeError("timestamp outside allowed clock skew")
