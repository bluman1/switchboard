"""HTTP client for the relay API (spec section 5)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

import httpx

from . import crypto, envelope, reqsig
from .canonical import canonical_bytes


class RelayError(RuntimeError):
    def __init__(self, status: int, detail: str):
        super().__init__(f"relay returned {status}: {detail}")
        self.status = status
        self.detail = detail


class DirectoryError(RuntimeError):
    """The relay served a directory entry that does not verify."""


def verify_entry(entry: dict[str, Any]) -> None:
    """Check the entry's signed registration against what the relay claims.

    The registration body was signed by the identity key at registration, so a
    relay cannot swap the X25519 key or the handle of a pubkey without breaking
    the signature. The card inside the registration may be stale (cards are
    updated later, unsigned); only the binding fields are checked.
    """
    reg = entry.get("registration")
    if not isinstance(reg, dict) or "signature" not in reg:
        raise DirectoryError("entry has no signed registration")
    unsigned = {k: v for k, v in reg.items() if k != "signature"}
    if not crypto.verify(entry["pubkey"], canonical_bytes(unsigned), reg["signature"]):
        raise DirectoryError("registration signature does not verify for this pubkey")
    if reg.get("ed25519_pubkey") != entry["pubkey"]:
        raise DirectoryError("registration pubkey does not match entry")
    if reg.get("x25519_pubkey") != entry.get("x25519_pubkey"):
        raise DirectoryError("relay-served x25519_pubkey differs from the signed registration")
    if entry.get("handle") is not None and reg.get("handle") != entry["handle"]:
        raise DirectoryError("relay-served handle differs from the signed registration")
    rot = entry.get("rotation")
    if rot is not None:
        envelope.verify(rot)
        if rot["from"]["pubkey"] != entry["pubkey"] or rot["type"] != "rotation":
            raise DirectoryError("rotation record is not signed by this identity")
        if rot["payload"].get("new_pubkey") != entry.get("rotated_to"):
            raise DirectoryError("relay-served rotated_to differs from the signed rotation")


class RelayClient:
    """Thin wrapper. ``http`` may be any object with ``httpx.Client``'s ``request``
    method (a ``fastapi.testclient.TestClient`` works for in-process tests)."""

    def __init__(self, base_url: str = "", keypair: crypto.Keypair | None = None, http: Any = None, timeout: float = 30.0, relay_pubkey: str | None = None):
        self.keypair = keypair
        self.relay_pubkey = relay_pubkey
        self.http = http or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    # ---- low level -------------------------------------------------------- #

    def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None, signed: bool = False) -> Any:
        query = urlencode({k: v for k, v in (params or {}).items() if v is not None})
        raw = json.dumps(body).encode("utf-8") if body is not None else b""
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if signed:
            if self.keypair is None:
                raise RelayError(0, "this call needs a keypair")
            if self.relay_pubkey is None:
                self.relay_pubkey = self.guide()["relay"]["pubkey"]
            headers.update(reqsig.sign_request(self.keypair, self.relay_pubkey, method, path, query, raw))
        url = path + (f"?{query}" if query else "")
        resp = self.http.request(method, url, content=raw, headers=headers)
        try:
            data = resp.json()
        except ValueError:
            data = {"error": resp.text}
        if resp.status_code >= 400:
            raise RelayError(resp.status_code, str(data.get("error", data)) if isinstance(data, dict) else str(data))
        return data

    # ---- public ------------------------------------------------------------ #

    def guide(self) -> dict[str, Any]:
        return self._call("GET", "/v1/guide")

    def register(self, *, handle: str, runtime: str, card: dict[str, Any]) -> dict[str, Any]:
        assert self.keypair is not None
        body = {
            "handle": handle,
            "ed25519_pubkey": self.keypair.ed25519_pub,
            "x25519_pubkey": self.keypair.x25519_pub,
            "runtime": runtime,
            "capability_card": card,
        }
        body["signature"] = self.keypair.sign(canonical_bytes(body))
        return self._call("POST", "/v1/register", body=body)

    def lookup(self, handle_or_pubkey: str) -> dict[str, Any]:
        entry = self._call("GET", f"/v1/directory/{handle_or_pubkey.lstrip('@')}")
        verify_entry(entry)
        return entry

    def search(self, **filters: Any) -> dict[str, Any]:
        page = self._call("GET", "/v1/directory", params=filters)
        for e in page.get("entries", []):
            verify_entry(e)
        return page

    def publish(self, env: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/v1/publish", body=env)

    def inbox(self, cursor: int | None = None, limit: int = 50) -> dict[str, Any]:
        return self._call("GET", "/v1/inbox", params={"cursor": cursor, "limit": limit}, signed=True)

    def ack(self, cursor: int) -> dict[str, Any]:
        return self._call("POST", "/v1/ack", body={"cursor": cursor}, signed=True)

    def subscribe(self, channel: str) -> dict[str, Any]:
        return self._call("POST", "/v1/subscriptions", body={"channel": channel, "action": "subscribe"}, signed=True)

    def unsubscribe(self, channel: str) -> dict[str, Any]:
        return self._call("POST", "/v1/subscriptions", body={"channel": channel, "action": "unsubscribe"}, signed=True)

    def subscriptions(self) -> list[str]:
        return self._call("GET", "/v1/subscriptions", signed=True)["channels"]

    def update_card(self, card: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/v1/card", body={"capability_card": card}, signed=True)

    def report(self, target_pubkey: str, reason: str, evidence_ids: list[str] | None = None) -> dict[str, Any]:
        return self._call("POST", "/v1/report", body={"target_pubkey": target_pubkey, "reason": reason, "evidence_ids": evidence_ids or []}, signed=True)

    def admin_revoke(self, target_pubkey: str, reason: str) -> dict[str, Any]:
        return self._call("POST", "/v1/admin/revoke", body={"target_pubkey": target_pubkey, "reason": reason}, signed=True)
