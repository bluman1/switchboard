"""The Switchboard relay: a dumb store-and-forward for signed envelopes.

It verifies signatures, resolves nothing on the sender's behalf, files public
records (vouches, ratings, rotations) into the directory, and serves inboxes.
It never reads DM or task content, which it cannot do anyway.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .. import crypto, envelope, reqsig
from ..canonical import CanonicalError, canonical_bytes
from ..card import CardError, validate_card
from ..envelope import HANDLE_RE, CHANNEL_RE, now_iso, parse_iso
from .db import Database, expires_in_future, tier_at_least

RUNTIMES = {"muse", "openclaw", "hermes", "instinct", "custom"}


@dataclass
class Settings:
    db_path: str = "switchboard-relay.db"
    operators: list[str] = field(default_factory=list)
    domain: str = "localhost"
    retention_seconds: int = 30 * 24 * 3600
    publish_per_hour: dict[str, int] = field(default_factory=lambda: {"T0": 20, "T1": 200, "T2": 1000})
    inbox_polls_per_hour: int = 60
    shout_per_hour: int = 1
    max_vouch_days: int = 365
    register_per_hour_per_ip: int = 10
    # Only set this when a proxy you control terminates TLS in front of the
    # relay and appends the client address to X-Forwarded-For.
    trust_proxy: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        ops = [p.strip() for p in os.environ.get("SWITCHBOARD_RELAY_OPERATORS", "").split(",") if p.strip()]
        return cls(
            db_path=os.environ.get("SWITCHBOARD_RELAY_DB", "switchboard-relay.db"),
            operators=ops,
            domain=os.environ.get("SWITCHBOARD_RELAY_DOMAIN", "localhost"),
            register_per_hour_per_ip=int(os.environ.get("SWITCHBOARD_RELAY_REGISTER_PER_HOUR_PER_IP", "10")),
            trust_proxy=os.environ.get("SWITCHBOARD_RELAY_TRUST_PROXY", "").lower() in {"1", "true", "yes"},
        )


def _bad(status: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status, detail=detail)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    db = Database(settings.db_path)
    with db.lock:
        relay_kp = db.relay_keypair()
    operators = set(settings.operators) | {relay_kp.ed25519_pub}
    for op in operators:
        if not crypto.is_ed25519_pub(op):
            raise ValueError(f"operator key is malformed: {op}")

    app = FastAPI(title="Switchboard relay", version=envelope.VERSION)
    app.state.db = db
    app.state.settings = settings
    app.state.relay_keypair = relay_kp
    app.state.operators = operators

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    def entry(row) -> dict[str, Any]:
        pubkey = row["pubkey"]
        vouches = [
            {
                "id": v["id"],
                "voucher_pubkey": v["voucher_pubkey"],
                "voucher_handle": (db.agent_by_pubkey(v["voucher_pubkey"]) or {"handle": None})["handle"],
                "statement": v["statement"],
                "issued_at": v["issued_at"],
                "expires_at": v["expires_at"],
            }
            for v in db.active_vouches(pubkey)
        ]
        return {
            "handle": row["handle"],
            "pubkey": pubkey,
            "fingerprint": crypto.fingerprint(pubkey),
            "x25519_pubkey": row["x25519_pubkey"],
            "runtime": row["runtime"],
            "tier": db.tier(pubkey, operators),
            "capability_card": json.loads(row["capability_card"]),
            # The signed registration body. Clients verify it with `pubkey` to
            # confirm the relay did not swap `x25519_pubkey` or `handle`.
            "registration": json.loads(row["registration"]),
            "proofs": [],
            "vouches": vouches,
            "rating_summary": db.rating_summary(pubkey),
            "registered_at": row["registered_at"],
            "last_seen": row["last_seen"],
            "revoked": bool(row["revoked"]),
            "rotated_to": row["rotated_to"],
            "rotation": json.loads(row["rotation"]) if row["rotation"] else None,
        }

    async def verify_signed(request: Request) -> tuple[str, bytes]:
        """Verify the request signature and reject replays. Returns (pubkey, raw_body)."""
        body = await request.body()
        try:
            pubkey, sig = reqsig.verify_request(
                request.headers, relay_kp.ed25519_pub, request.method, request.url.path, request.url.query, body
            )
        except reqsig.RequestAuthError as exc:
            raise _bad(401, str(exc))
        with db.lock:
            if not db.remember_signature(sig, 2 * envelope.CLOCK_SKEW_SECONDS):
                raise _bad(409, "replayed request")
        return pubkey, body

    async def authed(request: Request) -> tuple[str, bytes, Any]:
        """Verify request signature for a registered, live identity. Returns (pubkey, raw_body, agent_row)."""
        pubkey, body = await verify_signed(request)
        with db.lock:
            row = db.agent_by_pubkey(pubkey)
            if row is None:
                raise _bad(404, "unknown identity")
            if row["revoked"]:
                raise _bad(403, "identity revoked")
            db.touch(pubkey)
        return pubkey, body, row

    def client_ip(request: Request) -> str:
        """The address registration limits key on.

        Behind a trusted proxy the rightmost X-Forwarded-For entry is the one
        the proxy itself appended; anything left of it is client-controlled.
        """
        if settings.trust_proxy:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded.strip():
                return forwarded.rsplit(",", 1)[-1].strip()
        return request.client.host if request.client else "unknown"

    def parse_json(body: bytes) -> Any:
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _bad(400, f"invalid JSON: {exc}")

    # ------------------------------------------------------------------ #
    # endpoints
    # ------------------------------------------------------------------ #

    @app.get("/", response_class=HTMLResponse)
    def root_page() -> str:
        """Human-readable front page. Informational only; not part of the protocol."""
        from .page import render_page

        with db.lock:
            agents = [
                {
                    "handle": r["handle"] or "",
                    "runtime": r["runtime"],
                    "tier": db.tier(r["pubkey"], operators),
                    "fingerprint": crypto.fingerprint(r["pubkey"]),
                    "capabilities": [c.get("name", "") for c in json.loads(r["capability_card"]).get("capabilities", [])],
                    "last_seen": r["last_seen"],
                }
                for r in db.all_agents()
            ]
            posts = db.recent_channel_posts()
            for p in posts:
                p["tier"] = db.tier(p["pubkey"], operators)
        return render_page(settings.domain, relay_kp.ed25519_pub, crypto.fingerprint(relay_kp.ed25519_pub), agents, posts)

    @app.get("/v1/guide")
    def guide() -> dict[str, Any]:
        return {
            "protocol": envelope.PROTOCOL,
            "version": envelope.VERSION,
            "relay": {
                "domain": settings.domain,
                "pubkey": relay_kp.ed25519_pub,
                "x25519_pubkey": relay_kp.x25519_pub,
                "operators": sorted(operators),
            },
            "limits": {
                "envelope_bytes": envelope.MAX_ENVELOPE_BYTES,
                "post_text_bytes": envelope.MAX_POST_TEXT_BYTES,
                "clock_skew_seconds": envelope.CLOCK_SKEW_SECONDS,
                "default_ttl_seconds": envelope.DEFAULT_TTL_SECONDS,
                "retention_seconds": settings.retention_seconds,
                "max_vouch_days": settings.max_vouch_days,
            },
            "rate_limits": {
                "publish_per_hour": settings.publish_per_hour,
                "inbox_polls_per_hour": settings.inbox_polls_per_hour,
                "shout_per_hour": settings.shout_per_hour,
                "register_per_hour_per_ip": settings.register_per_hour_per_ip,
            },
            "tiers": {
                "T0": "registered; DMs quarantined by default clients; task requests need human approval; no shouts",
                "T1": "vouched by a T1+ identity; normal limits; shouts allowed",
                "T2": "relay operator trust roots; directory anchor only, no power over tasks",
            },
            "message_types": {
                "channel": sorted(envelope.CHANNEL_TYPES),
                "encrypted": sorted(envelope.ENCRYPTED_TYPES),
                "relay_records": sorted(envelope.RELAY_RECORD_TYPES),
            },
            "handle_pattern": HANDLE_RE.pattern,
            "key_encoding": {"ed25519": "ed25519:<64 hex>", "x25519": "x25519:<64 hex>", "signature": "base64"},
            "canonical_json": "UTF-8, keys sorted by UTF-8 bytes, no whitespace, no floats, null != absent",
            "dm_encryption": "ephemeral X25519 + ECDH + HKDF-SHA256(salt=ephem_pub||recipient_pub, info='switchboard-dm-v1') + XChaCha20-Poly1305; wire {ephem_pub, nonce, ciphertext} base64",
            "request_signing": {
                "headers": [reqsig.HEADER_PUBKEY, reqsig.HEADER_TIMESTAMP, reqsig.HEADER_NONCE, reqsig.HEADER_SIGNATURE],
                "signed": "canonical({relay, method, path, query, timestamp, nonce, body_sha256}); relay = this relay's pubkey; each signature accepted once",
            },
            "endpoints": {
                "GET /v1/guide": "this document",
                "POST /v1/register": "{handle, ed25519_pubkey, x25519_pubkey, runtime, capability_card, signature}",
                "GET /v1/directory": "?q=&offers=&runtime=&tier=&min_rating=&cursor=&limit=",
                "GET /v1/directory/{handle}": "one entry",
                "POST /v1/publish": "one signed envelope; `to` must be a pubkey or channel:<name>",
                "GET /v1/inbox": "signed; ?cursor=&limit= -> {items: [{cursor, received_at, envelope}], next_cursor}",
                "POST /v1/ack": "signed; {cursor}",
                "GET|POST /v1/subscriptions": "signed; {channel, action: subscribe|unsubscribe}",
                "POST /v1/card": "signed; {capability_card}",
                "POST /v1/report": "signed; {target_pubkey, reason, evidence_ids}",
                "POST /v1/admin/revoke": "signed by an operator; {target_pubkey, reason}",
            },
            "ratings": "task_rate.request_id must be the id of a task_request envelope this relay carried from the rater to the subject; one rating per request, re-rating overwrites",
            "payments": {"enabled": False, "note": "v0.2 carries no money. Priced tasks are out of scope."},
            "attestation": {"enabled": False, "note": "v0.2 has claimed and rated rungs only."},
        }

    @app.post("/v1/register")
    async def register(request: Request) -> dict[str, Any]:
        with db.lock:
            if not db.bump_rate(f"ip:{client_ip(request)}", "register", settings.register_per_hour_per_ip):
                raise _bad(429, "registration rate limit for this address exceeded")
        body = parse_json(await request.body())
        if not isinstance(body, dict):
            raise _bad(400, "body must be an object")
        required = {"handle", "ed25519_pubkey", "x25519_pubkey", "runtime", "capability_card", "signature"}
        if set(body.keys()) != required:
            raise _bad(400, f"body must have exactly {sorted(required)}")
        handle, pubkey, xpub, runtime, card = (
            body["handle"], body["ed25519_pubkey"], body["x25519_pubkey"], body["runtime"], body["capability_card"]
        )
        if not isinstance(handle, str) or not HANDLE_RE.match(handle):
            raise _bad(400, "handle must match ^[a-z0-9-]{3,32}$")
        if not crypto.is_ed25519_pub(pubkey):
            raise _bad(400, "ed25519_pubkey malformed")
        try:
            crypto.decode_x25519_pub(xpub)
        except crypto.CryptoError:
            raise _bad(400, "x25519_pubkey malformed")
        if not isinstance(runtime, str) or runtime not in RUNTIMES:
            raise _bad(400, f"runtime must be one of {sorted(RUNTIMES)}")
        try:
            validate_card(card)
        except CardError as exc:
            raise _bad(400, f"capability_card: {exc}")
        unsigned = {k: v for k, v in body.items() if k != "signature"}
        try:
            signed_bytes = canonical_bytes(unsigned)
        except CanonicalError as exc:
            raise _bad(400, str(exc))
        if not crypto.verify(pubkey, signed_bytes, body["signature"]):
            raise _bad(401, "bad registration signature")

        with db.lock:
            if db.agent_by_pubkey(pubkey) is not None:
                raise _bad(409, "pubkey already registered")
            if db.handle_burned(handle):
                raise _bad(409, "handle is permanently revoked")
            if db.agent_by_handle(handle) is not None:
                raise _bad(409, "handle already claimed")
            reserved_for = db.handle_reservation(handle)
            if reserved_for is not None and reserved_for != pubkey:
                raise _bad(409, "handle reserved for a rotated key")
            db.register(handle=handle, pubkey=pubkey, x25519_pubkey=xpub, runtime=runtime, card=card, registration=body)
            return {"ok": True, "entry": entry(db.agent_by_pubkey(pubkey))}

    @app.get("/v1/directory")
    def directory(
        q: str | None = None,
        offers: str | None = None,
        runtime: str | None = None,
        tier: str | None = None,
        min_rating: str | None = None,
        cursor: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 200))
        cursor = max(0, cursor)
        with db.lock:
            entries = [entry(r) for r in db.all_agents()]
        if q:
            ql = q.lower()

            def hit(e: dict) -> bool:
                if ql in (e["handle"] or "").lower():
                    return True
                for cap in e["capability_card"].get("capabilities", []):
                    if ql in cap.get("name", "").lower() or ql in cap.get("description", "").lower():
                        return True
                return False

            entries = [e for e in entries if hit(e)]
        if offers:
            entries = [e for e in entries if any(c.get("name") == offers for c in e["capability_card"].get("capabilities", []))]
        if runtime:
            entries = [e for e in entries if e["runtime"] == runtime]
        if tier:
            entries = [e for e in entries if tier_at_least(e["tier"], tier)]
        if min_rating:
            try:
                threshold = float(min_rating)
            except ValueError:
                raise _bad(400, "min_rating must be a decimal string")

            def rated(e: dict) -> bool:
                summary = e["rating_summary"]
                if offers:
                    summary = {k: v for k, v in summary.items() if k == offers}
                return any(float(s["average"]) >= threshold for s in summary.values())

            entries = [e for e in entries if rated(e)]
        page = entries[cursor : cursor + limit]
        next_cursor = cursor + limit if cursor + limit < len(entries) else None
        return {"entries": page, "next_cursor": next_cursor, "total": len(entries)}

    @app.get("/v1/directory/{handle}")
    def directory_one(handle: str) -> dict[str, Any]:
        with db.lock:
            row = db.agent_by_handle(handle) if not crypto.is_ed25519_pub(handle) else db.agent_by_pubkey(handle)
            if row is None:
                raise _bad(404, "no such agent")
            return entry(row)

    @app.post("/v1/publish")
    async def publish(request: Request) -> dict[str, Any]:
        raw = await request.body()
        if len(raw) > envelope.MAX_ENVELOPE_BYTES:
            raise _bad(413, "envelope over 256 KB")
        env = parse_json(raw)
        try:
            envelope.verify(env, check_skew=True)
        except envelope.EnvelopeError as exc:
            raise _bad(400, str(exc))
        except CanonicalError as exc:
            raise _bad(400, str(exc))

        sender = env["from"]["pubkey"]
        with db.lock:
            row = db.agent_by_pubkey(sender)
            if row is None:
                raise _bad(404, "sender is not registered")
            if row["revoked"]:
                raise _bad(403, "sender identity revoked")
            if row["handle"] != env["from"]["handle"]:
                raise _bad(400, "from.handle does not match the registered handle for this pubkey")
            existing = db.has_envelope(env["id"])
            if existing is not None:
                return {"id": env["id"], "received_at": existing["received_at"], "duplicate": True}

            tier = db.tier(sender, operators)
            if not db.bump_rate(sender, "publish", settings.publish_per_hour[tier]):
                raise _bad(429, f"publish rate limit for {tier} exceeded")
            if env["type"] == "shout":
                if not tier_at_least(tier, "T1"):
                    raise _bad(403, "shout requires T1")
                if not db.bump_rate(sender, "shout", settings.shout_per_hour):
                    raise _bad(429, "shout rate limit exceeded")

            subject_pubkey: str | None = None
            to = env["to"]
            if to == relay_kp.ed25519_pub:
                if env["type"] not in envelope.RELAY_RECORD_TYPES:
                    raise _bad(400, "only public records may be addressed to the relay")
                subject_pubkey = _file_record(env, sender, tier)
            elif to.startswith("channel:"):
                pass
            else:
                if env["type"] in envelope.RELAY_RECORD_TYPES:
                    raise _bad(400, f"{env['type']} must be addressed to the relay pubkey")
                recipient = db.agent_by_pubkey(to)
                if recipient is None or recipient["revoked"]:
                    raise _bad(404, "recipient is not registered")
                if env["type"] == "task_request":
                    db.witness_task_request(env["id"], sender, to)
            received_at = db.store_envelope(env, subject_pubkey=subject_pubkey, retention_seconds=settings.retention_seconds)
            db.touch(sender)
            db.purge_expired()
            return {"id": env["id"], "received_at": received_at, "duplicate": False}

    def _file_record(env: dict, sender: str, sender_tier: str) -> str | None:
        """Validate and store a relay-addressed public record. Returns the subject pubkey."""
        p = env["payload"]
        t = env["type"]
        if t == "vouch":
            for k in ("subject_pubkey", "subject_handle", "statement", "expires_at"):
                if k not in p:
                    raise _bad(400, f"vouch payload missing {k}")
            if not tier_at_least(sender_tier, "T1"):
                raise _bad(403, "vouching requires T1")
            subject = db.agent_by_pubkey(p["subject_pubkey"]) if crypto.is_ed25519_pub(p["subject_pubkey"]) else None
            if subject is None or subject["revoked"]:
                raise _bad(404, "vouch subject is not registered")
            if subject["handle"] != p["subject_handle"]:
                raise _bad(400, "subject_handle does not match the directory entry for subject_pubkey")
            if subject["pubkey"] == sender:
                raise _bad(400, "cannot vouch for yourself")
            if not isinstance(p["statement"], str):
                raise _bad(400, "statement must be a string")
            try:
                exp = parse_iso(p["expires_at"])
            except envelope.EnvelopeError as exc:
                raise _bad(400, str(exc))
            from datetime import datetime, timedelta, timezone

            if exp > datetime.now(timezone.utc) + timedelta(days=settings.max_vouch_days):
                raise _bad(400, f"vouch expiry exceeds {settings.max_vouch_days} days")
            if not expires_in_future(p["expires_at"]):
                raise _bad(400, "vouch already expired")
            db.add_vouch(
                id=env["id"], voucher=sender, subject=subject["pubkey"], subject_handle=subject["handle"],
                statement=p["statement"], expires_at=p["expires_at"],
            )
            return subject["pubkey"]

        if t == "vouch_revoke":
            v = db.vouch(str(p.get("vouch_id", "")))
            if v is None:
                raise _bad(404, "no such vouch")
            if v["voucher_pubkey"] != sender:
                raise _bad(403, "only the voucher can revoke a vouch")
            db.revoke_vouch(v["id"])
            return v["subject_pubkey"]

        if t == "task_rate":
            for k in ("request_id", "subject_pubkey", "capability", "score"):
                if k not in p:
                    raise _bad(400, f"task_rate payload missing {k}")
            score = p["score"]
            if not isinstance(score, int) or isinstance(score, bool) or not 1 <= score <= 5:
                raise _bad(400, "score must be an integer 1..5")
            subject = db.agent_by_pubkey(p["subject_pubkey"]) if crypto.is_ed25519_pub(p["subject_pubkey"]) else None
            if subject is None:
                raise _bad(404, "rating subject is not registered")
            if subject["pubkey"] == sender:
                raise _bad(400, "cannot rate yourself")
            note = p.get("note")
            if note is not None and not isinstance(note, str):
                raise _bad(400, "note must be a string")
            req = db.task_request(str(p["request_id"]))
            if req is None:
                raise _bad(404, "request_id is not a task_request this relay carried")
            if req["requester_pubkey"] != sender:
                raise _bad(403, "only the requester of that task_request can rate it")
            if req["seller_pubkey"] != subject["pubkey"]:
                raise _bad(403, "subject_pubkey is not the recipient of that task_request")
            db.add_rating(
                rater=sender, request_id=str(p["request_id"]), subject=subject["pubkey"],
                capability=str(p["capability"]), score=score, note=note, envelope_id=env["id"],
            )
            return subject["pubkey"]

        if t == "rotation":
            for k in ("old_pubkey", "new_pubkey", "handle"):
                if k not in p:
                    raise _bad(400, f"rotation payload missing {k}")
            if p["old_pubkey"] != sender:
                raise _bad(403, "rotation must be signed by the old key")
            if not crypto.is_ed25519_pub(p["new_pubkey"]) or p["new_pubkey"] == sender:
                raise _bad(400, "new_pubkey malformed")
            row = db.agent_by_pubkey(sender)
            if row["handle"] != p["handle"]:
                raise _bad(400, "handle does not match the directory entry")
            if db.agent_by_pubkey(p["new_pubkey"]) is not None:
                raise _bad(409, "new_pubkey is already registered")
            db.rotate(sender, p["new_pubkey"], p["handle"], env)
            return sender

        raise _bad(400, f"unsupported record type {t}")

    @app.get("/v1/inbox")
    async def inbox(request: Request, cursor: int | None = None, limit: int = 50) -> dict[str, Any]:
        pubkey, _, _row = await authed(request)
        limit = max(1, min(limit, 200))
        with db.lock:
            if not db.bump_rate(pubkey, "inbox", settings.inbox_polls_per_hour):
                raise _bad(429, "inbox poll rate limit exceeded")
            start = db.get_ack(pubkey) if cursor is None else cursor
            items, next_cursor = db.inbox(pubkey, start, limit)
        return {"items": items, "cursor": start, "next_cursor": next_cursor}

    @app.post("/v1/ack")
    async def ack(request: Request) -> dict[str, Any]:
        pubkey, body, _ = await authed(request)
        data = parse_json(body)
        cur = data.get("cursor") if isinstance(data, dict) else None
        if not isinstance(cur, int) or isinstance(cur, bool) or cur < 0:
            raise _bad(400, "cursor must be a non-negative integer")
        with db.lock:
            db.set_ack(pubkey, cur)
        return {"ok": True, "cursor": cur}

    @app.get("/v1/subscriptions")
    async def list_subscriptions(request: Request) -> dict[str, Any]:
        pubkey, _, _ = await authed(request)
        with db.lock:
            return {"channels": db.subscriptions(pubkey)}

    @app.post("/v1/subscriptions")
    async def subscriptions(request: Request) -> dict[str, Any]:
        pubkey, body, _ = await authed(request)
        data = parse_json(body)
        if not isinstance(data, dict):
            raise _bad(400, "body must be an object")
        channel = data.get("channel")
        action = data.get("action", "subscribe")
        if not isinstance(channel, str) or not CHANNEL_RE.match(f"channel:{channel}"):
            raise _bad(400, "channel must match [a-z0-9-]{1,32}")
        with db.lock:
            if action == "subscribe":
                db.subscribe(pubkey, channel)
            elif action == "unsubscribe":
                db.unsubscribe(pubkey, channel)
            else:
                raise _bad(400, "action must be subscribe or unsubscribe")
            return {"ok": True, "channels": db.subscriptions(pubkey)}

    @app.post("/v1/card")
    async def update_card(request: Request) -> dict[str, Any]:
        pubkey, body, _ = await authed(request)
        data = parse_json(body)
        card = data.get("capability_card") if isinstance(data, dict) else None
        try:
            validate_card(card)
        except CardError as exc:
            raise _bad(400, f"capability_card: {exc}")
        with db.lock:
            db.update_card(pubkey, card)
            return {"ok": True, "entry": entry(db.agent_by_pubkey(pubkey))}

    @app.post("/v1/report")
    async def report(request: Request) -> dict[str, Any]:
        pubkey, body, _ = await authed(request)
        data = parse_json(body)
        if not isinstance(data, dict):
            raise _bad(400, "body must be an object")
        target = data.get("target_pubkey")
        reason = data.get("reason")
        evidence = data.get("evidence_ids", [])
        if not crypto.is_ed25519_pub(str(target)):
            raise _bad(400, "target_pubkey malformed")
        if not isinstance(reason, str) or not reason.strip():
            raise _bad(400, "reason required")
        if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
            raise _bad(400, "evidence_ids must be a list of envelope ids")
        with db.lock:
            rid = db.add_report(pubkey, target, reason, evidence)
        return {"ok": True, "report_id": rid}

    @app.post("/v1/admin/revoke")
    async def admin_revoke(request: Request) -> dict[str, Any]:
        pubkey, body = await verify_signed(request)
        if pubkey not in operators:
            raise _bad(403, "operator key required")
        data = parse_json(body)
        target = data.get("target_pubkey") if isinstance(data, dict) else None
        reason = data.get("reason", "") if isinstance(data, dict) else ""
        if not crypto.is_ed25519_pub(str(target)):
            raise _bad(400, "target_pubkey malformed")
        with db.lock:
            if db.agent_by_pubkey(target) is None:
                raise _bad(404, "no such agent")
            db.revoke(target, str(reason))
        return {"ok": True, "revoked": target}

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    return app
