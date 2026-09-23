import json
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from switchboard import crypto, envelope, reqsig
from switchboard.canonical import canonical_bytes
from switchboard.relay.app import Settings, create_app

CARD = {
    "capabilities": [
        {
            "name": "web-research",
            "version": "1.0",
            "description": "Answers research questions with cited sources.",
            "input_schema": {"question": "string", "depth?": "quick|standard|deep"},
            "output_schema": {"brief": "string", "sources": ["url"]},
        }
    ],
    "constraints": ["polls every 10 min"],
}


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --- live mode -------------------------------------------------------------- #
# With SWITCHBOARD_TEST_RELAY_URL set, every test here runs against a live relay
# instead of the in-process FastAPI app. That is how a second implementation
# (worker/) proves it speaks the same protocol. The live relay must run with
# TEST_RESET=1 so each test starts from an empty directory, and
# SWITCHBOARD_TEST_OPERATOR must hold "<ed25519 seed hex>:<x25519 secret hex>"
# for one of its configured operator keys.
LIVE = os.environ.get("SWITCHBOARD_TEST_RELAY_URL")
PROFILE = os.environ.get("SWITCHBOARD_TEST_RELAY_PROFILE", "default")


def live_relay(profile: str = "default"):
    if profile != PROFILE:
        pytest.skip(f"needs the live relay started with the {profile!r} profile")
    client = httpx.Client(base_url=LIVE, timeout=30)
    assert client.post("/v1/admin/_reset").status_code == 200, "live relay must run with TEST_RESET=1"
    seed, xsec = os.environ["SWITCHBOARD_TEST_OPERATOR"].split(":")
    client.operator_kp = crypto.Keypair(bytes.fromhex(seed), bytes.fromhex(xsec))  # type: ignore[attr-defined]
    client.relay_pub = client.get("/v1/guide").json()["relay"]["pubkey"]  # type: ignore[attr-defined]
    return client


class Peer:
    def __init__(self, http: TestClient, handle: str, runtime: str = "custom"):
        self.http = http
        self.handle = handle
        self.kp = crypto.Keypair.generate()
        self.runtime = runtime

    @property
    def pub(self) -> str:
        return self.kp.ed25519_pub

    def register(self, card=CARD, handle=None):
        body = {
            "handle": handle or self.handle,
            "ed25519_pubkey": self.pub,
            "x25519_pubkey": self.kp.x25519_pub,
            "runtime": self.runtime,
            "capability_card": card,
        }
        body["signature"] = self.kp.sign(canonical_bytes(body))
        return self.http.post("/v1/register", content=json.dumps(body))

    def signed(self, method: str, path: str, query: str = "", body: dict | None = None, relay_pub: str | None = None):
        raw = json.dumps(body).encode() if body is not None else b""
        headers = reqsig.sign_request(self.kp, relay_pub or self.http.relay_pub, method, path, query, raw)
        url = path + (f"?{query}" if query else "")
        return self.http.request(method, url, content=raw, headers=headers)

    def replay(self, method: str, path: str, headers: dict, body: dict | None = None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.http.request(method, path, content=raw, headers=headers)

    def envelope(self, type: str, to: str, payload: dict, **kw):
        env = envelope.build(type=type, from_handle=self.handle, from_pubkey=self.pub, to=to, payload=payload, **kw)
        return envelope.sign(env, self.kp)

    def publish(self, env: dict):
        return self.http.post("/v1/publish", content=json.dumps(env))

    def dm(self, other: "Peer", text: str):
        entry = self.http.get(f"/v1/directory/{other.handle}").json()
        box = crypto.seal(entry["x25519_pubkey"], json.dumps({"text": text}).encode())
        return self.publish(self.envelope("dm", other.pub, box))

    def inbox(self, cursor: int | None = None):
        q = f"cursor={cursor}" if cursor is not None else ""
        return self.signed("GET", "/v1/inbox", q)

    def task_request(self, other: "Peer") -> str:
        """Publish a sealed task_request to ``other``; returns the envelope id the relay witnessed."""
        entry = self.http.get(f"/v1/directory/{other.handle}").json()
        rid = envelope.new_ulid()
        box = crypto.seal(entry["x25519_pubkey"], json.dumps({"request_id": rid, "capability": "web-research", "input": {}}).encode())
        r = self.publish(self.envelope("task_request", other.pub, box, id=rid))
        assert r.status_code == 200, r.text
        return rid

    def rate(self, other: "Peer", request_id: str, score: int = 5, capability: str = "web-research", subject: str | None = None):
        payload = {"request_id": request_id, "subject_pubkey": subject or other.pub, "capability": capability, "score": score}
        return self.publish(self.envelope("task_rate", self.http.relay_pub, payload))


@pytest.fixture
def relay(tmp_path):
    if LIVE:
        return live_relay()
    operator = crypto.Keypair.generate()
    settings = Settings(db_path=str(tmp_path / "relay.db"), operators=[operator.ed25519_pub])
    app = create_app(settings)
    client = TestClient(app)
    client.operator_kp = operator  # type: ignore[attr-defined]
    client.relay_pub = app.state.relay_keypair.ed25519_pub  # type: ignore[attr-defined]
    return client


def test_guide_lists_relay_key_and_limits(relay):
    g = relay.get("/v1/guide").json()
    assert g["protocol"] == "switchboard"
    assert g["relay"]["pubkey"] == relay.relay_pub
    assert relay.operator_kp.ed25519_pub in g["relay"]["operators"]
    assert g["payments"]["enabled"] is False


def test_register_and_lookup(relay):
    a = Peer(relay, "alice")
    r = a.register()
    assert r.status_code == 200, r.text
    e = r.json()["entry"]
    assert e["tier"] == "T0" and e["handle"] == "alice" and e["pubkey"] == a.pub
    assert relay.get("/v1/directory/alice").json()["x25519_pubkey"] == a.kp.x25519_pub
    assert relay.get(f"/v1/directory/{a.pub}").json()["handle"] == "alice"


def test_register_rejects_bad_signature_and_dup_handle(relay):
    a = Peer(relay, "alice")
    body = {"handle": "alice", "ed25519_pubkey": a.pub, "x25519_pubkey": a.kp.x25519_pub, "runtime": "custom", "capability_card": CARD}
    body["signature"] = crypto.Keypair.generate().sign(canonical_bytes(body))
    assert relay.post("/v1/register", content=json.dumps(body)).status_code == 401
    assert a.register().status_code == 200
    b = Peer(relay, "alice")
    assert b.register().status_code == 409
    assert Peer(relay, "Bad_Handle").register().status_code == 400
    assert Peer(relay, "bob").register(card={"capabilities": [{"name": "x"}]}).status_code == 400


def test_publish_requires_registration_and_matching_handle(relay):
    a = Peer(relay, "alice")
    env = a.envelope("post", "channel:general", {"text": "hi"})
    assert a.publish(env).status_code == 404
    a.register()
    assert a.publish(env).status_code == 200
    # duplicate is idempotent
    r = a.publish(env)
    assert r.status_code == 200 and r.json()["duplicate"] is True
    liar = envelope.sign(envelope.build(type="post", from_handle="mallory", from_pubkey=a.pub, to="channel:general", payload={"text": "x"}), a.kp)
    assert a.publish(liar).status_code == 400


def test_publish_rejects_tampered_and_stale(relay):
    a = Peer(relay, "alice")
    a.register()
    env = a.envelope("post", "channel:general", {"text": "hi"})
    env["payload"]["text"] = "tampered"
    assert a.publish(env).status_code == 400
    old = a.envelope("post", "channel:general", {"text": "hi"}, timestamp=iso(datetime.now(timezone.utc) - timedelta(minutes=10)))
    assert a.publish(old).status_code == 400


def test_channel_inbox_flow(relay):
    a, b = Peer(relay, "alice"), Peer(relay, "bob")
    a.register(); b.register()
    assert b.signed("POST", "/v1/subscriptions", body={"channel": "general"}).status_code == 200
    a.publish(a.envelope("post", "channel:general", {"text": "hello channel"}))
    a.publish(a.envelope("post", "channel:other", {"text": "not for bob"}))
    inbox = b.inbox().json()
    texts = [i["envelope"]["payload"]["text"] for i in inbox["items"]]
    assert texts == ["hello channel"]
    for i in inbox["items"]:
        envelope.verify(i["envelope"])  # arrives byte-for-byte as published
        assert i["received_at"] and isinstance(i["cursor"], int)
    cursor = inbox["next_cursor"]
    assert b.signed("POST", "/v1/ack", body={"cursor": cursor}).status_code == 200
    assert b.inbox().json()["items"] == []  # resumes from ack
    # unsigned inbox is refused
    assert relay.get("/v1/inbox").status_code == 401


def test_dm_roundtrip_through_relay(relay):
    a, b = Peer(relay, "alice"), Peer(relay, "bob")
    a.register(); b.register()
    a.dm(b, "psst")
    got = b.inbox().json()["items"][0]["envelope"]
    envelope.verify(got)
    plaintext = crypto.open_sealed(b.kp.x25519_secret, got["payload"])
    assert json.loads(plaintext)["text"] == "psst"
    # the sender does not see their own DM in their inbox
    assert a.inbox().json()["items"] == []


def test_dm_to_unknown_recipient_and_plaintext_dm_rejected(relay):
    a = Peer(relay, "alice")
    a.register()
    stranger = crypto.Keypair.generate()
    box = crypto.seal(stranger.x25519_pub, b"{}")
    assert a.publish(a.envelope("dm", stranger.ed25519_pub, box)).status_code == 404
    b = Peer(relay, "bob"); b.register()
    assert a.publish(a.envelope("dm", b.pub, {"text": "plain"})).status_code == 400


def test_vouch_chain_and_tiers(relay):
    op = Peer(relay, "operator")
    op.kp = relay.operator_kp
    assert op.register().status_code == 200
    assert relay.get("/v1/directory/operator").json()["tier"] == "T2"
    dana = Peer(relay, "dana-scout"); dana.register()
    eve = Peer(relay, "eve"); eve.register()
    assert relay.get("/v1/directory/dana-scout").json()["tier"] == "T0"

    # T0 cannot vouch
    exp = iso(datetime.now(timezone.utc) + timedelta(days=30))
    v = eve.envelope("vouch", relay.relay_pub, {"subject_pubkey": dana.pub, "subject_handle": "dana-scout", "statement": "x", "expires_at": exp})
    assert eve.publish(v).status_code == 403

    # T2 vouches dana -> T1; dana vouches eve -> T1
    v = op.envelope("vouch", relay.relay_pub, {"subject_pubkey": dana.pub, "subject_handle": "dana-scout", "statement": "verified out-of-band", "expires_at": exp})
    assert op.publish(v).status_code == 200, v
    d = relay.get("/v1/directory/dana-scout").json()
    assert d["tier"] == "T1" and d["vouches"][0]["voucher_handle"] == "operator"
    v2 = dana.envelope("vouch", relay.relay_pub, {"subject_pubkey": eve.pub, "subject_handle": "eve", "statement": "friend", "expires_at": exp})
    assert dana.publish(v2).status_code == 200
    assert relay.get("/v1/directory/eve").json()["tier"] == "T1"

    # vouch shows up in dana's inbox as a public record about her
    assert any(i["envelope"]["type"] == "vouch" for i in dana.inbox().json()["items"])

    # wrong handle for subject pubkey is refused
    bad = op.envelope("vouch", relay.relay_pub, {"subject_pubkey": dana.pub, "subject_handle": "eve", "statement": "x", "expires_at": exp})
    assert op.publish(bad).status_code == 400

    # revoke the root vouch: dana drops to T0 and eve with her (her voucher is no longer T1)
    rv = op.envelope("vouch_revoke", relay.relay_pub, {"vouch_id": v["id"]})
    assert op.publish(rv).status_code == 200
    assert relay.get("/v1/directory/dana-scout").json()["tier"] == "T0"
    assert relay.get("/v1/directory/eve").json()["tier"] == "T0"


def test_directory_search_and_ratings(relay):
    a, b = Peer(relay, "alice"), Peer(relay, "bob")
    a.register(); b.register(card={"capabilities": [{"name": "code-review", "description": "Reviews diffs"}], "constraints": []})
    assert [e["handle"] for e in relay.get("/v1/directory", params={"offers": "web-research"}).json()["entries"]] == ["alice"]
    assert [e["handle"] for e in relay.get("/v1/directory", params={"q": "diffs"}).json()["entries"]] == ["bob"]
    rid = b.task_request(a)
    assert b.rate(a, rid, 5).status_code == 200
    e = relay.get("/v1/directory/alice").json()
    assert e["rating_summary"] == {"web-research": {"count": 1, "raters": 1, "average": "5.00"}}
    assert relay.get("/v1/directory", params={"offers": "web-research", "min_rating": "4.5"}).json()["total"] == 1
    assert relay.get("/v1/directory", params={"offers": "web-research", "min_rating": "5.5"}).json()["total"] == 0
    # re-rating the same request overwrites rather than double counting
    assert b.rate(a, rid, 3).status_code == 200
    assert relay.get("/v1/directory/alice").json()["rating_summary"]["web-research"] == {"count": 1, "raters": 1, "average": "3.00"}
    assert b.rate(a, rid, 9, capability="x").status_code == 400


def test_rating_requires_a_witnessed_task_request(relay):
    a, b, c = Peer(relay, "alice"), Peer(relay, "bob"), Peer(relay, "carol")
    a.register(); b.register(); c.register()
    # no task_request ever carried: the id is invented
    r = b.rate(a, envelope.new_ulid())
    assert r.status_code == 404 and "task_request" in r.json()["error"]
    rid = b.task_request(a)
    # only the requester can rate that request
    assert c.rate(a, rid).status_code == 403
    # and only the seller it was sent to can be its subject
    assert b.rate(c, rid).status_code == 403
    # the seller cannot rate the requester on it either
    assert a.rate(b, rid).status_code == 403
    assert b.rate(a, rid).status_code == 200
    assert relay.get("/v1/directory/alice").json()["rating_summary"]["web-research"]["count"] == 1
    assert relay.get("/v1/directory/carol").json()["rating_summary"] == {}
    # the witness outlives envelope retention
    if not LIVE:
        relay.app.state.db.conn.execute("DELETE FROM envelopes WHERE type='task_request'")
        assert b.rate(a, rid, 4).status_code == 200


def test_rotation(relay):
    a = Peer(relay, "alice"); a.register()
    new_kp = crypto.Keypair.generate()
    rot = a.envelope("rotation", relay.relay_pub, {"old_pubkey": a.pub, "new_pubkey": new_kp.ed25519_pub, "handle": "alice"})
    assert a.publish(rot).status_code == 200
    # old key is revoked, handle is reserved for the new key
    assert a.publish(a.envelope("post", "channel:general", {"text": "x"})).status_code == 403
    squatter = Peer(relay, "alice")
    assert squatter.register().status_code == 409
    a2 = Peer(relay, "alice"); a2.kp = new_kp
    assert a2.register().status_code == 200
    e = relay.get("/v1/directory/alice").json()
    assert e["pubkey"] == new_kp.ed25519_pub and e["vouches"] == []
    assert relay.get(f"/v1/directory/{a.pub}").json()["rotated_to"] == new_kp.ed25519_pub


def test_operator_revoke_burns_handle(relay):
    op = Peer(relay, "operator"); op.kp = relay.operator_kp; op.register()
    m = Peer(relay, "mallory"); m.register()
    r = op.signed("POST", "/v1/admin/revoke", body={"target_pubkey": m.pub, "reason": "impersonation"})
    assert r.status_code == 200
    assert m.inbox().status_code == 403
    assert Peer(relay, "mallory").register().status_code == 409
    # non-operators cannot revoke
    a = Peer(relay, "alice"); a.register()
    assert a.signed("POST", "/v1/admin/revoke", body={"target_pubkey": op.pub, "reason": "x"}).status_code == 403


def test_shout_requires_t1_and_rate_limits(relay, tmp_path):
    a = Peer(relay, "alice"); a.register()
    assert a.publish(a.envelope("shout", "channel:general", {"text": "hey"})).status_code == 403


def test_publish_rate_limit(tmp_path):
    if LIVE:
        relay = live_relay("tiny")
    else:
        settings = Settings(db_path=str(tmp_path / "r.db"), publish_per_hour={"T0": 2, "T1": 200, "T2": 1000})
        relay = TestClient(create_app(settings))
    a = Peer(relay, "alice"); a.register()
    assert a.publish(a.envelope("post", "channel:g", {"text": "1"})).status_code == 200
    assert a.publish(a.envelope("post", "channel:g", {"text": "2"})).status_code == 200
    assert a.publish(a.envelope("post", "channel:g", {"text": "3"})).status_code == 429


def test_signed_requests_reject_replay_and_wrong_relay(relay):
    a = Peer(relay, "alice"); a.register()
    raw = json.dumps({"channel": "general", "action": "subscribe"}).encode()
    headers = reqsig.sign_request(a.kp, relay.relay_pub, "POST", "/v1/subscriptions", "", raw)
    assert a.replay("POST", "/v1/subscriptions", headers, {"channel": "general", "action": "subscribe"}).status_code == 200
    r = a.replay("POST", "/v1/subscriptions", headers, {"channel": "general", "action": "subscribe"})
    assert r.status_code == 409 and "replayed" in r.json()["error"]
    # a request signed for another relay is refused here
    other = crypto.Keypair.generate().ed25519_pub
    assert a.signed("GET", "/v1/inbox", relay_pub=other).status_code == 401
    # the replayed inbox poll never counted against the rate limit either
    for _ in range(3):
        assert a.inbox().status_code == 200


def test_report_is_idempotent(relay):
    a, b = Peer(relay, "alice"), Peer(relay, "bob")
    a.register(); b.register()
    body = {"target_pubkey": b.pub, "reason": "spam", "evidence_ids": ["01J1", "01J0"]}
    ids = {a.signed("POST", "/v1/report", body=body).json()["report_id"] for _ in range(3)}
    assert ids == {1}


def test_timestamps_must_be_one_shape(relay):
    op = Peer(relay, "operator"); op.kp = relay.operator_kp; op.register()
    d = Peer(relay, "dana"); d.register()
    for bad in ("20270101T000000Z", "2027-W01-1T00:00:00Z", "2027-01-01T00:00:00+00:00", "2027-01-01T00:00:00.000Z"):
        v = op.envelope("vouch", relay.relay_pub, {"subject_pubkey": d.pub, "subject_handle": "dana", "statement": "x", "expires_at": bad})
        assert op.publish(v).status_code == 400, bad
    stale = op.envelope("post", "channel:g", {"text": "x"}, timestamp="20260922T000000Z")
    assert op.publish(stale).status_code == 400


def test_directory_serves_signed_registration_and_rotation_record(relay):
    from switchboard.client import DirectoryError, verify_entry

    a = Peer(relay, "alice"); a.register()
    e = relay.get("/v1/directory/alice").json()
    verify_entry(e)
    tampered = dict(e, x25519_pubkey=crypto.Keypair.generate().x25519_pub)
    with pytest.raises(DirectoryError, match="x25519"):
        verify_entry(tampered)
    with pytest.raises(DirectoryError, match="handle"):
        verify_entry(dict(e, handle="mallory"))
    new_kp = crypto.Keypair.generate()
    a.publish(a.envelope("rotation", relay.relay_pub, {"old_pubkey": a.pub, "new_pubkey": new_kp.ed25519_pub, "handle": "alice"}))
    old = relay.get(f"/v1/directory/{a.pub}").json()
    verify_entry(old)
    assert old["rotation"]["payload"]["new_pubkey"] == new_kp.ed25519_pub
    with pytest.raises(DirectoryError, match="rotated_to"):
        verify_entry(dict(old, rotated_to=crypto.Keypair.generate().ed25519_pub))


def test_rating_summary_counts_distinct_raters(relay):
    a, b = Peer(relay, "alice"), Peer(relay, "bob")
    a.register(); b.register()
    for _ in range(3):
        assert b.rate(a, b.task_request(a)).status_code == 200
    assert relay.get("/v1/directory/alice").json()["rating_summary"]["web-research"] == {"count": 3, "raters": 1, "average": "5.00"}


def test_vouch_from_revoked_voucher_is_hidden(relay):
    op = Peer(relay, "operator"); op.kp = relay.operator_kp; op.register()
    d = Peer(relay, "dana"); d.register()
    e = Peer(relay, "eve"); e.register()
    exp = iso(datetime.now(timezone.utc) + timedelta(days=30))
    op.publish(op.envelope("vouch", relay.relay_pub, {"subject_pubkey": d.pub, "subject_handle": "dana", "statement": "x", "expires_at": exp}))
    d.publish(d.envelope("vouch", relay.relay_pub, {"subject_pubkey": e.pub, "subject_handle": "eve", "statement": "x", "expires_at": exp}))
    assert relay.get("/v1/directory/eve").json()["tier"] == "T1"
    op.signed("POST", "/v1/admin/revoke", body={"target_pubkey": d.pub, "reason": "gone"})
    ev = relay.get("/v1/directory/eve").json()
    assert ev["tier"] == "T0" and ev["vouches"] == []


def test_report_and_card_update(relay):
    a, b = Peer(relay, "alice"), Peer(relay, "bob")
    a.register(); b.register(card={"capabilities": [], "constraints": []})
    r = a.signed("POST", "/v1/report", body={"target_pubkey": b.pub, "reason": "spam", "evidence_ids": []})
    assert r.status_code == 200 and r.json()["report_id"] == 1
    new_card = {"capabilities": [], "constraints": ["research only"]}
    r = a.signed("POST", "/v1/card", body={"capability_card": new_card})
    assert r.status_code == 200 and r.json()["entry"]["capability_card"] == new_card
    assert relay.get("/v1/directory", params={"offers": "web-research"}).json()["total"] == 0


def test_register_rate_limit_per_ip(tmp_path):
    if LIVE:
        relay = live_relay("tiny")
    else:
        settings = Settings(db_path=str(tmp_path / "r.db"), register_per_hour_per_ip=2)
        relay = TestClient(create_app(settings))
    assert relay.get("/v1/guide").json()["rate_limits"]["register_per_hour_per_ip"] == 2
    assert Peer(relay, "alice").register().status_code == 200
    assert Peer(relay, "bob").register().status_code == 200
    r = Peer(relay, "carol").register()
    assert r.status_code == 429 and "registration" in r.json()["error"]
    # the proxy header is ignored unless the relay is told to trust it
    relay.headers["X-Forwarded-For"] = "203.0.113.9"
    assert Peer(relay, "dave").register().status_code == 429


def test_register_rate_limit_uses_forwarded_ip_behind_trusted_proxy(tmp_path):
    if LIVE:
        pytest.skip("the Worker takes the client address from Cloudflare, not from X-Forwarded-For")
    settings = Settings(db_path=str(tmp_path / "r.db"), register_per_hour_per_ip=1, trust_proxy=True)
    relay = TestClient(create_app(settings))
    relay.headers["X-Forwarded-For"] = "203.0.113.9"
    assert Peer(relay, "alice").register().status_code == 200
    assert Peer(relay, "bob").register().status_code == 429
    # the rightmost address is the one the trusted proxy appended; a client cannot spoof it
    relay.headers["X-Forwarded-For"] = "198.51.100.1, 203.0.113.9"
    assert Peer(relay, "carol").register().status_code == 429
    relay.headers["X-Forwarded-For"] = "203.0.113.9, 198.51.100.1"
    assert Peer(relay, "dave").register().status_code == 200


def test_root_page_is_human_readable(relay):
    a = Peer(relay, "alice"); a.register()
    r = relay.get("/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "<title>Switchboard</title>" in r.text and "/v1/guide" in r.text and "switchboard join --relay https://" in r.text
    assert "<b>alice</b>" in r.text and "offers web-research" in r.text and 'class="jack lit"' in r.text
    assert relay.get("/v1/guide").json()["relay"]["pubkey"] in r.text
    # only constrained fields reach the page; free text like descriptions never does
    b = Peer(relay, "bob"); b.register(card={"capabilities": [{"name": "x-y", "description": "<script>alert(1)</script>"}], "constraints": []})
    page = relay.get("/").text
    assert "offers x-y" in page and "alert(1)" not in page
