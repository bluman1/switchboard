"""SQLite storage for the relay. One connection, one lock, autocommit."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .. import crypto
from ..envelope import now_iso, parse_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS agents (
  pubkey          TEXT PRIMARY KEY,
  handle          TEXT UNIQUE,
  former_handle   TEXT,
  x25519_pubkey   TEXT NOT NULL,
  runtime         TEXT NOT NULL,
  capability_card TEXT NOT NULL,
  registration    TEXT NOT NULL,
  registered_at   TEXT NOT NULL,
  last_seen       TEXT NOT NULL,
  revoked         INTEGER NOT NULL DEFAULT 0,
  revoked_reason  TEXT,
  rotated_to      TEXT,
  rotation        TEXT
);

CREATE TABLE IF NOT EXISTS handle_reservations (
  handle TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  reserved_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS burned_handles (
  handle TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  reason TEXT,
  burned_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS envelopes (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  id             TEXT UNIQUE NOT NULL,
  type           TEXT NOT NULL,
  from_pubkey    TEXT NOT NULL,
  to_target      TEXT NOT NULL,
  subject_pubkey TEXT,
  received_at    TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  body           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS envelopes_to ON envelopes (to_target, seq);
CREATE INDEX IF NOT EXISTS envelopes_subject ON envelopes (subject_pubkey, seq);

CREATE TABLE IF NOT EXISTS subscriptions (
  pubkey  TEXT NOT NULL,
  channel TEXT NOT NULL,
  PRIMARY KEY (pubkey, channel)
);

CREATE TABLE IF NOT EXISTS acks (
  pubkey   TEXT PRIMARY KEY,
  cursor   INTEGER NOT NULL,
  acked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vouches (
  id             TEXT PRIMARY KEY,
  voucher_pubkey TEXT NOT NULL,
  subject_pubkey TEXT NOT NULL,
  subject_handle TEXT NOT NULL,
  statement      TEXT NOT NULL,
  issued_at      TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  revoked        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS vouches_subject ON vouches (subject_pubkey);

CREATE TABLE IF NOT EXISTS ratings (
  rater_pubkey   TEXT NOT NULL,
  request_id     TEXT NOT NULL,
  subject_pubkey TEXT NOT NULL,
  capability     TEXT NOT NULL,
  score          INTEGER NOT NULL,
  note           TEXT,
  envelope_id    TEXT NOT NULL,
  rated_at       TEXT NOT NULL,
  PRIMARY KEY (rater_pubkey, request_id)
);
CREATE INDEX IF NOT EXISTS ratings_subject ON ratings (subject_pubkey, capability);

-- Every task_request the relay carried, kept past envelope retention so a
-- rating can be checked against a request that really happened.
CREATE TABLE IF NOT EXISTS task_requests (
  id              TEXT PRIMARY KEY,
  requester_pubkey TEXT NOT NULL,
  seller_pubkey   TEXT NOT NULL,
  received_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_pubkey TEXT NOT NULL,
  target_pubkey   TEXT NOT NULL,
  reason          TEXT NOT NULL,
  evidence_ids    TEXT NOT NULL,
  filed_at        TEXT NOT NULL,
  UNIQUE (reporter_pubkey, target_pubkey, reason, evidence_ids)
);

CREATE TABLE IF NOT EXISTS seen_signatures (
  signature  TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_counters (
  pubkey TEXT NOT NULL,
  bucket TEXT NOT NULL,
  window INTEGER NOT NULL,
  count  INTEGER NOT NULL,
  PRIMARY KEY (pubkey, bucket, window)
);
"""

from ..tiers import TIER_ORDER, tier_at_least  # noqa: E402,F401  (re-exported for callers)


class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)

    # ---- meta ------------------------------------------------------------ #

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def relay_keypair(self) -> crypto.Keypair:
        seed = self.get_meta("relay_ed25519_seed")
        xsec = self.get_meta("relay_x25519_secret")
        if seed is None or xsec is None:
            kp = crypto.Keypair.generate()
            self.set_meta("relay_ed25519_seed", kp.ed25519_seed.hex())
            self.set_meta("relay_x25519_secret", kp.x25519_secret.hex())
            return kp
        return crypto.Keypair(bytes.fromhex(seed), bytes.fromhex(xsec))

    # ---- agents ---------------------------------------------------------- #

    def agent_by_pubkey(self, pubkey: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM agents WHERE pubkey=?", (pubkey,)).fetchone()

    def agent_by_handle(self, handle: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM agents WHERE handle=?", (handle,)).fetchone()

    def all_agents(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM agents WHERE revoked=0 ORDER BY registered_at").fetchall()

    def handle_reservation(self, handle: str) -> str | None:
        row = self.conn.execute("SELECT pubkey FROM handle_reservations WHERE handle=?", (handle,)).fetchone()
        return row["pubkey"] if row else None

    def handle_burned(self, handle: str) -> bool:
        return self.conn.execute("SELECT 1 FROM burned_handles WHERE handle=?", (handle,)).fetchone() is not None

    def register(self, *, handle: str, pubkey: str, x25519_pubkey: str, runtime: str, card: dict, registration: dict) -> None:
        """``registration`` is the full signed registration body; it is served
        back to clients so they can verify the handle/key binding themselves."""
        now = now_iso()
        self.conn.execute(
            "INSERT INTO agents (pubkey, handle, x25519_pubkey, runtime, capability_card, registration, registered_at, last_seen)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (pubkey, handle, x25519_pubkey, runtime, json.dumps(card), json.dumps(registration), now, now),
        )
        self.conn.execute("DELETE FROM handle_reservations WHERE handle=?", (handle,))

    # ---- request replay protection --------------------------------------- #

    def remember_signature(self, signature: str, ttl_seconds: int) -> bool:
        """Return False if this signature was already accepted inside its window."""
        now = datetime.now(timezone.utc)
        now_s = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.conn.execute("DELETE FROM seen_signatures WHERE expires_at <= ?", (now_s,))
        if self.conn.execute("SELECT 1 FROM seen_signatures WHERE signature=?", (signature,)).fetchone():
            return False
        exp = (now + timedelta(seconds=ttl_seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.conn.execute("INSERT INTO seen_signatures (signature, expires_at) VALUES (?, ?)", (signature, exp))
        return True

    def touch(self, pubkey: str) -> None:
        self.conn.execute("UPDATE agents SET last_seen=? WHERE pubkey=?", (now_iso(), pubkey))

    def update_card(self, pubkey: str, card: dict) -> None:
        self.conn.execute("UPDATE agents SET capability_card=? WHERE pubkey=?", (json.dumps(card), pubkey))

    def rotate(self, old_pubkey: str, new_pubkey: str, handle: str, record: dict) -> None:
        """``record`` is the signed rotation envelope; it is served on the old
        entry so clients can verify ``rotated_to`` themselves."""
        self.conn.execute(
            "UPDATE agents SET handle=NULL, former_handle=?, revoked=1, revoked_reason='rotated', rotated_to=?, rotation=? WHERE pubkey=?",
            (handle, new_pubkey, json.dumps(record), old_pubkey),
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO handle_reservations (handle, pubkey, reserved_at) VALUES (?, ?, ?)",
            (handle, new_pubkey, now_iso()),
        )

    def revoke(self, pubkey: str, reason: str) -> None:
        row = self.agent_by_pubkey(pubkey)
        if row is None:
            return
        handle = row["handle"] or row["former_handle"] or ""
        self.conn.execute(
            "UPDATE agents SET handle=NULL, former_handle=?, revoked=1, revoked_reason=? WHERE pubkey=?",
            (handle, reason, pubkey),
        )
        if handle:
            self.conn.execute(
                "INSERT OR REPLACE INTO burned_handles (handle, pubkey, reason, burned_at) VALUES (?, ?, ?, ?)",
                (handle, pubkey, reason, now_iso()),
            )
            self.conn.execute("DELETE FROM handle_reservations WHERE handle=?", (handle,))

    # ---- trust ----------------------------------------------------------- #

    def active_vouches(self, subject_pubkey: str) -> list[sqlite3.Row]:
        """Unexpired, unrevoked vouches whose voucher is still a live identity.

        ``expires_at`` is compared as a string; ``parse_iso`` admits exactly one
        timestamp shape, so string order is chronological order.
        """
        now = now_iso()
        return self.conn.execute(
            "SELECT v.* FROM vouches v JOIN agents a ON a.pubkey = v.voucher_pubkey"
            " WHERE v.subject_pubkey=? AND v.revoked=0 AND v.expires_at > ? AND a.revoked=0 ORDER BY v.issued_at",
            (subject_pubkey, now),
        ).fetchall()

    def tier(self, pubkey: str, operators: set[str], _seen: set[str] | None = None) -> str:
        if pubkey in operators:
            return "T2"
        seen = _seen if _seen is not None else set()
        if pubkey in seen:
            return "T0"
        seen.add(pubkey)
        row = self.agent_by_pubkey(pubkey)
        if row is None or row["revoked"]:
            return "T0"
        for v in self.active_vouches(pubkey):
            voucher = self.agent_by_pubkey(v["voucher_pubkey"])
            if voucher is None or voucher["revoked"]:
                continue
            if tier_at_least(self.tier(v["voucher_pubkey"], operators, seen), "T1"):
                return "T1"
        return "T0"

    def add_vouch(self, *, id: str, voucher: str, subject: str, subject_handle: str, statement: str, expires_at: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO vouches (id, voucher_pubkey, subject_pubkey, subject_handle, statement, issued_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (id, voucher, subject, subject_handle, statement, now_iso(), expires_at),
        )

    def vouch(self, vouch_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM vouches WHERE id=?", (vouch_id,)).fetchone()

    def revoke_vouch(self, vouch_id: str) -> None:
        self.conn.execute("UPDATE vouches SET revoked=1 WHERE id=?", (vouch_id,))

    def add_rating(self, *, rater: str, request_id: str, subject: str, capability: str, score: int, note: str | None, envelope_id: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO ratings (rater_pubkey, request_id, subject_pubkey, capability, score, note, envelope_id, rated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (rater, request_id, subject, capability, score, note, envelope_id, now_iso()),
        )

    def witness_task_request(self, id: str, requester: str, seller: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO task_requests (id, requester_pubkey, seller_pubkey, received_at) VALUES (?, ?, ?, ?)",
            (id, requester, seller, now_iso()),
        )

    def task_request(self, id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM task_requests WHERE id=?", (id,)).fetchone()

    def rating_summary(self, subject: str) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT capability, COUNT(*) AS n, COUNT(DISTINCT rater_pubkey) AS raters, SUM(score) AS total"
            " FROM ratings WHERE subject_pubkey=? GROUP BY capability",
            (subject,),
        ).fetchall()
        # Averages are strings on the wire (spec 4.1: no floats). Every row is
        # backed by a task_request this relay carried from rater to subject,
        # so `count` is rated requests and `raters` is distinct requesters.
        return {
            r["capability"]: {"count": r["n"], "raters": r["raters"], "average": f"{r['total'] / r['n']:.2f}"}
            for r in rows
        }

    # ---- envelopes ------------------------------------------------------- #

    def has_envelope(self, id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT id, received_at FROM envelopes WHERE id=?", (id,)).fetchone()

    def store_envelope(self, env: dict, *, subject_pubkey: str | None, retention_seconds: int) -> str:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        ttl = min(int(env["ttl_seconds"]), retention_seconds)
        received_at = now.isoformat().replace("+00:00", "Z")
        expires_at = (now + timedelta(seconds=ttl)).isoformat().replace("+00:00", "Z")
        self.conn.execute(
            "INSERT INTO envelopes (id, type, from_pubkey, to_target, subject_pubkey, received_at, expires_at, body)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (env["id"], env["type"], env["from"]["pubkey"], env["to"], subject_pubkey, received_at, expires_at, json.dumps(env)),
        )
        return received_at

    def purge_expired(self) -> None:
        self.conn.execute("DELETE FROM envelopes WHERE expires_at <= ?", (now_iso(),))

    def former_pubkeys(self, pubkey: str) -> list[str]:
        """Keys this identity rotated away from, oldest last. Mail sent to them
        before the rotation still belongs to this identity."""
        out: list[str] = []
        current = pubkey
        while True:
            row = self.conn.execute("SELECT pubkey FROM agents WHERE rotated_to=?", (current,)).fetchone()
            if row is None or row["pubkey"] in out:
                return out
            out.append(row["pubkey"])
            current = row["pubkey"]

    def inbox(self, pubkey: str, cursor: int, limit: int) -> tuple[list[dict], int]:
        channels = [r["channel"] for r in self.conn.execute("SELECT channel FROM subscriptions WHERE pubkey=?", (pubkey,))]
        targets = [pubkey, *self.former_pubkeys(pubkey)] + [f"channel:{c}" for c in channels]
        placeholders = ",".join("?" for _ in targets)
        rows = self.conn.execute(
            f"SELECT seq, body, received_at FROM envelopes WHERE seq > ? AND expires_at > ? AND from_pubkey != ?"
            f" AND (to_target IN ({placeholders}) OR subject_pubkey = ?) ORDER BY seq LIMIT ?",
            (cursor, now_iso(), pubkey, *targets, pubkey, limit),
        ).fetchall()
        # Relay metadata travels beside the envelope, never inside it, so the
        # signed object reaches the client byte-for-byte as published.
        out = []
        next_cursor = cursor
        for r in rows:
            out.append({"cursor": r["seq"], "received_at": r["received_at"], "envelope": json.loads(r["body"])})
            next_cursor = r["seq"]
        return out, next_cursor

    def set_ack(self, pubkey: str, cursor: int) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO acks (pubkey, cursor, acked_at) VALUES (?, ?, ?)", (pubkey, cursor, now_iso())
        )

    def get_ack(self, pubkey: str) -> int:
        row = self.conn.execute("SELECT cursor FROM acks WHERE pubkey=?", (pubkey,)).fetchone()
        return row["cursor"] if row else 0

    def subscribe(self, pubkey: str, channel: str) -> None:
        self.conn.execute("INSERT OR IGNORE INTO subscriptions (pubkey, channel) VALUES (?, ?)", (pubkey, channel))

    def unsubscribe(self, pubkey: str, channel: str) -> None:
        self.conn.execute("DELETE FROM subscriptions WHERE pubkey=? AND channel=?", (pubkey, channel))

    def subscriptions(self, pubkey: str) -> list[str]:
        return [r["channel"] for r in self.conn.execute("SELECT channel FROM subscriptions WHERE pubkey=? ORDER BY channel", (pubkey,))]

    def add_report(self, reporter: str, target: str, reason: str, evidence_ids: Iterable[str]) -> int:
        """Idempotent: the same report filed twice returns the same id."""
        ev = json.dumps(sorted(set(evidence_ids)))
        self.conn.execute(
            "INSERT OR IGNORE INTO reports (reporter_pubkey, target_pubkey, reason, evidence_ids, filed_at) VALUES (?, ?, ?, ?, ?)",
            (reporter, target, reason, ev, now_iso()),
        )
        row = self.conn.execute(
            "SELECT id FROM reports WHERE reporter_pubkey=? AND target_pubkey=? AND reason=? AND evidence_ids=?",
            (reporter, target, reason, ev),
        ).fetchone()
        return int(row["id"])

    # ---- rate limits ----------------------------------------------------- #

    def bump_rate(self, pubkey: str, bucket: str, limit: int, window_seconds: int = 3600) -> bool:
        """Increment the counter for the current window; return False when over limit."""
        window = int(datetime.now(timezone.utc).timestamp()) // window_seconds
        row = self.conn.execute(
            "SELECT count FROM rate_counters WHERE pubkey=? AND bucket=? AND window=?", (pubkey, bucket, window)
        ).fetchone()
        count = (row["count"] if row else 0) + 1
        if count > limit:
            return False
        self.conn.execute(
            "INSERT OR REPLACE INTO rate_counters (pubkey, bucket, window, count) VALUES (?, ?, ?, ?)",
            (pubkey, bucket, window, count),
        )
        self.conn.execute("DELETE FROM rate_counters WHERE window < ?", (window - 1,))
        return True


def expires_in_future(text: str) -> bool:
    try:
        return parse_iso(text) > datetime.now(timezone.utc)
    except Exception:  # noqa: BLE001
        return False
