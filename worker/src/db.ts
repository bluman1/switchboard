/** SQLite storage inside the Durable Object. Same schema and semantics as the Python relay's db.py. */
import { nowIso } from "./envelope";
import { tierAtLeast } from "./tiers";

export const SCHEMA = `
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
CREATE TABLE IF NOT EXISTS handle_reservations (handle TEXT PRIMARY KEY, pubkey TEXT NOT NULL, reserved_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS burned_handles (handle TEXT PRIMARY KEY, pubkey TEXT NOT NULL, reason TEXT, burned_at TEXT NOT NULL);
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
CREATE TABLE IF NOT EXISTS subscriptions (pubkey TEXT NOT NULL, channel TEXT NOT NULL, PRIMARY KEY (pubkey, channel));
CREATE TABLE IF NOT EXISTS acks (pubkey TEXT PRIMARY KEY, cursor INTEGER NOT NULL, acked_at TEXT NOT NULL);
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
CREATE TABLE IF NOT EXISTS task_requests (id TEXT PRIMARY KEY, requester_pubkey TEXT NOT NULL, seller_pubkey TEXT NOT NULL, received_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_pubkey TEXT NOT NULL,
  target_pubkey   TEXT NOT NULL,
  reason          TEXT NOT NULL,
  evidence_ids    TEXT NOT NULL,
  filed_at        TEXT NOT NULL,
  UNIQUE (reporter_pubkey, target_pubkey, reason, evidence_ids)
);
CREATE TABLE IF NOT EXISTS seen_signatures (signature TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rate_counters (pubkey TEXT NOT NULL, bucket TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (pubkey, bucket, window));
`;

export type Row = Record<string, SqlStorageValue>;

export interface AgentRow extends Row {
  pubkey: string; handle: string | null; former_handle: string | null; x25519_pubkey: string; runtime: string;
  capability_card: string; registration: string; registered_at: string; last_seen: string;
  revoked: number; revoked_reason: string | null; rotated_to: string | null; rotation: string | null;
}

export interface VouchRow extends Row {
  id: string; voucher_pubkey: string; subject_pubkey: string; subject_handle: string; statement: string;
  issued_at: string; expires_at: string; revoked: number;
}

function isoPlus(seconds: number, from = new Date()): string {
  return nowIso(new Date(from.getTime() + seconds * 1000));
}

export class Db {
  constructor(private sql: SqlStorage) {
    for (const stmt of SCHEMA.split(";")) if (stmt.trim()) sql.exec(stmt);
  }

  private one<T extends Row>(query: string, ...params: SqlStorageValue[]): T | null {
    const rows = this.sql.exec<T>(query, ...params).toArray();
    return rows.length ? rows[0] : null;
  }

  private all<T extends Row>(query: string, ...params: SqlStorageValue[]): T[] {
    return this.sql.exec<T>(query, ...params).toArray();
  }

  private run(query: string, ...params: SqlStorageValue[]): void {
    this.sql.exec(query, ...params);
  }

  // ---- meta ------------------------------------------------------------ //
  getMeta(key: string): string | null {
    const r = this.one<{ value: string }>("SELECT value FROM meta WHERE key=?", key);
    return r ? r.value : null;
  }
  setMeta(key: string, value: string): void {
    this.run("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", key, value);
  }

  // ---- agents ---------------------------------------------------------- //
  agentByPubkey(pubkey: string): AgentRow | null {
    return this.one<AgentRow>("SELECT * FROM agents WHERE pubkey=?", pubkey);
  }
  agentByHandle(handle: string): AgentRow | null {
    return this.one<AgentRow>("SELECT * FROM agents WHERE handle=?", handle);
  }
  allAgents(): AgentRow[] {
    return this.all<AgentRow>("SELECT * FROM agents WHERE revoked=0 ORDER BY registered_at, rowid");
  }
  handleReservation(handle: string): string | null {
    const r = this.one<{ pubkey: string }>("SELECT pubkey FROM handle_reservations WHERE handle=?", handle);
    return r ? r.pubkey : null;
  }
  handleBurned(handle: string): boolean {
    return this.one("SELECT 1 AS x FROM burned_handles WHERE handle=?", handle) !== null;
  }
  register(handle: string, pubkey: string, x25519Pubkey: string, runtime: string, card: unknown, registration: unknown): void {
    const now = nowIso();
    this.run(
      "INSERT INTO agents (pubkey, handle, x25519_pubkey, runtime, capability_card, registration, registered_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      pubkey, handle, x25519Pubkey, runtime, JSON.stringify(card), JSON.stringify(registration), now, now,
    );
    this.run("DELETE FROM handle_reservations WHERE handle=?", handle);
  }
  rememberSignature(signature: string, ttlSeconds: number): boolean {
    const now = new Date();
    this.run("DELETE FROM seen_signatures WHERE expires_at <= ?", nowIso(now));
    if (this.one("SELECT 1 AS x FROM seen_signatures WHERE signature=?", signature)) return false;
    this.run("INSERT INTO seen_signatures (signature, expires_at) VALUES (?, ?)", signature, isoPlus(ttlSeconds, now));
    return true;
  }
  touch(pubkey: string): void {
    this.run("UPDATE agents SET last_seen=? WHERE pubkey=?", nowIso(), pubkey);
  }
  updateCard(pubkey: string, card: unknown): void {
    this.run("UPDATE agents SET capability_card=? WHERE pubkey=?", JSON.stringify(card), pubkey);
  }
  rotate(oldPubkey: string, newPubkey: string, handle: string, record: unknown): void {
    this.run(
      "UPDATE agents SET handle=NULL, former_handle=?, revoked=1, revoked_reason='rotated', rotated_to=?, rotation=? WHERE pubkey=?",
      handle, newPubkey, JSON.stringify(record), oldPubkey,
    );
    this.run("INSERT OR REPLACE INTO handle_reservations (handle, pubkey, reserved_at) VALUES (?, ?, ?)", handle, newPubkey, nowIso());
  }
  revoke(pubkey: string, reason: string): void {
    const row = this.agentByPubkey(pubkey);
    if (!row) return;
    const handle = row.handle || row.former_handle || "";
    this.run("UPDATE agents SET handle=NULL, former_handle=?, revoked=1, revoked_reason=? WHERE pubkey=?", handle, reason, pubkey);
    if (handle) {
      this.run("INSERT OR REPLACE INTO burned_handles (handle, pubkey, reason, burned_at) VALUES (?, ?, ?, ?)", handle, pubkey, reason, nowIso());
      this.run("DELETE FROM handle_reservations WHERE handle=?", handle);
    }
  }

  // ---- trust ----------------------------------------------------------- //
  activeVouches(subjectPubkey: string): VouchRow[] {
    return this.all<VouchRow>(
      "SELECT v.* FROM vouches v JOIN agents a ON a.pubkey = v.voucher_pubkey" +
        " WHERE v.subject_pubkey=? AND v.revoked=0 AND v.expires_at > ? AND a.revoked=0 ORDER BY v.issued_at, v.rowid",
      subjectPubkey, nowIso(),
    );
  }
  tier(pubkey: string, operators: Set<string>, seen: Set<string> = new Set()): string {
    if (operators.has(pubkey)) return "T2";
    if (seen.has(pubkey)) return "T0";
    seen.add(pubkey);
    const row = this.agentByPubkey(pubkey);
    if (!row || row.revoked) return "T0";
    for (const v of this.activeVouches(pubkey)) {
      const voucher = this.agentByPubkey(v.voucher_pubkey);
      if (!voucher || voucher.revoked) continue;
      if (tierAtLeast(this.tier(v.voucher_pubkey, operators, seen), "T1")) return "T1";
    }
    return "T0";
  }
  addVouch(id: string, voucher: string, subject: string, subjectHandle: string, statement: string, expiresAt: string): void {
    this.run(
      "INSERT OR REPLACE INTO vouches (id, voucher_pubkey, subject_pubkey, subject_handle, statement, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      id, voucher, subject, subjectHandle, statement, nowIso(), expiresAt,
    );
  }
  vouch(id: string): VouchRow | null {
    return this.one<VouchRow>("SELECT * FROM vouches WHERE id=?", id);
  }
  revokeVouch(id: string): void {
    this.run("UPDATE vouches SET revoked=1 WHERE id=?", id);
  }
  addRating(rater: string, requestId: string, subject: string, capability: string, score: number, note: string | null, envelopeId: string): void {
    this.run(
      "INSERT OR REPLACE INTO ratings (rater_pubkey, request_id, subject_pubkey, capability, score, note, envelope_id, rated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      rater, requestId, subject, capability, score, note, envelopeId, nowIso(),
    );
  }
  witnessTaskRequest(id: string, requester: string, seller: string): void {
    this.run("INSERT OR IGNORE INTO task_requests (id, requester_pubkey, seller_pubkey, received_at) VALUES (?, ?, ?, ?)", id, requester, seller, nowIso());
  }
  taskRequest(id: string): { requester_pubkey: string; seller_pubkey: string } | null {
    return this.one<{ requester_pubkey: string; seller_pubkey: string }>("SELECT requester_pubkey, seller_pubkey FROM task_requests WHERE id=?", id);
  }
  ratingSummary(subject: string): Record<string, { count: number; raters: number; average: string }> {
    const rows = this.all<{ capability: string; n: number; raters: number; total: number }>(
      "SELECT capability, COUNT(*) AS n, COUNT(DISTINCT rater_pubkey) AS raters, SUM(score) AS total FROM ratings WHERE subject_pubkey=? GROUP BY capability ORDER BY capability",
      subject,
    );
    const out: Record<string, { count: number; raters: number; average: string }> = {};
    for (const r of rows) out[r.capability] = { count: Number(r.n), raters: Number(r.raters), average: fmt2(Number(r.total) / Number(r.n)) };
    return out;
  }

  // ---- envelopes ------------------------------------------------------- //
  hasEnvelope(id: string): { received_at: string } | null {
    return this.one<{ received_at: string }>("SELECT received_at FROM envelopes WHERE id=?", id);
  }
  storeEnvelope(env: { id: string; type: string; from: { pubkey: string }; to: string; ttl_seconds: number }, subjectPubkey: string | null, retentionSeconds: number): string {
    const now = new Date();
    const ttl = Math.min(env.ttl_seconds, retentionSeconds);
    const receivedAt = nowIso(now);
    this.run(
      "INSERT INTO envelopes (id, type, from_pubkey, to_target, subject_pubkey, received_at, expires_at, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      env.id, env.type, env.from.pubkey, env.to, subjectPubkey, receivedAt, isoPlus(ttl, now), JSON.stringify(env),
    );
    return receivedAt;
  }
  purgeExpired(): void {
    this.run("DELETE FROM envelopes WHERE expires_at <= ?", nowIso());
  }
  formerPubkeys(pubkey: string): string[] {
    const out: string[] = [];
    let current = pubkey;
    for (;;) {
      const row = this.one<{ pubkey: string }>("SELECT pubkey FROM agents WHERE rotated_to=?", current);
      if (!row || out.includes(row.pubkey)) return out;
      out.push(row.pubkey);
      current = row.pubkey;
    }
  }
  inbox(pubkey: string, cursor: number, limit: number): { items: { cursor: number; received_at: string; envelope: unknown }[]; next: number } {
    const channels = this.all<{ channel: string }>("SELECT channel FROM subscriptions WHERE pubkey=?", pubkey).map((r) => r.channel);
    const targets = [pubkey, ...this.formerPubkeys(pubkey), ...channels.map((c) => `channel:${c}`)];
    const placeholders = targets.map(() => "?").join(",");
    const rows = this.all<{ seq: number; body: string; received_at: string }>(
      `SELECT seq, body, received_at FROM envelopes WHERE seq > ? AND expires_at > ? AND from_pubkey != ? AND (to_target IN (${placeholders}) OR subject_pubkey = ?) ORDER BY seq LIMIT ?`,
      cursor, nowIso(), pubkey, ...targets, pubkey, limit,
    );
    let next = cursor;
    const items = rows.map((r) => {
      next = Number(r.seq);
      return { cursor: Number(r.seq), received_at: r.received_at, envelope: JSON.parse(r.body) as unknown };
    });
    return { items, next };
  }
  setAck(pubkey: string, cursor: number): void {
    this.run("INSERT OR REPLACE INTO acks (pubkey, cursor, acked_at) VALUES (?, ?, ?)", pubkey, cursor, nowIso());
  }
  getAck(pubkey: string): number {
    const r = this.one<{ cursor: number }>("SELECT cursor FROM acks WHERE pubkey=?", pubkey);
    return r ? Number(r.cursor) : 0;
  }
  subscribe(pubkey: string, channel: string): void {
    this.run("INSERT OR IGNORE INTO subscriptions (pubkey, channel) VALUES (?, ?)", pubkey, channel);
  }
  unsubscribe(pubkey: string, channel: string): void {
    this.run("DELETE FROM subscriptions WHERE pubkey=? AND channel=?", pubkey, channel);
  }
  subscriptions(pubkey: string): string[] {
    return this.all<{ channel: string }>("SELECT channel FROM subscriptions WHERE pubkey=? ORDER BY channel", pubkey).map((r) => r.channel);
  }
  addReport(reporter: string, target: string, reason: string, evidenceIds: string[]): number {
    const ev = JSON.stringify([...new Set(evidenceIds)].sort());
    this.run("INSERT OR IGNORE INTO reports (reporter_pubkey, target_pubkey, reason, evidence_ids, filed_at) VALUES (?, ?, ?, ?, ?)", reporter, target, reason, ev, nowIso());
    const row = this.one<{ id: number }>("SELECT id FROM reports WHERE reporter_pubkey=? AND target_pubkey=? AND reason=? AND evidence_ids=?", reporter, target, reason, ev);
    return Number(row!.id);
  }

  // ---- rate limits ----------------------------------------------------- //
  bumpRate(key: string, bucket: string, limit: number, windowSeconds = 3600): boolean {
    const window = Math.floor(Date.now() / 1000 / windowSeconds);
    const row = this.one<{ count: number }>("SELECT count FROM rate_counters WHERE pubkey=? AND bucket=? AND window=?", key, bucket, window);
    const count = (row ? Number(row.count) : 0) + 1;
    if (count > limit) return false;
    this.run("INSERT OR REPLACE INTO rate_counters (pubkey, bucket, window, count) VALUES (?, ?, ?, ?)", key, bucket, window, count);
    this.run("DELETE FROM rate_counters WHERE window < ?", window - 1);
    return true;
  }

  /** Test-only: wipe everything except the relay's own keys. */
  reset(): void {
    for (const t of ["agents", "handle_reservations", "burned_handles", "envelopes", "subscriptions", "acks", "vouches", "ratings", "task_requests", "reports", "seen_signatures", "rate_counters"]) {
      this.run(`DELETE FROM ${t}`);
    }
    this.run("DELETE FROM sqlite_sequence");
  }
}

/** Python's f"{x:.2f}" on a double: correctly rounded, ties to even. toFixed rounds exact ties up. */
export function fmt2(x: number): string {
  const t = x * 1000;
  if (Number.isInteger(t) && Math.abs(t % 10) === 5) {
    const q = Math.trunc(t / 10);
    const r = q % 2 === 0 ? q : q + Math.sign(t);
    return (r / 100).toFixed(2);
  }
  return x.toFixed(2);
}
