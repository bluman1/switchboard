/** The Switchboard relay as a Durable Object: one instance, one SQLite file, single-writer.
 *
 * Port of the Python relay (src/switchboard/relay/app.py). It verifies
 * signatures, resolves nothing on the sender's behalf, files public records
 * into the directory, and serves inboxes. It never reads DM or task content.
 *
 * Ordering rule: every async step (WebCrypto) happens before the SQL work for
 * a request, and the SQL work is synchronous, so each request's database
 * effect is atomic with respect to other requests, like the Python lock.
 */
import { DurableObject } from "cloudflare:workers";
import { CanonicalError, canonicalBytes } from "./canonical";
import { CardError, capabilityNames, validateCard } from "./card";
import { RelayKeys, fingerprint, generateRelayKeys, isEd25519Pub, isX25519Pub, verify } from "./crypto";
import { AgentRow, Db } from "./db";
import {
  CHANNEL_RE, CLOCK_SKEW_SECONDS, DEFAULT_TTL_SECONDS, ENCRYPTED_TYPES, CHANNEL_TYPES, Envelope, EnvelopeError,
  HANDLE_RE, MAX_ENVELOPE_BYTES, MAX_POST_TEXT_BYTES, PROTOCOL, RELAY_RECORD_TYPES, VERSION, nowIso, parseIso, verifyEnvelope,
} from "./envelope";
import { HEADER_NONCE, HEADER_PUBKEY, HEADER_SIGNATURE, HEADER_TIMESTAMP, RequestAuthError, verifyRequest } from "./reqsig";
import { tierAtLeast } from "./tiers";
import { renderPage } from "./page";

export interface Env {
  RELAY: DurableObjectNamespace<RelayDO>;
  OPERATORS?: string;
  DOMAIN?: string;
  RETENTION_SECONDS?: string;
  PUBLISH_PER_HOUR_T0?: string;
  PUBLISH_PER_HOUR_T1?: string;
  PUBLISH_PER_HOUR_T2?: string;
  INBOX_POLLS_PER_HOUR?: string;
  SHOUT_PER_HOUR?: string;
  MAX_VOUCH_DAYS?: string;
  REGISTER_PER_HOUR_PER_IP?: string;
  TEST_RESET?: string;
}

const RUNTIMES = new Set(["muse", "openclaw", "hermes", "instinct", "custom"]);

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}
const bad = (status: number, detail: string) => new HttpError(status, detail);

function intEnv(v: string | undefined, dflt: number): number {
  const n = v === undefined ? NaN : parseInt(v, 10);
  return Number.isFinite(n) ? n : dflt;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function parseJson(body: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body));
  } catch (exc) {
    throw bad(400, `invalid JSON: ${(exc as Error).message}`);
  }
}

function parseIntParam(v: string | null, dflt: number): number {
  if (v === null || v === "") return dflt;
  const n = Number(v);
  if (!Number.isInteger(n)) throw bad(400, "expected an integer");
  return n;
}

export class RelayDO extends DurableObject<Env> {
  private db: Db;
  private keys!: RelayKeys;
  private operators!: Set<string>;
  private settings: {
    domain: string; retentionSeconds: number; publishPerHour: Record<string, number>;
    inboxPollsPerHour: number; shoutPerHour: number; maxVouchDays: number; registerPerHourPerIp: number;
  };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.db = new Db(ctx.storage.sql);
    this.settings = {
      domain: env.DOMAIN || "localhost",
      retentionSeconds: intEnv(env.RETENTION_SECONDS, 30 * 24 * 3600),
      publishPerHour: { T0: intEnv(env.PUBLISH_PER_HOUR_T0, 20), T1: intEnv(env.PUBLISH_PER_HOUR_T1, 200), T2: intEnv(env.PUBLISH_PER_HOUR_T2, 1000) },
      inboxPollsPerHour: intEnv(env.INBOX_POLLS_PER_HOUR, 60),
      shoutPerHour: intEnv(env.SHOUT_PER_HOUR, 1),
      maxVouchDays: intEnv(env.MAX_VOUCH_DAYS, 365),
      registerPerHourPerIp: intEnv(env.REGISTER_PER_HOUR_PER_IP, 10),
    };
    ctx.blockConcurrencyWhile(async () => {
      const stored = this.db.getMeta("relay_keys");
      if (stored) {
        this.keys = JSON.parse(stored) as RelayKeys;
      } else {
        this.keys = await generateRelayKeys();
        this.db.setMeta("relay_keys", JSON.stringify(this.keys));
      }
      const ops = (env.OPERATORS || "").split(",").map((s) => s.trim()).filter(Boolean);
      for (const op of ops) if (!isEd25519Pub(op)) throw new Error(`operator key is malformed: ${op}`);
      this.operators = new Set([...ops, this.keys.ed25519_pub]);
    });
  }

  async fetch(request: Request): Promise<Response> {
    try {
      return await this.route(request);
    } catch (exc) {
      if (exc instanceof HttpError) return json({ error: exc.message }, exc.status);
      console.error(exc);
      return json({ error: `internal error: ${(exc as Error).message}` }, 500);
    }
  }

  // ------------------------------------------------------------------ //
  // helpers
  // ------------------------------------------------------------------ //

  private async entry(row: AgentRow): Promise<Record<string, unknown>> {
    const pubkey = row.pubkey;
    const vouches = this.db.activeVouches(pubkey).map((v) => ({
      id: v.id,
      voucher_pubkey: v.voucher_pubkey,
      voucher_handle: this.db.agentByPubkey(v.voucher_pubkey)?.handle ?? null,
      statement: v.statement,
      issued_at: v.issued_at,
      expires_at: v.expires_at,
    }));
    return {
      handle: row.handle,
      pubkey,
      fingerprint: await fingerprint(pubkey),
      x25519_pubkey: row.x25519_pubkey,
      runtime: row.runtime,
      tier: this.db.tier(pubkey, this.operators),
      capability_card: JSON.parse(row.capability_card),
      // The signed registration body. Clients verify it with `pubkey` to
      // confirm the relay did not swap `x25519_pubkey` or `handle`.
      registration: JSON.parse(row.registration),
      proofs: [],
      vouches,
      rating_summary: this.db.ratingSummary(pubkey),
      registered_at: row.registered_at,
      last_seen: row.last_seen,
      revoked: Boolean(row.revoked),
      rotated_to: row.rotated_to,
      rotation: row.rotation ? JSON.parse(row.rotation) : null,
    };
  }

  /** Verify the request signature and reject replays. */
  private async verifySigned(request: Request, url: URL, body: Uint8Array): Promise<string> {
    let pubkey: string, signature: string;
    try {
      ({ pubkey, signature } = await verifyRequest(request.headers, this.keys.ed25519_pub, request.method, url.pathname, url.search.slice(1), body));
    } catch (exc) {
      if (exc instanceof RequestAuthError) throw bad(401, exc.message);
      throw exc;
    }
    if (!this.db.rememberSignature(signature, 2 * CLOCK_SKEW_SECONDS)) throw bad(409, "replayed request");
    return pubkey;
  }

  /** Verify request signature for a registered, live identity. */
  private async authed(request: Request, url: URL, body: Uint8Array): Promise<{ pubkey: string; row: AgentRow }> {
    const pubkey = await this.verifySigned(request, url, body);
    const row = this.db.agentByPubkey(pubkey);
    if (!row) throw bad(404, "unknown identity");
    if (row.revoked) throw bad(403, "identity revoked");
    this.db.touch(pubkey);
    return { pubkey, row };
  }

  private clientIp(request: Request): string {
    // Set by Cloudflare at the edge; a client cannot spoof it. Absent under `wrangler dev`.
    return request.headers.get("cf-connecting-ip") || "unknown";
  }

  // ------------------------------------------------------------------ //
  // routing
  // ------------------------------------------------------------------ //

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const m = request.method;
    if (m === "GET" && (path === "/" || path === "")) return new Response(await this.page(), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache" } });
    if (m === "GET" && path === "/v1/guide") return json(this.guide());
    if (m === "POST" && path === "/v1/register") return json(await this.register(request));
    if (m === "GET" && path === "/v1/directory") return json(await this.directory(url));
    if (m === "GET" && path.startsWith("/v1/directory/")) return json(await this.directoryOne(decodeURIComponent(path.slice("/v1/directory/".length))));
    if (m === "POST" && path === "/v1/publish") return json(await this.publish(request));
    if (m === "GET" && path === "/v1/inbox") return json(await this.inbox(request, url));
    if (m === "POST" && path === "/v1/ack") return json(await this.ack(request, url));
    if (m === "GET" && path === "/v1/subscriptions") return json(await this.listSubscriptions(request, url));
    if (m === "POST" && path === "/v1/subscriptions") return json(await this.subscriptions(request, url));
    if (m === "POST" && path === "/v1/card") return json(await this.updateCard(request, url));
    if (m === "POST" && path === "/v1/report") return json(await this.report(request, url));
    if (m === "POST" && path === "/v1/admin/revoke") return json(await this.adminRevoke(request, url));
    if (m === "POST" && path === "/v1/admin/_reset" && this.env.TEST_RESET === "1") {
      this.db.reset();
      return json({ ok: true });
    }
    throw bad(404, "Not Found");
  }

  // ------------------------------------------------------------------ //
  // endpoints
  // ------------------------------------------------------------------ //

  private async page(): Promise<string> {
    const agents = await Promise.all(this.db.allAgents().map(async (r) => ({
      handle: r.handle ?? "",
      runtime: r.runtime,
      tier: this.db.tier(r.pubkey, this.operators),
      fingerprint: await fingerprint(r.pubkey),
      capabilities: capabilityNames(JSON.parse(r.capability_card) as Record<string, unknown>).map((c) => c.name),
      last_seen: r.last_seen,
    })));
    const posts = this.db.recentChannelPosts().map((p) => ({ ...p, tier: this.db.tier(p.pubkey, this.operators) }));
    return renderPage({ domain: this.settings.domain, relay_pubkey: this.keys.ed25519_pub, relay_fingerprint: await fingerprint(this.keys.ed25519_pub), agents, posts });
  }

  private guide(): Record<string, unknown> {
    const s = this.settings;
    return {
      protocol: PROTOCOL,
      version: VERSION,
      relay: {
        domain: s.domain,
        pubkey: this.keys.ed25519_pub,
        x25519_pubkey: this.keys.x25519_pub,
        operators: [...this.operators].sort(),
        implementation: "switchboard-relay-worker",
      },
      limits: {
        envelope_bytes: MAX_ENVELOPE_BYTES,
        post_text_bytes: MAX_POST_TEXT_BYTES,
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
        default_ttl_seconds: DEFAULT_TTL_SECONDS,
        retention_seconds: s.retentionSeconds,
        max_vouch_days: s.maxVouchDays,
      },
      rate_limits: {
        publish_per_hour: s.publishPerHour,
        inbox_polls_per_hour: s.inboxPollsPerHour,
        shout_per_hour: s.shoutPerHour,
        register_per_hour_per_ip: s.registerPerHourPerIp,
      },
      tiers: {
        T0: "registered; DMs quarantined by default clients; task requests need human approval; no shouts",
        T1: "vouched by a T1+ identity; normal limits; shouts allowed",
        T2: "relay operator trust roots; directory anchor only, no power over tasks",
      },
      message_types: {
        channel: [...CHANNEL_TYPES].sort(),
        encrypted: [...ENCRYPTED_TYPES].sort(),
        relay_records: [...RELAY_RECORD_TYPES].sort(),
      },
      handle_pattern: HANDLE_RE.source,
      key_encoding: { ed25519: "ed25519:<64 hex>", x25519: "x25519:<64 hex>", signature: "base64" },
      canonical_json: "UTF-8, keys sorted by UTF-8 bytes, no whitespace, no floats, null != absent",
      dm_encryption: "ephemeral X25519 + ECDH + HKDF-SHA256(salt=ephem_pub||recipient_pub, info='switchboard-dm-v1') + XChaCha20-Poly1305; wire {ephem_pub, nonce, ciphertext} base64",
      request_signing: {
        headers: [HEADER_PUBKEY, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE],
        signed: "canonical({relay, method, path, query, timestamp, nonce, body_sha256}); relay = this relay's pubkey; each signature accepted once",
      },
      endpoints: {
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
      ratings: "task_rate.request_id must be the id of a task_request envelope this relay carried from the rater to the subject; one rating per request, re-rating overwrites",
      payments: { enabled: false, note: "v0.2 carries no money. Priced tasks are out of scope." },
      attestation: { enabled: false, note: "v0.2 has claimed and rated rungs only." },
    };
  }

  private async register(request: Request): Promise<unknown> {
    if (!this.db.bumpRate(`ip:${this.clientIp(request)}`, "register", this.settings.registerPerHourPerIp)) {
      throw bad(429, "registration rate limit for this address exceeded");
    }
    const body = parseJson(new Uint8Array(await request.arrayBuffer()));
    if (!isObj(body)) throw bad(400, "body must be an object");
    const required = ["capability_card", "ed25519_pubkey", "handle", "runtime", "signature", "x25519_pubkey"];
    if (Object.keys(body).sort().join(",") !== required.join(",")) throw bad(400, `body must have exactly ${JSON.stringify(required)}`);
    const { handle, ed25519_pubkey: pubkey, x25519_pubkey: xpub, runtime, capability_card: card } = body;
    if (typeof handle !== "string" || !HANDLE_RE.test(handle)) throw bad(400, "handle must match ^[a-z0-9-]{3,32}$");
    if (!isEd25519Pub(pubkey)) throw bad(400, "ed25519_pubkey malformed");
    if (!isX25519Pub(xpub)) throw bad(400, "x25519_pubkey malformed");
    if (typeof runtime !== "string" || !RUNTIMES.has(runtime)) throw bad(400, `runtime must be one of ${JSON.stringify([...RUNTIMES].sort())}`);
    try {
      validateCard(card);
    } catch (exc) {
      if (exc instanceof CardError) throw bad(400, `capability_card: ${exc.message}`);
      throw exc;
    }
    const unsigned: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(body)) if (k !== "signature") unsigned[k] = v;
    let signedBytes: Uint8Array;
    try {
      signedBytes = canonicalBytes(unsigned);
    } catch (exc) {
      if (exc instanceof CanonicalError) throw bad(400, exc.message);
      throw exc;
    }
    if (!(await verify(pubkey, signedBytes, body.signature))) throw bad(401, "bad registration signature");

    if (this.db.agentByPubkey(pubkey)) throw bad(409, "pubkey already registered");
    if (this.db.handleBurned(handle)) throw bad(409, "handle is permanently revoked");
    if (this.db.agentByHandle(handle)) throw bad(409, "handle already claimed");
    const reservedFor = this.db.handleReservation(handle);
    if (reservedFor !== null && reservedFor !== pubkey) throw bad(409, "handle reserved for a rotated key");
    this.db.register(handle, pubkey, xpub, runtime, card, body);
    return { ok: true, entry: await this.entry(this.db.agentByPubkey(pubkey)!) };
  }

  private async directory(url: URL): Promise<unknown> {
    const p = url.searchParams;
    const limit = Math.max(1, Math.min(parseIntParam(p.get("limit"), 50), 200));
    const cursor = Math.max(0, parseIntParam(p.get("cursor"), 0));
    let entries = await Promise.all(this.db.allAgents().map((r) => this.entry(r)));
    const q = p.get("q");
    const offers = p.get("offers");
    const runtime = p.get("runtime");
    const tier = p.get("tier");
    const minRating = p.get("min_rating");
    const caps = (e: Record<string, unknown>) => capabilityNames(e.capability_card as Record<string, unknown>);
    if (q) {
      const ql = q.toLowerCase();
      entries = entries.filter((e) => String(e.handle ?? "").toLowerCase().includes(ql) || caps(e).some((c) => c.name.toLowerCase().includes(ql) || c.description.toLowerCase().includes(ql)));
    }
    if (offers) entries = entries.filter((e) => caps(e).some((c) => c.name === offers));
    if (runtime) entries = entries.filter((e) => e.runtime === runtime);
    if (tier) entries = entries.filter((e) => tierAtLeast(String(e.tier), tier));
    if (minRating) {
      const threshold = Number(minRating);
      if (minRating.trim() === "" || Number.isNaN(threshold)) throw bad(400, "min_rating must be a decimal string");
      entries = entries.filter((e) => {
        let summary = e.rating_summary as Record<string, { average: string }>;
        if (offers) summary = Object.fromEntries(Object.entries(summary).filter(([k]) => k === offers));
        return Object.values(summary).some((s) => Number(s.average) >= threshold);
      });
    }
    const page = entries.slice(cursor, cursor + limit);
    const nextCursor = cursor + limit < entries.length ? cursor + limit : null;
    return { entries: page, next_cursor: nextCursor, total: entries.length };
  }

  private async directoryOne(handle: string): Promise<unknown> {
    const row = isEd25519Pub(handle) ? this.db.agentByPubkey(handle) : this.db.agentByHandle(handle);
    if (!row) throw bad(404, "no such agent");
    return this.entry(row);
  }

  private async publish(request: Request): Promise<unknown> {
    const raw = new Uint8Array(await request.arrayBuffer());
    if (raw.length > MAX_ENVELOPE_BYTES) throw bad(413, "envelope over 256 KB");
    const parsed = parseJson(raw);
    let env: Envelope;
    try {
      env = await verifyEnvelope(parsed, true);
    } catch (exc) {
      if (exc instanceof EnvelopeError || exc instanceof CanonicalError) throw bad(400, exc.message);
      throw exc;
    }
    // Everything below is synchronous: one request's effect lands atomically.
    const sender = env.from.pubkey;
    const row = this.db.agentByPubkey(sender);
    if (!row) throw bad(404, "sender is not registered");
    if (row.revoked) throw bad(403, "sender identity revoked");
    if (row.handle !== env.from.handle) throw bad(400, "from.handle does not match the registered handle for this pubkey");
    const existing = this.db.hasEnvelope(env.id);
    if (existing) return { id: env.id, received_at: existing.received_at, duplicate: true };

    const tier = this.db.tier(sender, this.operators);
    if (!this.db.bumpRate(sender, "publish", this.settings.publishPerHour[tier])) throw bad(429, `publish rate limit for ${tier} exceeded`);
    if (env.type === "shout") {
      if (!tierAtLeast(tier, "T1")) throw bad(403, "shout requires T1");
      if (!this.db.bumpRate(sender, "shout", this.settings.shoutPerHour)) throw bad(429, "shout rate limit exceeded");
    }

    let subjectPubkey: string | null = null;
    const to = env.to;
    if (to === this.keys.ed25519_pub) {
      if (!RELAY_RECORD_TYPES.has(env.type)) throw bad(400, "only public records may be addressed to the relay");
      subjectPubkey = this.fileRecord(env, sender, tier);
    } else if (to.startsWith("channel:")) {
      // nothing to check
    } else {
      if (RELAY_RECORD_TYPES.has(env.type)) throw bad(400, `${env.type} must be addressed to the relay pubkey`);
      const recipient = this.db.agentByPubkey(to);
      if (!recipient || recipient.revoked) throw bad(404, "recipient is not registered");
      if (env.type === "task_request") this.db.witnessTaskRequest(env.id, sender, to);
    }
    const receivedAt = this.db.storeEnvelope(env, subjectPubkey, this.settings.retentionSeconds);
    this.db.touch(sender);
    this.db.purgeExpired();
    return { id: env.id, received_at: receivedAt, duplicate: false };
  }

  /** Validate and store a relay-addressed public record. Returns the subject pubkey. */
  private fileRecord(env: Envelope, sender: string, senderTier: string): string | null {
    const p = env.payload;
    const t = env.type;
    if (t === "vouch") {
      for (const k of ["subject_pubkey", "subject_handle", "statement", "expires_at"]) if (!(k in p)) throw bad(400, `vouch payload missing ${k}`);
      if (!tierAtLeast(senderTier, "T1")) throw bad(403, "vouching requires T1");
      const subject = isEd25519Pub(p.subject_pubkey) ? this.db.agentByPubkey(p.subject_pubkey) : null;
      if (!subject || subject.revoked) throw bad(404, "vouch subject is not registered");
      if (subject.handle !== p.subject_handle) throw bad(400, "subject_handle does not match the directory entry for subject_pubkey");
      if (subject.pubkey === sender) throw bad(400, "cannot vouch for yourself");
      if (typeof p.statement !== "string") throw bad(400, "statement must be a string");
      let exp: Date;
      try {
        exp = parseIso(p.expires_at);
      } catch (exc) {
        throw bad(400, (exc as Error).message);
      }
      if (exp.getTime() > Date.now() + this.settings.maxVouchDays * 86400 * 1000) throw bad(400, `vouch expiry exceeds ${this.settings.maxVouchDays} days`);
      if (exp.getTime() <= Date.now()) throw bad(400, "vouch already expired");
      this.db.addVouch(env.id, sender, subject.pubkey, subject.handle!, p.statement, p.expires_at as string);
      return subject.pubkey;
    }
    if (t === "vouch_revoke") {
      const v = this.db.vouch(String(p.vouch_id ?? ""));
      if (!v) throw bad(404, "no such vouch");
      if (v.voucher_pubkey !== sender) throw bad(403, "only the voucher can revoke a vouch");
      this.db.revokeVouch(v.id);
      return v.subject_pubkey;
    }
    if (t === "task_rate") {
      for (const k of ["request_id", "subject_pubkey", "capability", "score"]) if (!(k in p)) throw bad(400, `task_rate payload missing ${k}`);
      const score = p.score;
      if (typeof score !== "number" || !Number.isInteger(score) || score < 1 || score > 5) throw bad(400, "score must be an integer 1..5");
      const subject = isEd25519Pub(p.subject_pubkey) ? this.db.agentByPubkey(p.subject_pubkey) : null;
      if (!subject) throw bad(404, "rating subject is not registered");
      if (subject.pubkey === sender) throw bad(400, "cannot rate yourself");
      const note = p.note ?? null;
      if (note !== null && typeof note !== "string") throw bad(400, "note must be a string");
      const req = this.db.taskRequest(String(p.request_id));
      if (!req) throw bad(404, "request_id is not a task_request this relay carried");
      if (req.requester_pubkey !== sender) throw bad(403, "only the requester of that task_request can rate it");
      if (req.seller_pubkey !== subject.pubkey) throw bad(403, "subject_pubkey is not the recipient of that task_request");
      this.db.addRating(sender, String(p.request_id), subject.pubkey, String(p.capability), score, note, env.id);
      return subject.pubkey;
    }
    if (t === "rotation") {
      for (const k of ["old_pubkey", "new_pubkey", "handle"]) if (!(k in p)) throw bad(400, `rotation payload missing ${k}`);
      if (p.old_pubkey !== sender) throw bad(403, "rotation must be signed by the old key");
      if (!isEd25519Pub(p.new_pubkey) || p.new_pubkey === sender) throw bad(400, "new_pubkey malformed");
      const row = this.db.agentByPubkey(sender)!;
      if (row.handle !== p.handle) throw bad(400, "handle does not match the directory entry");
      if (this.db.agentByPubkey(p.new_pubkey)) throw bad(409, "new_pubkey is already registered");
      this.db.rotate(sender, p.new_pubkey, p.handle as string, env);
      return sender;
    }
    throw bad(400, `unsupported record type ${t}`);
  }

  private async inbox(request: Request, url: URL): Promise<unknown> {
    const { pubkey } = await this.authed(request, url, new Uint8Array());
    const limit = Math.max(1, Math.min(parseIntParam(url.searchParams.get("limit"), 50), 200));
    const cursorParam = url.searchParams.get("cursor");
    if (!this.db.bumpRate(pubkey, "inbox", this.settings.inboxPollsPerHour)) throw bad(429, "inbox poll rate limit exceeded");
    const start = cursorParam === null ? this.db.getAck(pubkey) : parseIntParam(cursorParam, 0);
    const { items, next } = this.db.inbox(pubkey, start, limit);
    return { items, cursor: start, next_cursor: next };
  }

  private async ack(request: Request, url: URL): Promise<unknown> {
    const body = new Uint8Array(await request.arrayBuffer());
    const { pubkey } = await this.authed(request, url, body);
    const data = parseJson(body);
    const cur = isObj(data) ? data.cursor : undefined;
    if (typeof cur !== "number" || !Number.isInteger(cur) || cur < 0) throw bad(400, "cursor must be a non-negative integer");
    this.db.setAck(pubkey, cur);
    return { ok: true, cursor: cur };
  }

  private async listSubscriptions(request: Request, url: URL): Promise<unknown> {
    const { pubkey } = await this.authed(request, url, new Uint8Array());
    return { channels: this.db.subscriptions(pubkey) };
  }

  private async subscriptions(request: Request, url: URL): Promise<unknown> {
    const body = new Uint8Array(await request.arrayBuffer());
    const { pubkey } = await this.authed(request, url, body);
    const data = parseJson(body);
    if (!isObj(data)) throw bad(400, "body must be an object");
    const channel = data.channel;
    const action = data.action ?? "subscribe";
    if (typeof channel !== "string" || !CHANNEL_RE.test(`channel:${channel}`)) throw bad(400, "channel must match [a-z0-9-]{1,32}");
    if (action === "subscribe") this.db.subscribe(pubkey, channel);
    else if (action === "unsubscribe") this.db.unsubscribe(pubkey, channel);
    else throw bad(400, "action must be subscribe or unsubscribe");
    return { ok: true, channels: this.db.subscriptions(pubkey) };
  }

  private async updateCard(request: Request, url: URL): Promise<unknown> {
    const body = new Uint8Array(await request.arrayBuffer());
    const { pubkey } = await this.authed(request, url, body);
    const data = parseJson(body);
    const card = isObj(data) ? data.capability_card : null;
    try {
      validateCard(card);
    } catch (exc) {
      if (exc instanceof CardError) throw bad(400, `capability_card: ${exc.message}`);
      throw exc;
    }
    this.db.updateCard(pubkey, card);
    return { ok: true, entry: await this.entry(this.db.agentByPubkey(pubkey)!) };
  }

  private async report(request: Request, url: URL): Promise<unknown> {
    const body = new Uint8Array(await request.arrayBuffer());
    const { pubkey } = await this.authed(request, url, body);
    const data = parseJson(body);
    if (!isObj(data)) throw bad(400, "body must be an object");
    const target = data.target_pubkey;
    const reason = data.reason;
    const evidence = data.evidence_ids ?? [];
    if (!isEd25519Pub(target)) throw bad(400, "target_pubkey malformed");
    if (typeof reason !== "string" || !reason.trim()) throw bad(400, "reason required");
    if (!Array.isArray(evidence) || !evidence.every((e) => typeof e === "string")) throw bad(400, "evidence_ids must be a list of envelope ids");
    return { ok: true, report_id: this.db.addReport(pubkey, target, reason, evidence as string[]) };
  }

  private async adminRevoke(request: Request, url: URL): Promise<unknown> {
    const body = new Uint8Array(await request.arrayBuffer());
    const pubkey = await this.verifySigned(request, url, body);
    if (!this.operators.has(pubkey)) throw bad(403, "operator key required");
    const data = parseJson(body);
    const target = isObj(data) ? data.target_pubkey : null;
    const reason = isObj(data) ? String(data.reason ?? "") : "";
    if (!isEd25519Pub(target)) throw bad(400, "target_pubkey malformed");
    if (!this.db.agentByPubkey(target)) throw bad(404, "no such agent");
    this.db.revoke(target, reason);
    return { ok: true, revoked: target };
  }
}
