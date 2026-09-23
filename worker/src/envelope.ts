/** Envelope validation and verification (spec section 4.2). */
import { canonicalBytes } from "./canonical";
import { isEd25519Pub, verify } from "./crypto";

export const PROTOCOL = "switchboard";
export const VERSION = "0.2";
export const DEFAULT_TTL_SECONDS = 7 * 24 * 3600;
export const MAX_ENVELOPE_BYTES = 256 * 1024;
export const MAX_POST_TEXT_BYTES = 8 * 1024;
export const CLOCK_SKEW_SECONDS = 300;

export const HANDLE_RE = /^[a-z0-9-]{3,32}$/;
export const CHANNEL_RE = /^channel:[a-z0-9-]{1,32}$/;
const ULID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export const CHANNEL_TYPES = new Set(["announce", "post", "shout"]);
export const ENCRYPTED_TYPES = new Set([
  "dm", "capability_query", "capability_response",
  "task_request", "task_accept", "task_decline", "task_counter", "task_update",
  "task_question", "task_answer", "task_result", "task_failed", "task_cancel",
]);
export const RELAY_RECORD_TYPES = new Set(["task_rate", "vouch", "vouch_revoke", "rotation"]);
export const ALL_TYPES = new Set([...CHANNEL_TYPES, ...ENCRYPTED_TYPES, ...RELAY_RECORD_TYPES]);

export class EnvelopeError extends Error {}

export function isUlid(text: unknown): text is string {
  return typeof text === "string" && ULID_RE.test(text);
}

export function nowIso(now = new Date()): string {
  return now.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Accept exactly YYYY-MM-DDTHH:MM:SSZ and only real calendar instants. */
export function parseIso(text: unknown): Date {
  if (typeof text !== "string" || !ISO_RE.test(text)) throw new EnvelopeError("timestamp must be YYYY-MM-DDTHH:MM:SSZ");
  const d = new Date(text);
  if (Number.isNaN(d.getTime()) || nowIso(d) !== text) throw new EnvelopeError(`bad timestamp: ${text}`);
  return d;
}

export function isSealed(payload: unknown): boolean {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return false;
  const keys = Object.keys(payload).sort();
  return keys.length === 3 && keys[0] === "ciphertext" && keys[1] === "ephem_pub" && keys[2] === "nonce";
}

export type Envelope = {
  protocol: string; version: string; id: string; type: string;
  from: { handle: string; pubkey: string }; to: string; timestamp: string;
  ttl_seconds: number; payload: Record<string, unknown>; signature: string;
};

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function signingBytes(env: Record<string, unknown>): Uint8Array {
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(env)) if (k !== "signature") body[k] = v;
  return canonicalBytes(body);
}

/** Structural checks that do not need the network. Throws EnvelopeError. */
export function validateShape(env: unknown): asserts env is Envelope {
  if (!isObj(env)) throw new EnvelopeError("envelope must be an object");
  for (const key of ["protocol", "version", "id", "type", "from", "to", "timestamp", "ttl_seconds", "payload", "signature"]) {
    if (!(key in env)) throw new EnvelopeError(`missing field '${key}'`);
  }
  if (env.protocol !== PROTOCOL) throw new EnvelopeError("wrong protocol");
  if (env.version !== VERSION) throw new EnvelopeError(`unsupported version ${JSON.stringify(env.version)}`);
  if (!isUlid(env.id)) throw new EnvelopeError("id must be a ULID");
  const type = env.type;
  if (typeof type !== "string" || !ALL_TYPES.has(type)) throw new EnvelopeError(`unknown type ${JSON.stringify(type)}`);
  const frm = env.from;
  if (!isObj(frm) || Object.keys(frm).sort().join(",") !== "handle,pubkey") throw new EnvelopeError("from must be {handle, pubkey}");
  if (!HANDLE_RE.test(String(frm.handle))) throw new EnvelopeError("from.handle is malformed");
  if (!isEd25519Pub(frm.pubkey)) throw new EnvelopeError("from.pubkey is malformed");
  const to = String(env.to);
  if (!(isEd25519Pub(env.to) || CHANNEL_RE.test(to))) throw new EnvelopeError("to must be an ed25519 pubkey or channel:<name>");
  if (CHANNEL_TYPES.has(type) && !to.startsWith("channel:")) throw new EnvelopeError(`${type} must be addressed to a channel`);
  if (!CHANNEL_TYPES.has(type) && to.startsWith("channel:")) throw new EnvelopeError(`${type} cannot be addressed to a channel`);
  const ttl = env.ttl_seconds;
  if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl <= 0) throw new EnvelopeError("ttl_seconds must be a positive integer");
  parseIso(env.timestamp);
  if (!isObj(env.payload)) throw new EnvelopeError("payload must be an object");
  if (ENCRYPTED_TYPES.has(type) && !isSealed(env.payload)) throw new EnvelopeError(`${type} payload must be a sealed box`);
  if (type === "post") {
    const text = (env.payload as Record<string, unknown>).text ?? "";
    if (typeof text !== "string" || new TextEncoder().encode(text).length > MAX_POST_TEXT_BYTES) throw new EnvelopeError("post text missing or over 8 KB");
  }
  if (canonicalBytes(env).length > MAX_ENVELOPE_BYTES) throw new EnvelopeError("envelope over 256 KB");
}

/** Validate shape and signature, optionally clock skew. Throws EnvelopeError or CanonicalError. */
export async function verifyEnvelope(env: unknown, checkSkew = false, now = new Date()): Promise<Envelope> {
  validateShape(env);
  if (!(await verify(env.from.pubkey, signingBytes(env), env.signature))) throw new EnvelopeError("bad signature");
  if (checkSkew) {
    const ts = parseIso(env.timestamp);
    if (Math.abs(now.getTime() - ts.getTime()) / 1000 > CLOCK_SKEW_SECONDS) throw new EnvelopeError("timestamp outside allowed clock skew");
  }
  return env;
}
