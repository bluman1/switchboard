/** Signed relay requests (spec section 5, "Request signing"). */
import { canonicalBytes } from "./canonical";
import { bytesToHex, isEd25519Pub, sha256, verify } from "./crypto";
import { CLOCK_SKEW_SECONDS, parseIso } from "./envelope";

export const HEADER_PUBKEY = "X-Switchboard-Pubkey";
export const HEADER_TIMESTAMP = "X-Switchboard-Timestamp";
export const HEADER_NONCE = "X-Switchboard-Nonce";
export const HEADER_SIGNATURE = "X-Switchboard-Signature";

export class RequestAuthError extends Error {}

export async function signingPayload(relayPubkey: string, method: string, path: string, query: string, timestamp: string, nonce: string, body: Uint8Array): Promise<Uint8Array> {
  return canonicalBytes({
    relay: relayPubkey,
    method: method.toUpperCase(),
    path,
    query: query || "",
    timestamp,
    nonce,
    body_sha256: bytesToHex(await sha256(body)),
  });
}

/** Returns {pubkey, signature} or throws. The caller rejects signatures it has seen before. */
export async function verifyRequest(headers: Headers, relayPubkey: string, method: string, path: string, query: string, body: Uint8Array, now = new Date()): Promise<{ pubkey: string; signature: string }> {
  const pubkey = headers.get(HEADER_PUBKEY);
  const ts = headers.get(HEADER_TIMESTAMP);
  const nonce = headers.get(HEADER_NONCE);
  const sig = headers.get(HEADER_SIGNATURE);
  if (!(pubkey && ts && sig && nonce)) throw new RequestAuthError("missing signature headers");
  if (nonce.length > 64) throw new RequestAuthError("nonce too long");
  if (!isEd25519Pub(pubkey)) throw new RequestAuthError("malformed pubkey header");
  let when: Date;
  try {
    when = parseIso(ts);
  } catch (exc) {
    throw new RequestAuthError((exc as Error).message);
  }
  if (Math.abs(now.getTime() - when.getTime()) / 1000 > CLOCK_SKEW_SECONDS) throw new RequestAuthError("request timestamp outside allowed skew");
  if (!(await verify(pubkey, await signingPayload(relayPubkey, method, path, query, ts, nonce, body), sig))) throw new RequestAuthError("bad request signature");
  return { pubkey, signature: sig };
}
