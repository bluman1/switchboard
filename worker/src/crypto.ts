/** Key encodings, base64, SHA-256, Ed25519 verification via WebCrypto. */
export class CryptoError extends Error {}

export const ED25519_PREFIX = "ed25519:";
export const X25519_PREFIX = "x25519:";
const HEX64 = /^[0-9a-f]{64}$/;

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function decodePrefixed(text: unknown, prefix: string): Uint8Array {
  if (typeof text !== "string" || !text.startsWith(prefix)) throw new CryptoError(`expected key with prefix ${prefix}`);
  const hex = text.slice(prefix.length);
  if (!HEX64.test(hex)) throw new CryptoError("key must be 64 lowercase hex chars");
  return hexToBytes(hex);
}

export function isEd25519Pub(text: unknown): text is string {
  try {
    decodePrefixed(text, ED25519_PREFIX);
    return true;
  } catch {
    return false;
  }
}

export function isX25519Pub(text: unknown): text is string {
  try {
    decodePrefixed(text, X25519_PREFIX);
    return true;
  } catch {
    return false;
  }
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

export function b64d(text: unknown): Uint8Array {
  if (typeof text !== "string" || text.length % 4 !== 0 || !B64.test(text)) throw new CryptoError("invalid base64");
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64e(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

const keyCache = new Map<string, CryptoKey>();

async function importVerifyKey(pubkey: string): Promise<CryptoKey> {
  const cached = keyCache.get(pubkey);
  if (cached) return cached;
  const raw = decodePrefixed(pubkey, ED25519_PREFIX);
  const key = await crypto.subtle.importKey("raw", raw as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  if (keyCache.size > 4096) keyCache.clear();
  keyCache.set(pubkey, key);
  return key;
}

/** Ed25519 verify. False for any malformed input, never throws. */
export async function verify(pubkey: string, message: Uint8Array, signatureB64: unknown): Promise<boolean> {
  try {
    const sig = b64d(signatureB64);
    if (sig.length !== 64) return false;
    const key = await importVerifyKey(pubkey);
    return await crypto.subtle.verify("Ed25519", key, sig as BufferSource, message as BufferSource);
  } catch {
    return false;
  }
}

/** Spec 2.3: first 8 bytes of SHA-256 of the raw key, colon-separated hex. */
export async function fingerprint(pubkey: string): Promise<string> {
  const digest = await sha256(decodePrefixed(pubkey, ED25519_PREFIX));
  return Array.from(digest.subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join(":");
}

export interface RelayKeys {
  ed25519_pub: string;
  x25519_pub: string;
  ed25519_pkcs8_b64: string;
}

/** The relay's own keys. It never signs anything in v0.2; the private key is kept for later. */
export async function generateRelayKeys(): Promise<RelayKeys> {
  const ed = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const x = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const edPub = new Uint8Array((await crypto.subtle.exportKey("raw", ed.publicKey)) as ArrayBuffer);
  const xPub = new Uint8Array((await crypto.subtle.exportKey("raw", x.publicKey)) as ArrayBuffer);
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", ed.privateKey)) as ArrayBuffer);
  return { ed25519_pub: ED25519_PREFIX + bytesToHex(edPub), x25519_pub: X25519_PREFIX + bytesToHex(xPub), ed25519_pkcs8_b64: b64e(pkcs8) };
}
