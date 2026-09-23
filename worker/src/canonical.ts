/** Canonical JSON (spec section 4.1), byte-identical to the Python reference.
 *
 * - Keys sorted by code point, which equals byte-wise UTF-8 order.
 * - No whitespace. Integers only. `null` allowed, distinct from absent.
 * - JSON.stringify escapes exactly the set Python's json.dumps(ensure_ascii=False)
 *   escapes (`"`, `\`, U+0000..U+001F). Lone surrogates are rejected, where
 *   Python fails at .encode("utf-8").
 */
export class CanonicalError extends Error {}

function cmpCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done && y.done) return 0;
    if (x.done) return -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx - cy;
  }
}

function str(s: string, path: string): string {
  if (!s.isWellFormed()) throw new CanonicalError(`${path}: string is not valid Unicode`);
  return JSON.stringify(s);
}

export function canonicalString(value: unknown, path = "$"): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return str(value, path);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new CanonicalError(`${path}: floats are not allowed in canonical JSON`);
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map((v, i) => canonicalString(v, `${path}[${i}]`)).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(cmpCodePoints);
    return "{" + keys.map((k) => str(k, path) + ":" + canonicalString(obj[k], `${path}.${k}`)).join(",") + "}";
  }
  throw new CanonicalError(`${path}: unsupported type ${typeof value}`);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalString(value));
}
