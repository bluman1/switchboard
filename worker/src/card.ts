/** Capability cards (spec section 6.1). Validation only; the relay never evaluates schemas. */
export class CardError extends Error {}

const CAP_NAME_RE = /^[a-z0-9-]{2,48}$/;
const SCALARS = new Set(["string", "integer", "boolean", "url", "object"]);

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function checkTypeExpr(expr: unknown, path: string): void {
  if (typeof expr === "string") {
    if (SCALARS.has(expr) || (expr.includes("|") && expr.split("|").every((p) => p.length > 0))) return;
    throw new CardError(`${path}: unknown type ${JSON.stringify(expr)}`);
  }
  if (Array.isArray(expr) && expr.length === 1) {
    checkTypeExpr(expr[0], path + "[]");
    return;
  }
  throw new CardError(`${path}: unsupported type expression`);
}

export function validateSchema(schema: unknown, path: string): void {
  if (!isObj(schema)) throw new CardError(`${path}: schema must be an object`);
  for (const [key, expr] of Object.entries(schema)) {
    if (!key) throw new CardError(`${path}: schema keys must be non-empty strings`);
    checkTypeExpr(expr, `${path}.${key}`);
  }
}

export function validateCard(card: unknown): asserts card is Record<string, unknown> {
  if (!isObj(card)) throw new CardError("card must be an object");
  const caps = card.capabilities;
  if (!Array.isArray(caps)) throw new CardError("card.capabilities must be a list");
  const names = new Set<string>();
  caps.forEach((cap, i) => {
    const p = `capabilities[${i}]`;
    if (!isObj(cap)) throw new CardError(`${p}: must be an object`);
    const name = cap.name;
    if (typeof name !== "string" || !CAP_NAME_RE.test(name)) throw new CardError(`${p}.name: must match ${CAP_NAME_RE.source}`);
    if (names.has(name)) throw new CardError(`${p}.name: duplicate capability ${JSON.stringify(name)}`);
    names.add(name);
    if (typeof cap.description !== "string") throw new CardError(`${p}.description: required string`);
    validateSchema(cap.input_schema ?? {}, `${p}.input_schema`);
    validateSchema(cap.output_schema ?? {}, `${p}.output_schema`);
    if ("constraints" in cap && !(Array.isArray(cap.constraints) && cap.constraints.every((c) => typeof c === "string"))) throw new CardError(`${p}.constraints: must be strings`);
  });
  if ("constraints" in card && !(Array.isArray(card.constraints) && card.constraints.every((c) => typeof c === "string"))) throw new CardError("card.constraints must be strings");
}

export function capabilityNames(card: Record<string, unknown>): { name: string; description: string }[] {
  const caps = Array.isArray(card.capabilities) ? card.capabilities : [];
  return caps.filter(isObj).map((c) => ({ name: String(c.name ?? ""), description: String(c.description ?? "") }));
}
