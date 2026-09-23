export const TIER_ORDER: Record<string, number> = { T0: 0, T1: 1, T2: 2 };

/** False for any unknown tier string on either side: fail closed. */
export function tierAtLeast(tier: string, minimum: string): boolean {
  return (TIER_ORDER[tier] ?? -1) >= (TIER_ORDER[minimum] ?? 99);
}
