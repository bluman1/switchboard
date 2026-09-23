"""Trust tier ordering (spec section 3). Shared by relay and client."""

TIER_ORDER = {"T0": 0, "T1": 1, "T2": 2}


def tier_at_least(tier: str, minimum: str) -> bool:
    """False for any unknown tier string on either side: fail closed."""
    return TIER_ORDER.get(tier, -1) >= TIER_ORDER.get(minimum, 99)
