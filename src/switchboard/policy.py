"""Standing policy and autonomy levels (spec section 9), v0.2 subset.

v0.2 carries no money, so the policy has no spend caps. What it decides:

- whether an inbound ``task_request`` is auto-accepted, declined, or surfaced
  to the human;
- whether an outbound ``task_request`` may be sent without confirmation;
- whether DMs from T0 identities are quarantined into the digest.

Hard rules that no policy can relax:

- ``task_request`` from a T0 identity is never auto-accepted (spec section 3).
- A request for a capability not on the card is declined.
- A request whose input fails the capability's ``input_schema`` is declined.
- An expired request is declined.
- An unknown autonomy level behaves as L1 (fail closed).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .card import find_capability, validate_value
from .envelope import EnvelopeError, parse_iso
from .tiers import tier_at_least

LEVELS = ("L1", "L2", "L3", "L4")

DEFAULT_POLICY: dict[str, Any] = {
    "autonomy": "L1",
    "auto_accept_inbound": [],
    "auto_approve_outbound": {"min_tier": "T1", "min_rating": "0"},
    "quarantine_t0_dms": True,
    "max_open_tasks": 5,
}


class PolicyError(ValueError):
    pass


def validate_policy(policy: Any) -> None:
    if not isinstance(policy, dict):
        raise PolicyError("policy must be an object")
    if policy.get("autonomy", "L1") not in LEVELS:
        raise PolicyError(f"autonomy must be one of {LEVELS}")
    rules = policy.get("auto_accept_inbound", [])
    if not isinstance(rules, list):
        raise PolicyError("auto_accept_inbound must be a list")
    for r in rules:
        if not isinstance(r, dict) or not isinstance(r.get("capability"), str):
            raise PolicyError("each auto_accept_inbound rule needs a capability string")
        if r.get("min_tier", "T1") not in ("T1", "T2"):
            raise PolicyError("auto_accept_inbound.min_tier must be T1 or T2 (T0 is never auto-accepted)")
    out = policy.get("auto_approve_outbound", {})
    if not isinstance(out, dict):
        raise PolicyError("auto_approve_outbound must be an object")
    if out.get("min_tier", "T1") not in ("T0", "T1", "T2"):
        raise PolicyError("auto_approve_outbound.min_tier must be T0, T1, or T2")
    try:
        float(out.get("min_rating", "0") or "0")
    except (TypeError, ValueError):
        raise PolicyError("auto_approve_outbound.min_rating must be a decimal string")
    mot = policy.get("max_open_tasks", 5)
    if not isinstance(mot, int) or isinstance(mot, bool) or mot < 0:
        raise PolicyError("max_open_tasks must be a non-negative integer")
    if not isinstance(policy.get("quarantine_t0_dms", True), bool):
        raise PolicyError("quarantine_t0_dms must be a boolean")


def _level(policy: dict[str, Any]) -> str:
    level = policy.get("autonomy", "L1")
    return level if level in LEVELS else "L1"


@dataclass
class Decision:
    action: str  # "accept" | "decline" | "ask" | "allow"
    reason: str

    @property
    def automatic(self) -> bool:
        return self.action in ("accept", "allow")


def decide_inbound_task(
    policy: dict[str, Any],
    card: dict[str, Any],
    sender_tier: str,
    sender_known: bool,
    payload: dict[str, Any],
    open_tasks: int = 0,
) -> Decision:
    cap_name = payload.get("capability")
    cap = find_capability(card, str(cap_name)) if cap_name else None
    if cap is None:
        return Decision("decline", f"capability {cap_name!r} is not on the card")
    problems = validate_value(cap.get("input_schema", {}), payload.get("input"))
    if problems:
        return Decision("decline", "input does not match input_schema: " + "; ".join(problems))
    expires = payload.get("expires_at")
    if expires is not None:
        try:
            if parse_iso(expires) < datetime.now(timezone.utc):
                return Decision("decline", f"request expired at {expires}")
        except EnvelopeError:
            return Decision("decline", "expires_at is malformed")
    if not tier_at_least(sender_tier, "T1"):
        return Decision("ask", "requests from T0 identities always need human approval")
    if open_tasks >= int(policy.get("max_open_tasks", 5)):
        return Decision("ask", "at max_open_tasks")
    level = _level(policy)
    if level == "L1":
        return Decision("ask", "autonomy L1: confirm everything")
    if level == "L3" and not sender_known:
        return Decision("ask", "autonomy L3: first contact with this counterparty")
    for rule in policy.get("auto_accept_inbound", []):
        if not isinstance(rule, dict) or rule.get("capability") not in (cap_name, "*"):
            continue
        if not tier_at_least(sender_tier, rule.get("min_tier", "T1")):
            continue
        return Decision("accept", f"matched auto_accept_inbound rule for {rule.get('capability')}")
    return Decision("ask", "no auto_accept_inbound rule matched")


def decide_outbound_task(policy: dict[str, Any], target_entry: dict[str, Any], capability: str) -> Decision:
    if _level(policy) == "L1":
        return Decision("ask", "autonomy L1: confirm everything")
    rule = policy.get("auto_approve_outbound") or {}
    tier = target_entry.get("tier", "T0")
    if not tier_at_least(tier, rule.get("min_tier", "T1")):
        return Decision("ask", f"counterparty is {tier}, below min_tier {rule.get('min_tier', 'T1')}")
    min_rating = float(rule.get("min_rating", "0") or "0")
    if min_rating > 0:
        summary = target_entry.get("rating_summary", {}).get(capability)
        if summary is None or float(summary["average"]) < min_rating:
            return Decision("ask", f"counterparty rating for {capability} is below {min_rating}")
    return Decision("allow", "within auto_approve_outbound")


def quarantine_dm(policy: dict[str, Any], sender_tier: str) -> bool:
    return bool(policy.get("quarantine_t0_dms", True)) and not tier_at_least(sender_tier, "T1")
