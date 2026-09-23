"""Capability cards (spec section 6.1) and the tiny schema language they use.

A card::

    {
      "capabilities": [
        {
          "name": "web-research",
          "version": "1.0",
          "description": "Answers research questions with cited sources.",
          "input_schema":  {"question": "string", "depth": "quick|standard|deep"},
          "output_schema": {"brief": "string", "sources": ["url"]},
          "constraints": ["no disallowed content"]
        }
      ],
      "constraints": ["polls every 10 min, not realtime"],
      "poll_interval_seconds": 600
    }

Schema language (deliberately small; a stranger's agent must be able to
validate an input before hiring):

- ``"string"``, ``"integer"``, ``"boolean"``, ``"url"``, ``"object"``
- ``"a|b|c"``: enum of strings
- ``["string"]`` / ``["url"]``: list of that type
- A key ending in ``?`` is optional.
"""

from __future__ import annotations

import re
from typing import Any

CAP_NAME_RE = re.compile(r"^[a-z0-9-]{2,48}$")
_SCALARS = {"string", "integer", "boolean", "url", "object"}


class CardError(ValueError):
    pass


def _check_type_expr(expr: Any, path: str) -> None:
    if isinstance(expr, str):
        if expr in _SCALARS or ("|" in expr and all(part for part in expr.split("|"))):
            return
        raise CardError(f"{path}: unknown type {expr!r}")
    if isinstance(expr, list) and len(expr) == 1:
        _check_type_expr(expr[0], path + "[]")
        return
    raise CardError(f"{path}: unsupported type expression")


def validate_schema(schema: Any, path: str) -> None:
    if not isinstance(schema, dict):
        raise CardError(f"{path}: schema must be an object")
    for key, expr in schema.items():
        if not isinstance(key, str) or not key:
            raise CardError(f"{path}: schema keys must be non-empty strings")
        _check_type_expr(expr, f"{path}.{key}")


def validate_card(card: Any) -> None:
    if not isinstance(card, dict):
        raise CardError("card must be an object")
    caps = card.get("capabilities")
    if not isinstance(caps, list):
        raise CardError("card.capabilities must be a list")
    names = set()
    for i, cap in enumerate(caps):
        p = f"capabilities[{i}]"
        if not isinstance(cap, dict):
            raise CardError(f"{p}: must be an object")
        name = cap.get("name")
        if not isinstance(name, str) or not CAP_NAME_RE.match(name):
            raise CardError(f"{p}.name: must match {CAP_NAME_RE.pattern}")
        if name in names:
            raise CardError(f"{p}.name: duplicate capability {name!r}")
        names.add(name)
        if not isinstance(cap.get("description"), str):
            raise CardError(f"{p}.description: required string")
        validate_schema(cap.get("input_schema", {}), f"{p}.input_schema")
        validate_schema(cap.get("output_schema", {}), f"{p}.output_schema")
        if "constraints" in cap and not all(isinstance(c, str) for c in cap["constraints"]):
            raise CardError(f"{p}.constraints: must be strings")
    if "constraints" in card and not all(isinstance(c, str) for c in card["constraints"]):
        raise CardError("card.constraints must be strings")


def _matches(expr: Any, value: Any) -> bool:
    if isinstance(expr, list):
        return isinstance(value, list) and all(_matches(expr[0], v) for v in value)
    if expr == "string":
        return isinstance(value, str)
    if expr == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expr == "boolean":
        return isinstance(value, bool)
    if expr == "url":
        return isinstance(value, str) and value.startswith(("http://", "https://"))
    if expr == "object":
        return isinstance(value, dict)
    if isinstance(expr, str) and "|" in expr:
        return isinstance(value, str) and value in expr.split("|")
    return False


def validate_value(schema: dict[str, Any], value: Any) -> list[str]:
    """Return a list of problems (empty means valid)."""
    problems: list[str] = []
    if not isinstance(value, dict):
        return ["value must be an object"]
    declared = {k[:-1] if k.endswith("?") else k for k in schema}
    for extra in sorted(set(value) - declared):
        problems.append(f"unexpected field {extra!r}")  # undeclared fields are the injection surface
    for key, expr in schema.items():
        optional = key.endswith("?")
        name = key[:-1] if optional else key
        if name not in value:
            if not optional:
                problems.append(f"missing field {name!r}")
            continue
        if not _matches(expr, value[name]):
            problems.append(f"field {name!r} does not match {expr!r}")
    return problems


def find_capability(card: dict[str, Any], name: str) -> dict[str, Any] | None:
    for cap in card.get("capabilities", []):
        if cap.get("name") == name:
            return cap
    return None
