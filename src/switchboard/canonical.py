"""Canonical JSON (spec section 4.1).

Signatures must verify across implementations, so the signed bytes are
defined exactly:

- UTF-8, no BOM.
- Object keys sorted byte-wise by their UTF-8 encoding.
- No insignificant whitespace.
- Integers only on the wire. Floats are rejected; decimal amounts are strings.
- ``null`` is allowed. Absent and null are different.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalError(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed in canonical JSON")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"{path}: object keys must be strings")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of ``value``.

    Python's ``sort_keys`` orders keys by code point, which is identical to
    byte-wise UTF-8 order, so this satisfies the spec.
    """
    _check(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_str(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")
