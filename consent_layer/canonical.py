"""Canonical JSON serialization.

A signature is only meaningful if signer and verifier agree, byte for byte, on what
was signed. `json.dumps` does not give that guarantee: key order, whitespace and
float formatting all vary. So every signed structure is serialized through here.

Rules (a deliberately small subset of RFC 8785 / JCS):
  * object keys sorted by Unicode code point
  * no insignificant whitespace
  * UTF-8, no ASCII escaping
  * floats are rejected outright -- money is integers-or-Decimal-shaped, and
    float formatting is the classic canonicalization footgun
  * NaN/Infinity rejected
"""

from __future__ import annotations

import json
import math
from typing import Any

# Prefixed onto every payload before signing so a signature minted for one kind of
# object can never be replayed as another (domain separation).
GRANT_DOMAIN = b"consent-layer/sdl/1/grant\x00"


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented canonically."""


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(f"non-finite float at {path}")
        raise CanonicalizationError(
            f"float at {path}: use int (minor units) or a decimal string, "
            "floats are not canonically representable"
        )
    if isinstance(value, dict):
        for key, sub in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key at {path}: {key!r}")
            _check(sub, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, sub in enumerate(value):
            _check(sub, f"{path}[{index}]")
        return
    raise CanonicalizationError(f"unserializable type {type(value).__name__} at {path}")


def canonical_json(value: Any) -> bytes:
    """Serialize `value` to its one canonical byte representation."""
    _check(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def signing_payload(grant_body: dict[str, Any]) -> bytes:
    """Bytes that get signed for a grant: domain tag + canonical body.

    `grant_body` must already have the `signature` field stripped -- a signature
    cannot cover itself.
    """
    if "signature" in grant_body:
        raise CanonicalizationError("strip `signature` before building signing payload")
    return GRANT_DOMAIN + canonical_json(grant_body)
