from __future__ import annotations

import base64
import json
import math
from hashlib import sha256
from typing import Any


class CanonicalizationError(TypeError):
    """Raised when a value cannot be represented without ambiguity."""


def _canonical(value: Any, stack: set[int]) -> object:
    if value is None:
        return ["none"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite floats are not supported")
        return ["float", value.hex()]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, bytes):
        return ["bytes", base64.b64encode(value).decode("ascii")]

    if isinstance(value, (list, tuple, dict, set, frozenset)):
        ident = id(value)
        if ident in stack:
            raise CanonicalizationError("cyclic values are not supported")
        stack.add(ident)
        try:
            if isinstance(value, list):
                return ["list", [_canonical(item, stack) for item in value]]
            if isinstance(value, tuple):
                return ["tuple", [_canonical(item, stack) for item in value]]
            if isinstance(value, dict):
                entries = []
                for key, item in value.items():
                    ckey = _canonical(key, stack)
                    cvalue = _canonical(item, stack)
                    key_sort = json.dumps(
                        ckey, ensure_ascii=False, separators=(",", ":")
                    )
                    entries.append((key_sort, ckey, cvalue))
                entries.sort(key=lambda row: row[0])
                return ["dict", [[key, item] for _, key, item in entries]]
            tag = "set" if isinstance(value, set) else "frozenset"
            encoded = [_canonical(item, stack) for item in value]
            encoded.sort(
                key=lambda item: json.dumps(
                    item, ensure_ascii=False, separators=(",", ":")
                )
            )
            return [tag, encoded]
        finally:
            stack.remove(ident)

    raise CanonicalizationError(
        f"unsupported value type for canonical fingerprint: "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


def canonical_bytes(value: object) -> bytes:
    """Return a deterministic, type-preserving representation.

    Unsupported or cyclic values fail closed instead of falling back to repr(),
    which can be ambiguous, process-specific, or state-incomplete.
    """
    canonical = _canonical(value, set())
    return json.dumps(
        canonical, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def stable_digest(value: object) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def typed_identity(value: object) -> str:
    """Stable identity token preserving representation distinctions."""
    return stable_digest(["radiald-identity-v1", value])
