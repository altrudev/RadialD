from __future__ import annotations

import base64
import json
import math
from hashlib import sha256
from typing import Any


class CanonicalizationError(TypeError):
    """Raised when a value cannot be represented without ambiguity."""


def _canonical(value: Any, stack: set[int]) -> object:
    value_type = type(value)

    if value is None:
        return ["none"]
    if value_type is bool:
        return ["bool", value]
    if value_type is int:
        return ["int", str(value)]
    if value_type is float:
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite floats are not supported")
        return ["float", value.hex()]
    if value_type is str:
        return ["str", value]
    if value_type is bytes:
        return ["bytes", base64.b64encode(value).decode("ascii")]

    if value_type in (list, tuple, dict, set, frozenset):
        ident = id(value)
        if ident in stack:
            raise CanonicalizationError("cyclic values are not supported")
        stack.add(ident)
        try:
            if value_type is list:
                return ["list", [_canonical(item, stack) for item in value]]
            if value_type is tuple:
                return ["tuple", [_canonical(item, stack) for item in value]]
            if value_type is dict:
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
            tag = "set" if value_type is set else "frozenset"
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
        f"{value_type.__module__}.{value_type.__qualname__}"
    )


def canonical_bytes(value: object) -> bytes:
    """Return a deterministic, type-preserving representation.

    Only exact supported built-in types are accepted. Unsupported or cyclic
    values fail closed instead of falling back to repr(), which can be
    ambiguous, process-specific, state-incomplete, or equality-confused.
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
