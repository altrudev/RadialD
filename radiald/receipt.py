from __future__ import annotations

import base64
from collections.abc import Callable, Mapping

from .canonical import stable_digest
from .fabric import AssuranceFabricResult, _utc


def _json_stable(value: object) -> object:
    """Map a receipt to the form it has after any JSON round-trip.

    JSON has one number type, so JavaScript (and most other JSON libraries)
    write 1.0 as 1, and tuples come back as lists. Receipts are meant to
    travel through DDC Platform and browsers, so they are digested in this
    JSON-stable form: integral floats become ints and tuples become lists.
    Non-integral floats are kept exactly (float.hex) by canonical_bytes.
    """
    if type(value) is float and value.is_integer():
        return int(value)
    if isinstance(value, (list, tuple)):
        return [_json_stable(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _json_stable(item) for key, item in value.items()}
    return value


def _receipt_digest(unsigned: Mapping[str, object]) -> str:
    return "sha256:" + stable_digest(_json_stable(dict(unsigned)))


def make_assurance_receipt(
    result: AssuranceFabricResult,
    *,
    receipt_id: str,
    issued_at: str,
    adapter_version: str = "assurance-fabric-v1",
) -> dict[str, object]:
    if not receipt_id.strip() or len(receipt_id) > 256:
        raise ValueError("receipt_id required and must be <=256 chars")
    _utc(issued_at)
    bounding = result.report.bounding_link
    payload: dict[str, object] = {
        "schema": "radiald-assurance-receipt/1",
        "receipt_id": receipt_id,
        "issued_at": issued_at,
        "adapter_version": adapter_version,
        "policy_digest": result.policy_digest,
        "evidence_fingerprints": list(result.envelope_fingerprints),
        "binding": {
            "consistent": result.binding.consistent,
            "resolved": dict(result.binding.resolved),
            "conflicts": {k: list(v) for k, v in result.binding.conflicts.items()},
            "missing": list(result.binding.missing),
        },
        "system_assurance": result.report.system_assurance,
        "maximum_safe_autonomy": result.report.maximum_safe_autonomy.value,
        "bounding_link": None if bounding is None else {
            "name": bounding.name,
            "status": bounding.status.value,
            "severity": bounding.severity,
            "confidence": bounding.confidence,
            "residual_risk": bounding.residual_risk,
        },
        "signal_count": len(result.report.links),
    }
    payload["receipt_digest"] = _receipt_digest(payload)
    return payload


def verify_assurance_receipt(receipt: Mapping[str, object]) -> bool:
    if receipt.get("schema") != "radiald-assurance-receipt/1":
        return False
    expected = receipt.get("receipt_digest")
    if not isinstance(expected, str):
        return False
    unsigned = dict(receipt)
    unsigned.pop("seal", None)
    unsigned.pop("receipt_digest", None)
    if expected == _receipt_digest(unsigned):
        return True
    # Receipts issued before the JSON-stable digest (radiald <= 0.4) hashed
    # the raw Python values. They still verify while carried unchanged.
    return expected == "sha256:" + stable_digest(unsigned)


def seal_assurance_receipt(
    receipt: Mapping[str, object],
    *,
    signer: Callable[[bytes], bytes],
    key_id: str,
    algorithm: str,
) -> dict[str, object]:
    if not verify_assurance_receipt(receipt):
        raise ValueError("receipt integrity check failed")
    if not key_id.strip() or not algorithm.strip():
        raise ValueError("key_id and algorithm required")
    unsigned = dict(receipt)
    unsigned.pop("seal", None)
    seal_payload = {
        "receipt_digest": unsigned["receipt_digest"],
        "algorithm": algorithm,
        "key_id": key_id,
    }
    payload_digest = "sha256:" + stable_digest(seal_payload)
    signature = signer(payload_digest.encode("ascii"))
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("signer must return signature bytes")
    sealed = dict(unsigned)
    sealed["seal"] = {
        "algorithm": algorithm,
        "key_id": key_id,
        "signed_payload_digest": payload_digest,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    return sealed
