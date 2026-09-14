from __future__ import annotations

import base64
from collections.abc import Callable, Mapping

from .canonical import stable_digest
from .fabric import AssuranceFabricResult


def make_assurance_receipt(
    result: AssuranceFabricResult,
    *,
    receipt_id: str,
    issued_at: str,
    adapter_version: str = "assurance-fabric-v1",
) -> dict[str, object]:
    if not receipt_id.strip():
        raise ValueError("receipt_id required")
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
    payload["receipt_digest"] = "sha256:" + stable_digest(payload)
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
    payload_digest = "sha256:" + stable_digest(unsigned)
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
