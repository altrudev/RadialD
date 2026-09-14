from __future__ import annotations

import base64
from collections.abc import Callable, Mapping

from .canonical import stable_digest
from .receipt import verify_assurance_receipt


def verify_assurance_seal(
    receipt: Mapping[str, object],
    *,
    verifier: Callable[[bytes, bytes, str, str], bool],
) -> bool:
    if not verify_assurance_receipt(receipt):
        return False
    seal = receipt.get("seal")
    if not isinstance(seal, Mapping):
        return False

    algorithm = seal.get("algorithm")
    key_id = seal.get("key_id")
    payload_digest = seal.get("signed_payload_digest")
    signature_b64 = seal.get("signature_b64")
    values = (algorithm, key_id, payload_digest, signature_b64)
    if not all(isinstance(value, str) and value for value in values):
        return False

    unsigned = dict(receipt)
    unsigned.pop("seal", None)
    receipt_digest = unsigned.get("receipt_digest")
    if not isinstance(receipt_digest, str):
        return False
    seal_payload = {
        "receipt_digest": receipt_digest,
        "algorithm": algorithm,
        "key_id": key_id,
    }
    expected = "sha256:" + stable_digest(seal_payload)
    if payload_digest != expected:
        return False

    try:
        signature = base64.b64decode(signature_b64, validate=True)
        return bool(verifier(
            payload_digest.encode("ascii"),
            signature,
            key_id,
            algorithm,
        ))
    except Exception:
        return False
