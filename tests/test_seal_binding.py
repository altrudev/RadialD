import unittest

from radiald.fabric import EvidenceEnvelope, EvidencePolicy, analyze_assurance_fabric
from radiald.receipt import make_assurance_receipt, seal_assurance_receipt
from radiald.seal import verify_assurance_seal


def d(ch):
    return "sha256:" + ch * 64


class SealBindingTests(unittest.TestCase):
    def test_key_metadata_substitution_is_rejected(self):
        envelope = EvidenceEnvelope.create(
            source="receipt",
            source_schema="receipt/1",
            artifact_digest=d("a"),
            verifier_id="verifier:receipt",
            trust_anchor_fingerprint=d("b"),
            verified_at="2026-09-14T06:00:00Z",
            freshness_scope="preflight",
            disposition="VERIFIED",
            bindings={"action_digest": d("1")},
        )
        result = analyze_assurance_fabric(
            envelopes=[envelope],
            producer_signals=(),
            policy=EvidencePolicy(
                policy_id="p",
                action_class="test",
                required_sources=("receipt",),
                required_binding_fields=("action_digest",),
            ),
            now="2026-09-14T06:00:30Z",
            verifier=lambda value: True,
        )
        receipt = make_assurance_receipt(
            result,
            receipt_id="r1",
            issued_at="2026-09-14T06:00:31Z",
        )
        sealed = seal_assurance_receipt(
            receipt,
            signer=lambda payload: b"sig:" + payload[:8],
            key_id="external:test",
            algorithm="test-only",
        )
        self.assertTrue(verify_assurance_seal(
            sealed,
            verifier=lambda payload, signature, key_id, algorithm: (
                key_id == "external:test"
                and algorithm == "test-only"
                and signature == b"sig:" + payload[:8]
            ),
        ))
        swapped = dict(sealed)
        swapped["seal"] = dict(sealed["seal"])
        swapped["seal"]["key_id"] = "external:other"
        self.assertFalse(verify_assurance_seal(
            swapped,
            verifier=lambda payload, signature, key_id, algorithm: True,
        ))


if __name__ == "__main__":
    unittest.main()
