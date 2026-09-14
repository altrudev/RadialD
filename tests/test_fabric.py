import unittest

from radiald.fabric import (
    EvidenceEnvelope,
    EvidencePolicy,
    analyze_assurance_fabric,
    bind_evidence,
    contradiction_signals,
)
from radiald.receipt import (
    make_assurance_receipt,
    seal_assurance_receipt,
    verify_assurance_receipt,
)
from radiald.weaklink import SafeAutonomy, WeakLinkSignal, WeakLinkStatus


def d(ch):
    return "sha256:" + ch * 64


def env(source, action, *, scope="preflight", resource="r1"):
    return EvidenceEnvelope(
        source=source,
        artifact_digest=d("a"),
        verifier_id="verifier:" + source,
        trust_anchor_fingerprint=d("b"),
        verified_at="2026-09-14T06:00:00Z",
        freshness_scope=scope,
        disposition="VERIFIED",
        bindings={
            "action_digest": action,
            "resource_id": resource,
            "policy_digest": d("c"),
        },
        attestation_digest=d("d"),
    )


class FabricTests(unittest.TestCase):
    def test_matching_evidence_binds(self):
        report = bind_evidence(
            [env("receipt", d("1")), env("dsr", d("1"))],
            required_fields=("action_digest", "resource_id", "policy_digest"),
        )
        self.assertTrue(report.consistent)

    def test_individually_valid_mixed_actions_never_compose(self):
        envelopes = [
            env("receipt", d("1")),
            env("physical", d("2")),
            env("dsr", d("3")),
            env("renderdiff", d("4")),
            env("transition", d("5")),
        ]
        result = analyze_assurance_fabric(
            envelopes=envelopes,
            producer_signals=(),
            policy=EvidencePolicy(
                policy_id="physical:v1",
                action_class="physical",
                required_sources=(
                    "receipt", "physical", "dsr", "renderdiff", "transition"
                ),
                required_binding_fields=(
                    "action_digest", "resource_id", "policy_digest"
                ),
                require_preflight=True,
                max_preflight_age_seconds=120,
            ),
            now="2026-09-14T06:00:30Z",
        )
        self.assertFalse(result.binding.consistent)
        self.assertEqual(
            result.report.bounding_link.name,
            "cross_evidence_binding",
        )
        self.assertEqual(
            result.report.maximum_safe_autonomy,
            SafeAutonomy.HUMAN_REQUIRED,
        )

    def test_missing_required_source_fails_closed(self):
        result = analyze_assurance_fabric(
            envelopes=[env("receipt", d("1"))],
            producer_signals=(),
            policy=EvidencePolicy(
                policy_id="remote:v1",
                action_class="remote",
                required_sources=("receipt", "dsr"),
                required_binding_fields=("action_digest",),
            ),
            now="2026-09-14T06:00:30Z",
        )
        names = {signal.name: signal for signal in result.report.links}
        self.assertEqual(
            names["required_evidence:dsr"].status,
            WeakLinkStatus.UNRESOLVED,
        )

    def test_stale_preflight_evidence_fails_closed(self):
        result = analyze_assurance_fabric(
            envelopes=[env("receipt", d("1"))],
            producer_signals=(),
            policy=EvidencePolicy(
                policy_id="p",
                action_class="test",
                required_binding_fields=("action_digest",),
                require_preflight=True,
                max_preflight_age_seconds=10,
            ),
            now="2026-09-14T06:01:00Z",
        )
        names = {signal.name: signal for signal in result.report.links}
        self.assertEqual(
            names["evidence_freshness"].status,
            WeakLinkStatus.UNRESOLVED,
        )

    def test_closed_and_unresolved_same_signal_creates_contradiction(self):
        signals = contradiction_signals([
            WeakLinkSignal("authority", 1, 1, WeakLinkStatus.CLOSED),
            WeakLinkSignal("authority", 1, 1, WeakLinkStatus.UNRESOLVED),
        ])
        self.assertEqual(len(signals), 1)
        self.assertEqual(
            signals[0].name,
            "evidence_contradiction:authority",
        )

    def test_receipt_is_tamper_evident_and_sealable(self):
        result = analyze_assurance_fabric(
            envelopes=[env("receipt", d("1"))],
            producer_signals=(),
            policy=EvidencePolicy(
                policy_id="p",
                action_class="test",
                required_sources=("receipt",),
                required_binding_fields=("action_digest",),
            ),
            now="2026-09-14T06:00:30Z",
        )
        receipt = make_assurance_receipt(
            result,
            receipt_id="r1",
            issued_at="2026-09-14T06:00:31Z",
        )
        self.assertTrue(verify_assurance_receipt(receipt))
        tampered = dict(receipt)
        tampered["system_assurance"] = 1.0
        self.assertFalse(verify_assurance_receipt(tampered))
        sealed = seal_assurance_receipt(
            receipt,
            signer=lambda payload: b"sig:" + payload[:8],
            key_id="external:test",
            algorithm="test-only",
        )
        self.assertIn("seal", sealed)


if __name__ == "__main__":
    unittest.main()
