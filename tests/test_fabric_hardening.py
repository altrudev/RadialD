import unittest

from radiald.fabric import EvidenceEnvelope, EvidencePolicy, analyze_assurance_fabric
from radiald.weaklink import WeakLinkStatus


def d(ch):
    return "sha256:" + ch * 64


def env():
    return EvidenceEnvelope(
        source="receipt",
        source_schema="receipt/1",
        artifact_digest=d("a"),
        verifier_id="verifier:receipt",
        trust_anchor_fingerprint=d("b"),
        verified_at="2026-09-14T06:00:00Z",
        freshness_scope="preflight",
        disposition="VERIFIED",
        bindings={"action_digest": d("1")},
        attestation_digest=d("d"),
    )


class FabricTrustHardeningTests(unittest.TestCase):
    def test_bindings_are_immutable_snapshot(self):
        bindings = {"action_digest": d("1")}
        envelope = EvidenceEnvelope(
            source="receipt",
            source_schema="receipt/1",
            artifact_digest=d("a"),
            verifier_id="verifier:receipt",
            trust_anchor_fingerprint=d("b"),
            verified_at="2026-09-14T06:00:00Z",
            freshness_scope="preflight",
            disposition="VERIFIED",
            bindings=bindings,
            attestation_digest=d("d"),
        )
        bindings["action_digest"] = d("2")
        self.assertEqual(envelope.bindings["action_digest"], d("1"))
        with self.assertRaises(TypeError):
            envelope.bindings["action_digest"] = d("3")

    def test_verifier_runs_once_per_envelope(self):
        calls = 0

        def verifier(envelope):
            nonlocal calls
            calls += 1
            return True

        analyze_assurance_fabric(
            envelopes=[env()],
            producer_signals=(),
            policy=EvidencePolicy(
                policy_id="p",
                action_class="test",
                required_sources=("receipt",),
                required_binding_fields=("action_digest",),
                require_preflight=True,
                preflight_sources=("receipt",),
            ),
            now="2026-09-14T06:00:30Z",
            verifier=verifier,
        )
        self.assertEqual(calls, 1)

    def test_budget_bounds_generator_consumption(self):
        produced = 0

        def stream():
            nonlocal produced
            for _ in range(1000):
                produced += 1
                yield env()

        result = analyze_assurance_fabric(
            envelopes=stream(),
            producer_signals=(),
            policy=EvidencePolicy(
                policy_id="p",
                action_class="test",
                required_sources=("receipt",),
                required_binding_fields=("action_digest",),
                max_envelopes=3,
            ),
            now="2026-09-14T06:00:30Z",
            verifier=lambda envelope: True,
        )
        by_name = {signal.name: signal for signal in result.report.links}
        self.assertEqual(produced, 4)
        self.assertTrue(result.binding.budget_exceeded)
        self.assertEqual(
            by_name["evidence_budget"].status,
            WeakLinkStatus.UNRESOLVED,
        )


if __name__ == "__main__":
    unittest.main()
