import unittest
from radiald.adapters import renderdiff_signals
from radiald.weaklink import WeakLinkStatus

class RenderDiffAdapterTests(unittest.TestCase):
    def test_missing_divergence_evidence_stays_unresolved(self):
        report = {"views": {"assurance": {"complete": False, "coverage": {}}}, "summary": {}}
        by_name = {s.name: s for s in renderdiff_signals(report, receipt_verified=True)}
        self.assertEqual(by_name["representation_divergence"].status, WeakLinkStatus.UNRESOLVED)

    def test_explicit_false_divergence_can_close(self):
        report = {"views": {"assurance": {"material_divergence": False, "complete": False, "coverage": {}}}, "summary": {}}
        by_name = {s.name: s for s in renderdiff_signals(report, receipt_verified=True)}
        self.assertEqual(by_name["representation_divergence"].status, WeakLinkStatus.CLOSED)

if __name__ == "__main__":
    unittest.main()
