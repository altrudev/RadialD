import unittest

from radiald import (
    SafeAutonomy,
    WeakLinkAnalyzer,
    WeakLinkSignal,
    WeakLinkStatus,
)


class WeakLinkTests(unittest.TestCase):
    def test_unresolved_high_risk_bounds_system(self):
        report = WeakLinkAnalyzer().analyze([
            WeakLinkSignal(
                "representation_equivalence",
                severity=0.95,
                confidence=0.95,
                status=WeakLinkStatus.CLOSED,
            ),
            WeakLinkSignal(
                "external_state_freshness",
                severity=0.90,
                confidence=0.95,
                status=WeakLinkStatus.UNRESOLVED,
                propagation_depth=2,
                reversible=False,
            ),
        ])

        self.assertEqual(report.bounding_link.name, "external_state_freshness")
        self.assertEqual(
            report.maximum_safe_autonomy, SafeAutonomy.HUMAN_REQUIRED
        )
        self.assertLess(report.system_assurance, 0.2)

    def test_closed_links_do_not_reduce_assurance(self):
        report = WeakLinkAnalyzer().analyze([
            WeakLinkSignal("authority", 1.0, 1.0, WeakLinkStatus.CLOSED),
            WeakLinkSignal("provenance", 0.8, 1.0, WeakLinkStatus.CLOSED),
        ])

        self.assertIsNone(report.bounding_link)
        self.assertEqual(report.system_assurance, 1.0)
        self.assertEqual(
            report.maximum_safe_autonomy,
            SafeAutonomy.AUTONOMOUS_WITH_RECEIPTS,
        )

    def test_contained_link_remains_visible(self):
        report = WeakLinkAnalyzer().analyze([
            WeakLinkSignal("recovery", 0.8, 1.0, WeakLinkStatus.CONTAINED),
        ])

        self.assertEqual(report.bounding_link.name, "recovery")
        self.assertGreater(report.system_assurance, 0.7)
        self.assertEqual(
            report.maximum_safe_autonomy, SafeAutonomy.BOUNDED_AUTONOMY
        )


if __name__ == "__main__":
    unittest.main()
