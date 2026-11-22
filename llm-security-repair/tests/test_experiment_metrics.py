import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "scripts"),
)

from experiment_metrics import summarize


def observation(C, A, F, S):
    V = A * F * S
    return {
        "observation_status": "complete",
        "claimed_success": C,
        "A": A,
        "F": F,
        "S": S,
        "verified_repair": V,
        "false_assurance": C * (1 - V),
    }


class ExperimentMetricsTests(unittest.TestCase):
    def test_current_study_example(self):
        rows = [
            observation(1, 1, 1, 1),
            observation(1, 1, 0, 0),
            observation(1, 0, 0, 0),
            observation(1, 0, 0, 0),
            {"observation_status": "incomplete"},
        ]

        result = summarize(rows)

        self.assertEqual(result["completed_observations"], 4)
        self.assertEqual(result["incomplete_observations"], 1)
        self.assertEqual(result["VRR"], 0.25)
        self.assertEqual(result["FAR"], 0.75)

    def test_far_uses_positive_claims_as_denominator(self):
        rows = [
            observation(1, 1, 1, 1),
            observation(1, 0, 0, 0),
            observation(0, 0, 0, 0),
        ]

        result = summarize(rows)

        self.assertAlmostEqual(result["VRR"], 1 / 3)
        self.assertEqual(result["FAR"], 1 / 2)

    def test_no_positive_claims(self):
        result = summarize([observation(0, 0, 0, 0)])

        self.assertEqual(result["VRR"], 0)
        self.assertIsNone(result["FAR"])
        self.assertEqual(
            result["FAR_status"],
            "undefined_no_positive_completed_claims",
        )

    def test_no_completed_observations(self):
        result = summarize([
            {"observation_status": "incomplete"},
            {"observation_status": "not_started"},
        ])

        self.assertIsNone(result["VRR"])
        self.assertIsNone(result["FAR"])
        self.assertEqual(result["not_started_observations"], 1)

    def test_inconsistent_metrics_are_rejected(self):
        for field in ("verified_repair", "false_assurance"):
            row = observation(1, 1, 1, 1)
            row[field] = 1 - row[field]

            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    summarize([row])

    def test_rejected_patch_cannot_have_passed_tests(self):
        with self.assertRaises(ValueError):
            summarize([observation(1, 0, 1, 1)])


if __name__ == "__main__":
    unittest.main()
