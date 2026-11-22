import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "scripts"),
)

from experiment_plan import build_plan


class ExperimentPlanTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "experiment_id": "simulated_study",
            "cases": ["CVE-2021-32839", "CVE-2022-3102"],
            "models": ["SIMULATED_MODEL_A", "SIMULATED_MODEL_B"],
            "repetitions": 3,
        }

    def test_number_of_trials(self):
        plan = build_plan(self.config)
        self.assertEqual(len(plan), 12)

    def test_every_trial_has_a_different_directory(self):
        plan = build_plan(self.config)
        directories = {task["trial_dir"] for task in plan}
        self.assertEqual(len(directories), 12)

    def test_repetitions_are_recorded(self):
        plan = build_plan(self.config)
        self.assertEqual(
            {task["repetition"] for task in plan},
            {1, 2, 3},
        )

    def test_invalid_configurations_are_rejected(self):
        changes = [
            {"experiment_id": "../previous_results"},
            {"experiment_id": "gpt"},
            {"repetitions": 0},
            {"repetitions": True},
            {"models": []},
            {"cases": ["CVE-2021-32839", "CVE-2021-32839"]},
            {"cases": ["invalid_case"]},
        ]

        for change in changes:
            with self.subTest(change=change):
                config = dict(self.config, **change)
                with self.assertRaises(ValueError):
                    build_plan(config)


if __name__ == "__main__":
    unittest.main()
