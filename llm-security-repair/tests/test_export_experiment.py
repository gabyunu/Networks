import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "scripts"),
)

import export_experiment as exporter


class ExportExperimentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.study = self.root / "study"
        self.study.mkdir()

        root_patch = patch.object(exporter, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

        self.plan = [
            {
                "case": "CVE-2024-53861",
                "model": "SIMULATED_MODEL",
                "repetition": repetition,
                "runs_root": f"study/repetition_{repetition}",
                "trial_dir": (
                    f"study/repetition_{repetition}/gpt/CVE-2024-53861"
                ),
            }
            for repetition in (1, 2)
        ]
        self.write_json(self.study / "plan.json", self.plan)

    def write_json(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    def complete_trial(self, index, repaired=True):
        task = self.plan[index - 1]
        run = self.root / task["trial_dir"]

        self.write_json(
            self.study / "trial_records" / f"trial_{index:04d}.json",
            {**task, "pipeline_status": "complete", "reason": ""},
        )
        self.write_json(run / "generation.json", {
            "generation_status": "ready_for_verification",
            "model": "SIMULATED_RETURNED_MODEL",
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
            "api_latency_ms": 123,
        })
        value = int(repaired)
        self.write_json(run / "eval.json", {
            "observation_status": "complete",
            "claimed_success": 1,
            "confidence": 0.8,
            "A": value,
            "F": value,
            "S": value,
            "verified_repair": value,
            "false_assurance": 1 - value,
        })

    def test_unstarted_trials_are_preserved(self):
        rows = exporter.collect_rows(self.study)
        metrics = exporter.calculate_groups(rows)["overall"]

        self.assertEqual(len(rows), 2)
        self.assertEqual(metrics["not_started_observations"], 2)
        self.assertIsNone(metrics["VRR"])
        self.assertIsNone(metrics["FAR"])

    def test_started_trial_without_record_is_incomplete(self):
        (self.root / self.plan[0]["trial_dir"]).mkdir(parents=True)
        rows = exporter.collect_rows(self.study)

        self.assertEqual(rows[0]["observation_status"], "incomplete")
        self.assertEqual(rows[0]["reason"], "missing_controller_record")

    def test_completed_trial_keeps_metadata(self):
        self.complete_trial(1)
        rows = exporter.collect_rows(self.study)

        self.assertEqual(rows[0]["observation_status"], "complete")
        self.assertEqual(rows[0]["total_tokens"], 15)
        self.assertEqual(rows[0]["api_latency_ms"], 123)
        self.assertEqual(
            rows[0]["returned_model"], "SIMULATED_RETURNED_MODEL"
        )

    def test_incomplete_pipeline_overrides_positive_evaluation(self):
        self.complete_trial(1)
        path = self.study / "trial_records/trial_0001.json"
        record = json.loads(path.read_text())
        record["pipeline_status"] = "incomplete"
        record["reason"] = "frozen_integrity_failed_after_evaluation"
        self.write_json(path, record)

        rows = exporter.collect_rows(self.study)
        metrics = exporter.calculate_groups(rows)["overall"]

        self.assertEqual(rows[0]["observation_status"], "incomplete")
        self.assertEqual(metrics["completed_observations"], 0)
        self.assertIsNone(rows[0]["verified_repair"])

    def test_metrics_are_separated_by_repetition(self):
        self.complete_trial(1, repaired=True)
        self.complete_trial(2, repaired=False)

        metrics = exporter.calculate_groups(
            exporter.collect_rows(self.study)
        )

        self.assertEqual(metrics["overall"]["VRR"], 0.5)
        self.assertEqual(metrics["overall"]["FAR"], 0.5)
        groups = metrics["by_model_and_repetition"]
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0]["VRR"], 1)
        self.assertEqual(groups[1]["VRR"], 0)

    def test_command_writes_separate_csv_and_metrics(self):
        self.complete_trial(1)

        with patch.object(
            sys, "argv",
            ["export_experiment.py", "--study", str(self.study)],
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                exporter.main()

        with (self.study / "results.csv").open(newline="") as file:
            rows = list(csv.DictReader(file))

        metrics = json.loads((self.study / "metrics.json").read_text())

        self.assertEqual(len(rows), 2)
        self.assertEqual(metrics["overall"]["completed_observations"], 1)
        self.assertFalse((self.root / "results.csv").exists())


if __name__ == "__main__":
    unittest.main()
