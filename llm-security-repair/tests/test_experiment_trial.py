import hashlib
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

import experiment_trial as trial


class ExperimentTrialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

        root_patch = patch.object(trial, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

        self.task = {
            "case": "CVE-2024-53861",
            "model": "SIMULATED_MODEL",
            "repetition": 1,
            "runs_root": "runs/study/repetition_01",
            "trial_dir": "runs/study/repetition_01/gpt/CVE-2024-53861",
        }
        self.run = self.root / self.task["trial_dir"]
        self.generation_status = "ready_for_verification"
        self.applied = False
        self.modify_patch = False
        self.calls = 0

    def fake_command(self, arguments, log_path):
        self.calls += 1

        if self.calls == 1:
            self.run.mkdir(parents=True)
            files = {
                "generation.json": json.dumps({
                    "generation_status": self.generation_status,
                }),
                "response.txt": "SIMULATED RESPONSE",
                "patch.diff": "SIMULATED PATCH",
            }

            manifest = []
            for name, content in files.items():
                data = content.encode("utf-8")
                (self.run / name).write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                manifest.append(f"{digest}  {name}\n")

            (self.run / "frozen.sha256").write_text(
                "".join(manifest), encoding="utf-8"
            )
            return 0

        evaluation = {
            "apply_ok": self.applied,
            "functional_status": "passed" if self.applied else "not_run",
            "security_status": "passed" if self.applied else "not_run",
            "observation_status": "complete",
            "notes": "" if self.applied else "patch_rejected",
        }
        (self.run / "eval.json").write_text(json.dumps(evaluation))

        if self.modify_patch:
            (self.run / "patch.diff").write_text("MODIFIED")

        return 0

    def test_existing_attempt_is_preserved(self):
        self.run.mkdir(parents=True)
        original = self.run / "response.txt"
        original.write_text("ORIGINAL")

        with patch.object(trial, "run_command") as command:
            with self.assertRaises(FileExistsError):
                trial.run_trial(self.task)

        command.assert_not_called()
        self.assertEqual(original.read_text(), "ORIGINAL")

    def test_invalid_response_is_not_evaluated(self):
        self.generation_status = "invalid_response"

        with patch.object(trial, "run_command", self.fake_command):
            result = trial.run_trial(self.task)

        self.assertEqual(self.calls, 1)
        self.assertEqual(result["pipeline_status"], "incomplete")
        self.assertFalse((self.run / "eval.json").exists())

    def test_rejected_patch_is_a_completed_observation(self):
        with patch.object(trial, "run_command", self.fake_command):
            result = trial.run_trial(self.task)

        self.assertEqual(result["pipeline_status"], "complete")
        self.assertEqual(result["reason"], "patch_rejected")
        self.assertEqual(list((self.run / "test_evidence").iterdir()), [])

    def test_executed_test_logs_are_archived(self):
        self.applied = True
        logs = (
            self.root / "vul4py/workspaces"
            / self.task["case"] / "logs"
        )
        logs.mkdir(parents=True)

        for prefix in ("functional", "exploit"):
            for extension in ("log", "junit.xml"):
                name = f"{prefix}_gpt_candidate.{extension}"
                (logs / name).write_text("SIMULATED EVIDENCE")

        with patch.object(trial, "run_command", self.fake_command):
            result = trial.run_trial(self.task)

        self.assertEqual(result["pipeline_status"], "complete")
        evidence = list((self.run / "test_evidence").iterdir())
        self.assertEqual(len(evidence), 4)
        for file in evidence:
            self.assertEqual(file.read_text(), "SIMULATED EVIDENCE")

    def test_changed_patch_invalidates_pipeline(self):
        self.modify_patch = True

        with patch.object(trial, "run_command", self.fake_command):
            result = trial.run_trial(self.task)

        self.assertEqual(result["pipeline_status"], "incomplete")
        self.assertEqual(
            result["reason"],
            "frozen_integrity_failed_after_evaluation",
        )


if __name__ == "__main__":
    unittest.main()
