import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "vul4py" / "scripts"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location(
    "evaluator_under_test", SCRIPTS / "evaluate.py"
)
evaluator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluator)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.workspaces = root / "workspaces"
        self.runs = root / "runs"
        self.case = "SIMULATED_CASE"
        workspace = self.workspaces / self.case
        workspace.mkdir(parents=True)
        (workspace / "meta.json").write_text("{}")

        self.run = self.runs / "gpt" / self.case
        self.run.mkdir(parents=True)
        files = {
            "response.txt": "simulated response",
            "claim.json": json.dumps({
                "success_claim": True, "confidence": 0.5
            }),
            "patch.diff": "simulated patch",
        }
        manifest = []
        for name, content in files.items():
            data = content.encode("utf-8")
            (self.run / name).write_bytes(data)
            manifest.append(f"{sha256(data).hexdigest()}  {name}\n")
        (self.run / "frozen.sha256").write_text("".join(manifest))

    def evaluate(self):
        return evaluator.evaluate_one(
            self.workspaces, self.runs, "gpt", self.case
        )

    def test_missing_manifest(self):
        (self.run / "frozen.sha256").unlink()
        with patch.object(evaluator, "run_vul4py") as command:
            result = self.evaluate()
        command.assert_not_called()
        self.assertEqual(result["verification_status"], "incomplete")
        self.assertEqual(result["notes"], "missing_frozen_manifest")

    def test_modified_patch(self):
        (self.run / "patch.diff").write_text("changed")
        with patch.object(evaluator, "run_vul4py") as command:
            result = self.evaluate()
        command.assert_not_called()
        self.assertEqual(
            result["notes"], "frozen_output_integrity_check_failed"
        )
        self.assertIsNone(result["verified_repair"])

    def test_existing_evaluation_is_preserved(self):
        target = self.run / "eval.json"
        original = b'{"preserved": true}'
        target.write_bytes(original)
        with patch.object(evaluator, "run_vul4py") as command:
            with self.assertRaises(SystemExit):
                self.evaluate()
        command.assert_not_called()
        self.assertEqual(target.read_bytes(), original)

    def test_valid_manifest_reaches_patch_stage(self):
        simulated = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="SIMULATED_FAILURE"
        )
        with patch.object(
            evaluator, "run_vul4py", return_value=simulated
        ) as command:
            result = self.evaluate()
        command.assert_called_once()
        self.assertIn("fork", command.call_args.args[0])
        self.assertEqual(result["notes"], "patch_application_incomplete")


if __name__ == "__main__":
    unittest.main()
