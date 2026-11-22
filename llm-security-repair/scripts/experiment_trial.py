import json
import shutil
import subprocess
import sys
from pathlib import Path

from experiment_plan import ROOT


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def run_command(arguments, log_path):
    with log_path.open("x", encoding="utf-8") as log:
        result = subprocess.run(
            arguments,
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    return result.returncode


def check_frozen(run_dir, log_name):
    return run_command(
        [
            "sha256sum",
            "--check",
            "--strict",
            str(run_dir / "frozen.sha256"),
        ],
        run_dir / log_name,
    )


def verify_frozen(run_dir, log_name):
    with (run_dir / log_name).open("x", encoding="utf-8") as log:
        result = subprocess.run(
            ["sha256sum", "--check", "--strict", "frozen.sha256"],
            cwd=run_dir,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    return result.returncode == 0


def run_trial(task):
    run_dir = ROOT / task["trial_dir"]
    runs_root = ROOT / task["runs_root"]
    case = task["case"]

    if run_dir.exists():
        raise FileExistsError(f"El intento ya existe: {run_dir}")

    # El registro del controlador vive fuera de la carpeta que crea el generador.
    controller_dir = runs_root / "controller_logs"
    controller_dir.mkdir(parents=True, exist_ok=True)

    generation_rc = run_command(
        [
            sys.executable,
            str(ROOT / "vul4py/scripts/run_agent.py"),
            "--agent", "gpt",
            "--model", task["model"],
            "--vuln-id", case,
            "--runs", str(runs_root),
            "--workspaces", str(ROOT / "vul4py/workspaces"),
        ],
        controller_dir / f"{case}_generation.log",
    )

    result = {
        **task,
        "generation_command_rc": generation_rc,
        "pipeline_status": "incomplete",
        "reason": "",
    }

    generation_path = run_dir / "generation.json"

    if not generation_path.is_file():
        result["reason"] = "missing_generation_record"
        return result

    generation = read_json(generation_path)
    result["generation_status"] = generation.get("generation_status")

    if not verify_frozen(run_dir, "integrity_before.log"):
        result["reason"] = "frozen_integrity_failed_before_evaluation"
        return result

    if generation.get("generation_status") != "ready_for_verification":
        result["reason"] = generation.get(
            "generation_status", "generation_incomplete"
        )
        return result

    evaluation_rc = run_command(
        [
            "python3.12",
            str(ROOT / "vul4py/scripts/evaluate.py"),
            "--agent", "gpt",
            "--vuln-id", case,
            "--runs", str(runs_root),
            "--workspaces", str(ROOT / "vul4py/workspaces"),
        ],
        controller_dir / f"{case}_evaluation.log",
    )
    result["evaluation_command_rc"] = evaluation_rc

    evaluation_path = run_dir / "eval.json"

    if not evaluation_path.is_file():
        result["reason"] = "missing_evaluation_record"
        return result

    evaluation = read_json(evaluation_path)

    # Solo copiar registros de pruebas que este intento llegó a ejecutar.
    evidence = run_dir / "test_evidence"
    evidence.mkdir(exist_ok=False)
    benchmark_logs = ROOT / "vul4py/workspaces" / case / "logs"

    for prefix, status_field in (
        ("functional", "functional_status"),
        ("exploit", "security_status"),
    ):
        if evaluation.get(status_field) in (None, "not_run"):
            continue

        for extension in ("log", "junit.xml"):
            source = benchmark_logs / f"{prefix}_gpt_candidate.{extension}"
            if source.is_file():
                shutil.copy2(source, evidence / source.name)

    if not verify_frozen(run_dir, "integrity_after.log"):
        result["reason"] = "frozen_integrity_failed_after_evaluation"
        return result

    result["pipeline_status"] = evaluation.get(
        "observation_status", "incomplete"
    )
    result["reason"] = evaluation.get("notes", "")
    return result
