import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone

from experiment_plan import ROOT, build_plan
from check_experiment import check_benchmark
from experiment_trial import run_trial


def save_json(path, data):
    with path.open("x", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Planifica o ejecuta un experimento independiente."
    )
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    config_path = ROOT / "experiment_config.json"
    config_bytes = config_path.read_bytes()
    config = json.loads(config_bytes)
    plan = build_plan(config)

    check_benchmark(config["cases"])

    study_dir = ROOT / "vul4py/runs" / config["experiment_id"]

    if study_dir.exists():
        parser.error(
            f"El experimento ya tiene una carpeta: {study_dir}. "
            "Se conserva sin modificaciones."
        )

    print(f"Experimento: {config['experiment_id']}")
    print(f"Intentos planificados: {len(plan)}")
    print(f"Destino: {study_dir}")

    if not args.execute:
        print("Modo planificación: ninguna llamada a la API.")
        return

    if not os.environ.get("OPENAI_API_KEY"):
        parser.error("Falta OPENAI_API_KEY en esta terminal.")

    # Comprobar el SDK antes de crear el experimento.
    import openai

    prompt_bytes = (ROOT / "experiment_prompt.txt").read_bytes()
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()

    study_dir.mkdir(parents=True, exist_ok=False)

    with (study_dir / "config.json").open("xb") as file:
        file.write(config_bytes)

    with (study_dir / "experiment_prompt.txt").open("xb") as file:
        file.write(prompt_bytes)

    save_json(study_dir / "plan.json", plan)
    save_json(study_dir / "registration.json", {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "repository_commit": revision,
        "openai_sdk_version": openai.__version__,
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "planned_trials": len(plan),
    })

    records_dir = study_dir / "trial_records"
    records_dir.mkdir()

    # Ejecución secuencial: el benchmark comparte carpetas temporales.
    for index, task in enumerate(plan, start=1):
        print(
            f"[{index}/{len(plan)}] {task['case']} "
            f"| {task['model']} | repetición {task['repetition']}",
            flush=True,
        )

        unexpected_error = False
        try:
            record = run_trial(task)
        except Exception as error:
            unexpected_error = True
            record = {
                **task,
                "pipeline_status": "incomplete",
                "reason": "controller_error",
                "error_type": type(error).__name__,
            }

        save_json(records_dir / f"trial_{index:04d}.json", record)
        print(
            f"Estado: {record['pipeline_status']} "
            f"| Motivo: {record.get('reason', '')}",
            flush=True,
        )

        if unexpected_error:
            print("Ejecución detenida; los registros existentes se conservan.")
            return

    print("Recorrido terminado. Los resultados deben agregarse por separado.")


if __name__ == "__main__":
    main()
