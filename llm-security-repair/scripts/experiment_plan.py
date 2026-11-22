import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build_plan(config):
    if not isinstance(config, dict):
        raise ValueError("La configuración debe ser un objeto JSON.")

    experiment = config.get("experiment_id")
    if not isinstance(experiment, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]*", experiment
    ):
        raise ValueError("experiment_id inválido.")

    if experiment in {"gpt", "claude", "swe", "trae", "openhands"}:
        raise ValueError("Usa un nombre distinto para el experimento.")

    for field in ("cases", "models"):
        values = config.get(field)
        if (
            not isinstance(values, list)
            or not values
            or any(
                not isinstance(value, str)
                or not value
                or value != value.strip()
                for value in values
            )
        ):
            raise ValueError(f"{field} debe contener textos no vacíos.")

        if len(values) != len(set(values)):
            raise ValueError(f"{field} contiene elementos repetidos.")

    for case in config["cases"]:
        if not re.fullmatch(r"CVE-\d{4}-\d+", case):
            raise ValueError(f"Identificador de caso inválido: {case}")

    repetitions = config.get("repetitions")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions debe ser un entero positivo.")

    plan = []
    base = Path("vul4py/runs") / experiment

    for model_index, model in enumerate(config["models"], start=1):
        for repetition in range(1, repetitions + 1):
            group = (
                base
                / f"model_{model_index:02d}"
                / f"repetition_{repetition:02d}"
            )
            for case in config["cases"]:
                plan.append({
                    "case": case,
                    "model": model,
                    "repetition": repetition,
                    "runs_root": str(group),
                    "trial_dir": str(group / "gpt" / case),
                })

    return plan


def main():
    parser = argparse.ArgumentParser(
        description="Planifica intentos sin realizar llamadas a la API."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "experiment_config.json",
    )
    args = parser.parse_args()

    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        plan = build_plan(config)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Casos: {len(config['cases'])}")
    print(f"Modelos: {len(config['models'])}")
    print(f"Repeticiones: {config['repetitions']}")
    print(f"Intentos planificados: {len(plan)}")

    for task in plan:
        print(
            f"{task['case']} | {task['model']} | "
            f"repetición {task['repetition']} | {task['trial_dir']}"
        )

    print("Solo planificación: ninguna llamada a la API.")


if __name__ == "__main__":
    main()
