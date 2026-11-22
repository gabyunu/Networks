import argparse
import csv
import json
from pathlib import Path

from experiment_plan import ROOT
from experiment_metrics import summarize


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def collect_rows(study_dir):
    plan = read_json(study_dir / "plan.json")
    rows = []

    for index, task in enumerate(plan, start=1):
        run_dir = ROOT / task["trial_dir"]
        record_path = (
            study_dir / "trial_records" / f"trial_{index:04d}.json"
        )

        row = {
            **task,
            "observation_status": "not_started",
            "reason": "",
            "claimed_success": None,
            "confidence": None,
            "A": None,
            "F": None,
            "S": None,
            "verified_repair": None,
            "false_assurance": None,
            "returned_model": None,
            "input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
            "api_latency_ms": None,
            "request_started_at": None,
            "response_received_at": None,
            "generation_status": None,
            "error": None,
            "http_status": None,
        }

        if not record_path.is_file():
            if run_dir.exists():
                row["observation_status"] = "incomplete"
                row["reason"] = "missing_controller_record"
            rows.append(row)
            continue

        record = read_json(record_path)

        for field in ("case", "model", "repetition", "trial_dir"):
            if record.get(field) != task[field]:
                raise ValueError(f"Registro distinto del plan: {record_path}")

        row["observation_status"] = "incomplete"
        row["reason"] = record.get("reason", "")

        generation_path = run_dir / "generation.json"
        generation = (
            read_json(generation_path)
            if generation_path.is_file() else {}
        )

        row["returned_model"] = generation.get("model")

        for field in (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "api_latency_ms",
            "request_started_at",
            "response_received_at",
            "generation_status",
            "error",
            "http_status",
        ):
            row[field] = generation.get(field)

        evaluation_path = run_dir / "eval.json"
        evaluation = (
            read_json(evaluation_path)
            if evaluation_path.is_file() else {}
        )

        if (
            record.get("pipeline_status") == "complete"
            and generation.get("generation_status")
                == "ready_for_verification"
            and evaluation.get("observation_status") == "complete"
        ):
            row["observation_status"] = "complete"

            for field in (
                "claimed_success",
                "confidence",
                "A",
                "F",
                "S",
                "verified_repair",
                "false_assurance",
            ):
                row[field] = evaluation.get(field)
        elif not row["reason"]:
            row["reason"] = "incomplete_or_missing_evidence"

        rows.append(row)

    return rows


def calculate_groups(rows):
    return {
        "overall": summarize(rows),
        "by_model": [
            {
                "model": model,
                **summarize([
                    row for row in rows if row["model"] == model
                ]),
            }
            for model in sorted({row["model"] for row in rows})
        ],
        "by_model_and_repetition": [
            {
                "model": model,
                "repetition": repetition,
                **summarize([
                    row for row in rows
                    if row["model"] == model
                    and row["repetition"] == repetition
                ]),
            }
            for model, repetition in sorted({
                (row["model"], row["repetition"]) for row in rows
            })
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Exporta un experimento registrado, sin llamadas a la API."
    )
    parser.add_argument("--study", type=Path, required=True)
    args = parser.parse_args()
    study_dir = args.study.resolve()

    if not (study_dir / "plan.json").is_file():
        parser.error("No existe un plan registrado en esa carpeta.")

    rows = collect_rows(study_dir)
    metrics = calculate_groups(rows)

    with (study_dir / "results.csv").open(
        "w", newline="", encoding="utf-8"
    ) as file:
        fields = list(rows[0]) if rows else ["observation_status"]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    (study_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(metrics["overall"], indent=2))
    print(f"Archivos generados en: {study_dir}")


if __name__ == "__main__":
    main()
