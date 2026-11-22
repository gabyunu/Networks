import csv
import json

from experiment_plan import ROOT, build_plan


def check_benchmark(cases):
    report_path = ROOT / "vul4py/workspaces/scan_report.tsv"

    with report_path.open(newline="", encoding="utf-8") as file:
        report = {
            row["cve_id"]: row
            for row in csv.DictReader(file, delimiter="\t")
        }

    for case in cases:
        row = report.get(case)

        if row is None:
            raise ValueError(f"{case}: falta en scan_report.tsv")

        if row["status"] != "OK":
            raise ValueError(f"{case}: estado {row['status']}, se requiere OK")

        for field in ("fv_pfes", "ff_pfes"):
            counts = [
                int(value)
                for value in row[field].split("/")
            ]

            if len(counts) != 4:
                raise ValueError(f"{case}: resumen inválido en {field}")

            passed, failed, errored, skipped = counts

            if min(counts) < 0 or passed < 1 or failed or errored:
                raise ValueError(
                    f"{case}: pruebas funcionales no válidas en {field}"
                )

        workspace = ROOT / "vul4py/workspaces" / case

        for required in ("meta.json", "vulnerable", "fixed"):
            if not (workspace / required).exists():
                raise ValueError(f"{case}: falta {required}")

        print(f"OK: {case}")


def main():
    config = json.loads(
        (ROOT / "experiment_config.json").read_text(encoding="utf-8")
    )
    plan = build_plan(config)
    check_benchmark(config["cases"])

    existing = [
        task["trial_dir"]
        for task in plan
        if (ROOT / task["trial_dir"]).exists()
    ]

    if existing:
        raise ValueError(
            "Ya existen carpetas de intentos; no se sobrescribirán:\n"
            + "\n".join(existing)
        )

    print(f"Plan comprobado: {len(plan)} intentos.")
    print("No se realizaron llamadas a la API.")


if __name__ == "__main__":
    main()
