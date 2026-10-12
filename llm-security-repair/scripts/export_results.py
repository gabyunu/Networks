import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
EVAL_DIR = ROOT / "vul4py" / "runs" / "gpt"
OUTPUT = ROOT / "results.csv"


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def read_text(path):
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def bool_text(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    return ""


config = read_text(ROOT / "src" / "config.py")
match = re.search(r'^MODEL\s*=\s*["\'](.+?)["\']', config, re.MULTILINE)
model = match.group(1) if match else "unknown"

columns = [
    "cve",
    "project",
    "vulnerable_file",
    "model",
    "response_saved",
    "response_parse_status",
    "success_claim",
    "confidence",
    "patch_saved",
    "api_latency_ms",
    "patch_applied",
    "functional_rc",
    "security_rc",
    "vul4py_plausible",
    "evaluation_elapsed_s",
    "evaluation_status",
    "notes",
]

rows = []

for case_dir in sorted(RESULTS_DIR.iterdir()):
    if not case_dir.is_dir():
        continue

    cve = case_dir.name
    response_path = case_dir / "response.txt"
    claim_path = case_dir / "claim.json"
    patch_path = case_dir / "patch.diff"
    latency_path = case_dir / "latency_ms.txt"

    if not response_path.exists():
        continue

    claim = read_json(claim_path)
    meta_path = ROOT / "vul4py" / "workspaces" / cve / "meta.json"
    meta = read_json(meta_path)

    files = meta.get("new_code_files", [])
    vulnerable_file = files[0] if files else ""

    if vulnerable_file:
        parts = Path(vulnerable_file).parts
        project = parts[0] if len(parts) > 1 else Path(parts[0]).stem
    else:
        project = ""

    eval_path = EVAL_DIR / cve / "eval.json"
    evaluation = read_json(eval_path)

    if claim_path.exists() and patch_path.exists():
        parse_status = "valid_json"
    else:
        parse_status = "invalid_json"

    if not evaluation:
        evaluation_status = "not_evaluated"
    elif not evaluation.get("apply_ok", False):
        evaluation_status = "patch_not_applied"
    elif (
        evaluation.get("functional_rc") is None
        or evaluation.get("exploit_rc") is None
    ):
        evaluation_status = "incomplete"
    elif evaluation.get("plausible") is True:
        evaluation_status = "plausible"
    else:
        evaluation_status = "not_plausible"

    notes = []
    if parse_status == "invalid_json":
        notes.append(
            "Raw response saved, but the script did not extract "
            "a valid claim and patch."
        )
    if evaluation_status == "not_evaluated":
        notes.append("Vul4Py evaluation not yet completed.")
    if evaluation.get("notes"):
        notes.append(str(evaluation["notes"]))

    rows.append({
        "cve": cve,
        "project": project,
        "vulnerable_file": vulnerable_file,
        "model": model,
        "response_saved": "yes",
        "response_parse_status": parse_status,
        "success_claim": bool_text(claim.get("success_claim")),
        "confidence": claim.get("confidence", ""),
        "patch_saved": "yes" if patch_path.exists() else "no",
        "api_latency_ms": read_text(latency_path),
        "patch_applied": bool_text(evaluation.get("apply_ok")),
        "functional_rc": evaluation.get("functional_rc", ""),
        "security_rc": evaluation.get("exploit_rc", ""),
        "vul4py_plausible": bool_text(evaluation.get("plausible")),
        "evaluation_elapsed_s": evaluation.get("elapsed_s", ""),
        "evaluation_status": evaluation_status,
        "notes": " ".join(notes),
    })

with OUTPUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)

print(f"CSV creado: {OUTPUT}")
print(f"Intentos registrados: {len(rows)}")
print("No se han calculado métricas agregadas.")
