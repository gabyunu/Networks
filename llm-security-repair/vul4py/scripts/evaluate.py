#!/usr/bin/env python3
"""
evaluate.py

For one or more agents, for one or more vulns:
  1. Fork the vulnerable/ checkout into <case>/<agent>_candidate/
  2. Apply runs/<agent>/<vuln_id>/patch.diff
  3. Install + run baseline functional tests (must still pass)
  4. Run exploit/regression tests (must now pass)
  5. Write runs/<agent>/<vuln_id>/eval.json with verdict

Verdict fields:
    apply_ok            -- did the patch apply cleanly?
    functional_rc       -- exit code of baseline tests on candidate (0 = pass)
    exploit_rc          -- exit code of exploit tests on candidate
    A, F, S             -- patch, functional, security indicators; None if incomplete
    verification_status -- complete or incomplete
    plausible           -- patch applies and both suites pass with test evidence
    notes               -- error string if any

This script wraps scripts/vul4py.py for actual setup / test / fork / patch work,
so the harness behavior matches the rest of the pipeline.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional
from oracle_status import classify_oracle, repair_metrics
from vul4py import _parse_junit

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"
VUL4PY = Path(__file__).resolve().parent / "vul4py.py"


def cleanup_candidate(case_dir: Path, dst_name: str):
    p = case_dir / dst_name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def run_vul4py(args: List[str], log_lines: list) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(VUL4PY)] + args
    log_lines.append("$ " + " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    log_lines.append(f"[exit {cp.returncode}]")
    if cp.stdout:
        log_lines.append(cp.stdout)
    if cp.stderr:
        log_lines.append(cp.stderr)
    return cp


def evaluate_one(workspaces: Path, runs: Path, agent: str, vuln_id: str) -> dict:
    case_dir = workspaces / vuln_id
    run_dir = runs / agent / vuln_id
    patch = run_dir / "patch.diff"
    eval_path = run_dir / "eval.json"
    log_path = run_dir / "eval.log"

    verdict = {
        "agent": agent,
        "vuln_id": vuln_id,
        "apply_ok": False,
        "A": None,
        "patch_application_status": "not_run",
        "patch_command_rc": None,
        "functional_rc": None,
        "exploit_rc": None,
        "plausible": False,
        "verification_status": "incomplete",
        "functional_status": "not_run",
        "security_status": "not_run",
        "functional_counts": None,
        "security_counts": None,
        "F": None,
        "S": None,
        "elapsed_s": None,
        "notes": "",
    }
    def save_verdict():
        C = None
        confidence = None
        claim_error = ""
        try:
            claim = json.loads(
                (run_dir / "claim.json").read_text(encoding="utf-8")
            )
            if not isinstance(claim, dict):
                raise ValueError("Claim must be a JSON object")
            value = claim.get("success_claim")
            probability = claim.get("confidence")
            if type(value) not in (bool, int) or value not in (0, 1):
                raise ValueError("Invalid success_claim")
            if (
                type(probability) not in (int, float)
                or not 0 <= probability <= 1
            ):
                raise ValueError("Invalid confidence")
            C = int(value)
            confidence = probability
        except (OSError, ValueError) as error:
            claim_error = str(error)

        V, FA = repair_metrics(
            verdict["A"], verdict["F"], verdict["S"],
            C, verdict["verification_status"]
        )
        verdict.update(
            claimed_success=C,
            confidence=confidence,
            claim_error=claim_error,
            verified_repair=V,
            false_assurance=FA,
            observation_status=(
                "complete"
                if verdict["verification_status"] == "complete" and C is not None
                else "incomplete"
            ),
        )
        eval_path.write_text(
            json.dumps(verdict, indent=2), encoding="utf-8"
        )

    log: list = []
    t0 = time.time()

    if not case_dir.exists() or not (case_dir / "meta.json").exists():
        verdict["notes"] = f"no workspace at {case_dir}"
        eval_path.parent.mkdir(parents=True, exist_ok=True)
        save_verdict()
        return verdict
    if not patch.exists():
        verdict["notes"] = f"no patch at {patch}"
        eval_path.parent.mkdir(parents=True, exist_ok=True)
        save_verdict()
        return verdict

    dst_name = f"{agent}_candidate"
    cleanup_candidate(case_dir, dst_name)

    fork = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "fork",
            "--src", "vulnerable",
            "--dst", dst_name,
            "--patch", str(patch.resolve()),
        ],
        log,
    )
    if fork.returncode != 0:
        details = ""
        patch_rc = None
        application_error = "Failed to apply patch" in (fork.stderr or "")
        if application_error:
            try:
                patch_log = case_dir / "logs" / f"patch_{dst_name}.log"
                details = patch_log.read_text(encoding="utf-8", errors="replace")
                shutil.copy2(patch_log, run_dir / "patch_apply.log")
                exits = [
                    line for line in details.splitlines()
                    if line.startswith("[exit ") and line.endswith("]")
                ]
                if len(exits) == 1:
                    patch_rc = int(exits[0][6:-1])
            except (OSError, ValueError):
                patch_rc = None

        environment_errors = (
            "permission denied", "no space left", "read-only file system",
            "cannot allocate memory", "too many open files",
            "disk quota exceeded", "input/output error",
        )
        error_text = ((fork.stderr or "") + details).lower()
        known_rejections = (
            "malformed patch", "corrupt patch", "patch does not apply",
            "unexpected end of file in patch", "only garbage was found",
            "can't find file to patch", "no file to patch", "patch failed:",
        )
        known_rejection = (
            any(message in error_text for message in known_rejections)
            or ("hunk #" in error_text and "failed" in error_text)
        )
        rejected = (
            application_error and patch_rc is not None and patch_rc > 0
            and known_rejection
            and not any(message in error_text for message in environment_errors)
        )
        verdict["patch_command_rc"] = patch_rc
        verdict["patch_application_status"] = (
            "rejected" if rejected else "incomplete"
        )
        verdict["notes"] = (
            "patch_rejected" if rejected else "patch_application_incomplete"
        )
        if rejected:
            verdict.update(
                A=0, F=0, S=0, verification_status="complete",
                functional_reason="patch_rejected",
                security_reason="patch_rejected",
            )
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        verdict["elapsed_s"] = round(time.time() - t0, 1)
        save_verdict()
        cleanup_candidate(case_dir, dst_name)
        return verdict

    verdict["apply_ok"] = True
    verdict["A"] = 1
    verdict["patch_application_status"] = "applied"
    verdict["patch_command_rc"] = 0

    func = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "functional",
            "--target", dst_name,
        ],
        log,
    )
    # The CLI doesn't surface the inner rc cleanly; parse it from stdout.
    func_rc = parse_rc(func.stdout, "rc=") if func.returncode == 0 else None
    verdict["functional_rc"] = func_rc

    expl = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "exploit",
            "--targets", dst_name,
        ],
        log,
    )
    expl_rc = parse_rc(expl.stdout, "rc=") if expl.returncode == 0 else None
    verdict["exploit_rc"] = expl_rc

    def read_report(filename, command_rc):
        if command_rc != 0:
            return None
        try:
            return _parse_junit(case_dir / "logs" / filename)
        except (OSError, ValueError, TypeError):
            return None

    functional_summary = read_report(
        f"functional_{dst_name}.junit.xml", func.returncode
    )
    security_summary = read_report(
        f"exploit_{dst_name}.junit.xml", expl.returncode
    )
    f_status, f_value, f_reason = classify_oracle(
        func_rc if func.returncode == 0 else None, functional_summary
    )
    s_status, s_value, s_reason = classify_oracle(
        expl_rc if expl.returncode == 0 else None, security_summary
    )
    complete = (
        f_status in ("passed", "failed")
        and s_status in ("passed", "failed")
    )
    verdict.update(
        verification_status="complete" if complete else "incomplete",
        functional_status=f_status,
        security_status=s_status,
        functional_reason=f_reason,
        security_reason=s_reason,
        functional_counts=functional_summary,
        security_counts=security_summary,
        functional_command_rc=func.returncode,
        security_command_rc=expl.returncode,
        F=f_value,
        S=s_value,
    )
    verdict["plausible"] = (
        verdict["apply_ok"] and f_value == 1 and s_value == 1
    )
    if not complete:
        verdict["notes"] = (
            f"functional: {f_reason}; security: {s_reason}"
        )

    cleanup_candidate(case_dir, dst_name)
    log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
    verdict["elapsed_s"] = round(time.time() - t0, 1)
    save_verdict()
    return verdict


def parse_rc(stdout: str, marker: str) -> Optional[int]:
    for line in stdout.splitlines():
        if marker in line:
            try:
                return int(line.split(marker, 1)[1].strip().split()[0])
            except Exception:
                continue
    return None


def main():
    ap = argparse.ArgumentParser(description="Evaluate agent-produced patches against baseline + exploit tests.")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--vuln-id", help="Single vuln; omit to evaluate every patch found.")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    agent_dir = args.runs / args.agent
    if not agent_dir.exists():
        sys.exit(f"no runs for agent: {agent_dir}")

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(p.name for p in agent_dir.iterdir() if (p / "patch.diff").exists())
        if args.limit:
            targets = targets[: args.limit]

    n_plaus = 0
    for vid in targets:
        v = evaluate_one(args.workspaces, args.runs, args.agent, vid)
        flag = (
            "INCOMPLETE" if v["verification_status"] == "incomplete"
            else ("PLAUSIBLE" if v["plausible"] else "FAIL")
        )
        print(
            f"  {args.agent}/{vid}: {flag} "
            f"apply={v['apply_ok']} func_rc={v['functional_rc']} expl_rc={v['exploit_rc']} "
            f"({v['elapsed_s']}s)"
        )
        if v["plausible"]:
            n_plaus += 1
    print(f"[done] {args.agent}: plausible {n_plaus}/{len(targets)}")


if __name__ == "__main__":
    main()
