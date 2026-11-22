#!/usr/bin/env python3
"""
run_agent.py

Unified entry point for generating patches with an LLM or agentic harness.

Layout produced (one per (agent, vuln_id)):
    runs/<agent>/<vuln_id>/
        prompt.txt       -- prompt the agent saw (only for direct LLM agents)
        patch.diff       -- unified diff against vulnerable/
        generation.json  -- model/agent metadata, tokens, cost, elapsed_s, error
        notes.md         -- free-form notes (optional)

Built-in agents (direct LLM call):
    claude   -- Anthropic, default model claude-opus-4-7 (Opus 4.7, 1M context)
    gpt      -- OpenAI, default model gpt-4.1

External agents (this script does NOT run them; it just defines the contract):
    openhands, trae, swe
    -> Drop their output into runs/<agent>/<vuln_id>/patch.diff yourself.

The built-in path is intentionally minimal: it reads the vulnerable checkout,
serialises a small set of likely-vulnerable .py files (from meta.json's
new_code_files when available, else baseline_test_files' parents), asks the
model for a unified diff, and writes patch.diff verbatim. This is a baseline
for the paper's "direct LLM" condition; agentic harnesses go through their own
runner and just drop their output here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"

BUILTIN = {"claude", "gpt"}
EXTERNAL = {"openhands", "trae", "swe"}


# ---------- prompt assembly ----------

SYSTEM_PROMPT = """You are a security engineer. Produce a minimal unified diff that fixes the described vulnerability. Output ONLY the diff, no prose, no fences. Paths must be relative to the repository root, prefixed `a/` and `b/`."""


def load_meta(case_dir: Path) -> dict:
    return json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))


def collect_context_files(case_dir: Path, meta: dict, max_files: int = 4, max_bytes: int = 60_000) -> List[tuple]:
    """Return [(rel_path, contents)] up to budgets. Prefer new_code_files."""
    vuln_dir = case_dir / "vulnerable"
    targets: List[str] = []
    for p in meta.get("new_code_files", []):
        if p not in targets:
            targets.append(p)
    if not targets:
        for p in meta.get("baseline_test_files", []):
            d = os.path.dirname(p) or "."
            if d not in targets:
                targets.append(d)

    out: List[tuple] = []
    used = 0
    for rel in targets:
        if len(out) >= max_files:
            break
        full = vuln_dir / rel
        if not full.exists() or not full.is_file():
            continue
        try:
            data = full.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if used + len(data) > max_bytes:
            continue
        out.append((rel, data))
        used += len(data)
    return out


def build_user_prompt(vuln_id: str, meta: dict, files: List[tuple]) -> str:
    blocks = [
        "",
        "The vulnerable source files follow. Produce a single unified diff that",
        "patches the vulnerability while keeping the baseline tests passing.",
        "",
    ]
    for rel, data in files:
        blocks.append(f"--- FILE: {rel} ---")
        blocks.append(data.rstrip())
        blocks.append(f"--- END FILE: {rel} ---")
        blocks.append("")
    blocks.append("Respond with ONLY the unified diff.")
    return "\n".join(blocks)


# ---------- LLM backends ----------

def call_claude(system: str, prompt: str, model: str) -> tuple:
    from anthropic import Anthropic  # lazy
    client = Anthropic()
    t0 = time.time()
    resp = client.messages.create(
        model=model,
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    elapsed = time.time() - t0
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    meta = {
        "model": model,
        "input_tokens": resp.usage.input_tokens,
        "output_tokens": resp.usage.output_tokens,
        "stop_reason": resp.stop_reason,
        "elapsed_s": elapsed,
    }
    return text, meta


def call_gpt(system: str, prompt: str, model: str, temperature: float = 0.0) -> tuple:
    from datetime import datetime, timezone
    from openai import OpenAI

    def utc_now():
        return datetime.now(timezone.utc).isoformat()

    info = {
        "requested_model": model,
        "model": None,
        "request_started_at": None,
        "response_received_at": None,
        "input_tokens": None,
        "output_tokens": None,
        "total_tokens": None,
        "api_latency_ms": None,
        "elapsed_s": None,
        "max_retries": 0,
        "timeout_seconds": 120.0,
        "error": None,
    }
    started = None

    try:
        with OpenAI(max_retries=0, timeout=120.0) as client:
            info["request_started_at"] = utc_now()
            started = time.perf_counter()

            response = client.responses.create(
                model=model,
                input=[{"role": "user", "content": prompt}],
            )

            elapsed = time.perf_counter() - started
            usage = response.usage
            info.update(
                model=response.model,
                response_received_at=utc_now(),
                response_id=response.id,
                request_id=getattr(response, "_request_id", None),
                response_status=response.status,
                input_tokens=getattr(usage, "input_tokens", None),
                output_tokens=getattr(usage, "output_tokens", None),
                total_tokens=getattr(usage, "total_tokens", None),
                api_latency_ms=elapsed * 1000,
                elapsed_s=elapsed,
                raw_response=response.model_dump(mode="json"),
            )
            return response.output_text, info

    except Exception as error:
        info.update(
            error=type(error).__name__,
            http_status=getattr(error, "status_code", None),
            request_id=getattr(error, "request_id", None),
            finished_at=utc_now(),
        )
        if started is not None:
            elapsed = time.perf_counter() - started
            info["api_latency_ms"] = elapsed * 1000
            info["elapsed_s"] = elapsed
        return "", info


# ---------- patch extraction ----------

def extract_diff(text: str) -> str:
    # If the model wrapped in ``` fences, strip them.
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines)
    return stripped + ("\n" if not stripped.endswith("\n") else "")


# ---------- driver ----------

def run_builtin(agent: str, model: str, vuln_id: str, case_dir: Path, out_dir: Path,
                temperature: float = 0.0) -> int:
    meta = load_meta(case_dir)
    files = collect_context_files(case_dir, meta)
    user = build_user_prompt(vuln_id, meta, files)

    if agent == "gpt":
        import hashlib

        prompt_bytes = (HERE.parent / "experiment_prompt.txt").read_bytes()
        expected_hash = "ca460a8d6854b780400382024847109064445de01e248c3b3114a7d4b7780323"
        if hashlib.sha256(prompt_bytes).hexdigest() != expected_hash:
            raise ValueError("Experimental prompt has changed")

        if len(files) != 1:
            raise ValueError("This protocol requires exactly one source file")

        relative_file, source_code = files[0]
        source_path = Path(relative_file)
        benchmark_tests = set(
            meta.get("baseline_test_files", [])
            + meta.get("new_test_files", [])
        )
        if (
            relative_file in benchmark_tests
            or any(part.lower() in ("test", "tests") for part in source_path.parts)
            or source_path.name.startswith("test_")
            or source_path.name.endswith("_test.py")
            or source_path.name == "conftest.py"
        ):
            raise ValueError("Test files must not be sent to the model")

        user = (
            prompt_bytes.decode("utf-8")
            + f"\n\nVulnerable source file: {relative_file}\n\n"
            + source_code
        )

    legacy_response = HERE.parent / "results" / vuln_id / "response.txt"
    default_run = out_dir.parent.parent.resolve() == RUNS.resolve()

    if agent == "gpt" and default_run and legacy_response.exists():
        print(
            f"[!] {vuln_id}: existing historical response; generation blocked.",
            file=sys.stderr,
        )
        return 2

    try:
        out_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(
            f"[!] {out_dir}: run directory already exists; generation blocked.",
            file=sys.stderr,
        )
        return 2
    (out_dir / "prompt.txt").write_text(user, encoding="utf-8")

    try:
        if agent == "claude":
            text, info = call_claude(SYSTEM_PROMPT, user, model)
        else:
            text, info = call_gpt(SYSTEM_PROMPT, user, model, temperature=temperature)
    except Exception as e:
        (out_dir / "generation.json").write_text(
            json.dumps({"agent": agent, "model": model, "error": repr(e)}, indent=2),
            encoding="utf-8",
        )
        print(f"[!] {vuln_id} {agent}: {e}", file=sys.stderr)
        return 1

    if agent == "gpt":
        import hashlib
        from datetime import datetime, timezone

        def save_json(name, data):
            with (out_dir / name).open("x", encoding="utf-8") as file:
                json.dump(data, file, indent=2)

        info.update(
            agent=agent,
            vuln_id=vuln_id,
            context_files=[relative for relative, _ in files],
            prompt_sha256=hashlib.sha256(user.encode("utf-8")).hexdigest(),
            source_sha256={
                relative: hashlib.sha256(data.encode("utf-8")).hexdigest()
                for relative, data in files
            },
        )

        with (out_dir / "response.txt").open("x", encoding="utf-8") as file:
            file.write(text)

        raw_response = info.pop("raw_response", None)
        if raw_response is not None:
            save_json("llm_response.json", raw_response)

        result = 1
        if info.get("error"):
            info["generation_status"] = "api_error"
        elif info.get("response_status") != "completed":
            info["generation_status"] = "incomplete_response"
        else:
            try:
                data = json.loads(text)
                if not isinstance(data, dict):
                    raise ValueError("Response must be a JSON object")

                C = data.get("success_claim")
                P = data.get("confidence")
                patch = data.get("patch")

                if type(C) not in (bool, int) or C not in (0, 1):
                    raise ValueError("Invalid success_claim")
                if type(P) not in (int, float) or not 0 <= P <= 1:
                    raise ValueError("Invalid confidence")
                if not isinstance(patch, str):
                    raise ValueError("Patch must be a string")

                save_json("claim.json", {
                    "success_claim": bool(C),
                    "confidence": P,
                })
                with (out_dir / "patch.diff").open("x", encoding="utf-8") as file:
                    file.write(patch)

                info["generation_status"] = "ready_for_verification"
                result = 0

            except (ValueError, TypeError) as error:
                info["generation_status"] = "invalid_response"
                info["parse_error"] = str(error)

        info["frozen_at"] = datetime.now(timezone.utc).isoformat()
        save_json("generation.json", info)

        names = [
            "prompt.txt", "response.txt", "llm_response.json",
            "claim.json", "patch.diff", "generation.json",
        ]
        with (out_dir / "frozen.sha256").open("x", encoding="utf-8") as manifest:
            for name in names:
                path = out_dir / name
                if path.is_file():
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    manifest.write(f"{digest}  {name}\n")

        print(f"[generation] {vuln_id}: {info['generation_status']}")
        return result

    diff = extract_diff(text)
    (out_dir / "patch.diff").write_text(diff, encoding="utf-8")
    info.update({"agent": agent, "vuln_id": vuln_id, "context_files": [r for r, _ in files]})
    (out_dir / "generation.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return 0


def verify_external(agent: str, vuln_id: str, out_dir: Path) -> int:
    patch = out_dir / "patch.diff"
    if not patch.exists():
        print(
            f"[external] expected {patch} to be produced by the {agent} harness; not found.",
            file=sys.stderr,
        )
        return 2
    (out_dir / "generation.json").write_text(
        json.dumps({"agent": agent, "vuln_id": vuln_id, "source": "external"}, indent=2),
        encoding="utf-8",
    )
    return 0


def main():
    ap = argparse.ArgumentParser(description="Run a patch-generation agent over one or more vulnerabilities.")
    ap.add_argument("--agent", required=True, choices=sorted(BUILTIN | EXTERNAL))
    ap.add_argument("--model", help="Override model id (builtin agents only). "
                                    "Defaults: claude=claude-opus-4-7, gpt=gpt-4.1")
    ap.add_argument("--vuln-id", help="Single vuln to run; omit to scan all in workspaces/")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None, help="Cap how many vulns to process")
    ap.add_argument("--temperature", type=float, default=0.0,
                    help="Sampling temperature for the gpt builtin (default 0, paper-consistent)")
    args = ap.parse_args()

    model = args.model
    if args.agent == "claude" and not model:
        model = "claude-opus-4-7"
    elif args.agent == "gpt" and not model:
        model = "gpt-4.1"

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(
            p.name for p in args.workspaces.iterdir()
            if p.is_dir() and (p / "meta.json").exists()
        )
        if args.limit:
            targets = targets[: args.limit]

    if not targets:
        sys.exit(f"no vuln workspaces found under {args.workspaces}")

    n_ok = n_err = 0
    for vid in targets:
        case_dir = args.workspaces / vid
        out_dir = args.runs / args.agent / vid
        if not case_dir.exists():
            print(f"[!] {vid}: no workspace at {case_dir}; skipping", file=sys.stderr)
            n_err += 1
            continue

        if args.agent in BUILTIN:
            rc = run_builtin(args.agent, model, vid, case_dir, out_dir, temperature=args.temperature)
        else:
            rc = verify_external(args.agent, vid, out_dir)

        if rc == 0:
            n_ok += 1
            print(f"[+] {args.agent}/{vid}: OK")
        else:
            n_err += 1

    print(f"[done] {args.agent}: ok={n_ok}, err={n_err}, total={len(targets)}")


if __name__ == "__main__":
    main()
