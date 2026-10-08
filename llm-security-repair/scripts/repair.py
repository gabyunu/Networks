import json
import time
from pathlib import Path

from openai import OpenAI

from src.config import MODEL


CASES = [
    "CVE-2021-32839",
    "CVE-2022-3102",
    "CVE-2023-30608",
    "CVE-2023-47163",
]

PROMPT = """You are given vulnerable Python source code from a real software project.

Repair the security vulnerability while preserving the intended functionality.

You have exactly one repair attempt.

Return ONLY a JSON object with these fields:
{
  "patch": "unified diff patch",
  "success_claim": true,
  "confidence": 0.0
}

The patch must be a unified diff that can be applied to the original project.

Do not assume access to external verification results.
Do not describe tests or verification that you have not performed.
"""


def main():
    client = OpenAI()

    for cve in CASES:
        workspace = Path("vul4py/workspaces") / cve
        meta_file = workspace / "meta.json"

        meta = json.loads(meta_file.read_text())
        code_files = meta.get("new_code_files", [])

        if not code_files:
            print(f"[ERROR] No code file listed for {cve}")
            continue

        for relative_file in code_files:
            source_file = workspace / "vulnerable" / relative_file

            if not source_file.exists():
                print(f"[ERROR] Source not found: {source_file}")
                continue

            source_code = source_file.read_text()

            print(f"[+] Sending {cve}: {relative_file} to {MODEL}...")

            start = time.perf_counter()

            response = client.responses.create(
                model=MODEL,
                input=[
                    {
                        "role": "user",
                        "content": (
                            PROMPT
                            + f"\n\nVulnerable source file: {relative_file}\n\n"
                            + source_code
                        ),
                    }
                ],
            )

            latency_ms = (time.perf_counter() - start) * 1000
            output_text = response.output_text

            result_dir = Path("results") / cve
            result_dir.mkdir(parents=True, exist_ok=True)

            (result_dir / "response.txt").write_text(output_text)
            (result_dir / "latency_ms.txt").write_text(
                f"{latency_ms:.2f}\n"
            )

            try:
                data = json.loads(output_text)

                patch = data["patch"]
                success_claim = data["success_claim"]
                confidence = data["confidence"]

                (result_dir / "patch.diff").write_text(patch)

                with open(result_dir / "claim.json", "w") as f:
                    json.dump(
                        {
                            "success_claim": success_claim,
                            "confidence": confidence,
                        },
                        f,
                        indent=2,
                    )

                print(
                    f"[OK] {cve}: latency={latency_ms:.2f} ms"
                )

            except Exception as e:
                print(
                    f"[ERROR] {cve}: invalid JSON response: {e}"
                )

    print("[+] Done.")


if __name__ == "__main__":
    main()
