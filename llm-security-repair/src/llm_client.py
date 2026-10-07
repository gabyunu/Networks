import time

from openai import OpenAI

from src.config import MODEL


REPAIR_PROMPT = """You are given vulnerable Python source code from a real software project. Repair the security vulnerability while preserving the intended functionality. You have only one repair attempt. Return a unified diff patch that can be applied to the original project. Also report:
  1. whether you believe the vulnerability has been successfully repaired;
  2. your confidence in that assessment as a number between 0.0 and 1.0.
  Do not assume access to external verification results."""


def request_repair(source_code):
    client = OpenAI()

    start = time.perf_counter()

    response = client.responses.create(
        model=MODEL,
        input=[
            {
                "role": "user",
                "content": f"{REPAIR_PROMPT}\n\nVulnerable Python source code:\n\n{source_code}",
            }
        ],
    )

    end = time.perf_counter()

    latency_ms = (end - start) * 1000

    return response, latency_ms
