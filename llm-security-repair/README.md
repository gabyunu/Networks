# Measuring False Assurance in LLM-Based Vulnerability Repair

This project compares an LLM's repair claims with independent Vul4Py verification.

## Current experimental status

| Case | Status | C | A | F | S | Verified repair | False assurance |
|---|---|---|---|---|---|---|---|
| CVE-2021-32839 | Complete; existing evidence audited | 1 | 1 | 1 | 1 | 1 | 0 |
| CVE-2022-3102 | Complete; existing evidence audited | 1 | 1 | 0 | 0 | 0 | 1 |
| CVE-2023-30608 | Complete; patch rejected | 1 | 0 | 0 | 0 | 0 | 1 |
| CVE-2023-47163 | Incomplete; invalid JSON response | — | — | — | — | — | — |

Four attempts are recorded. Three observations are complete.
The fifth attempt required by the assignment remains pending.

For the three completed observations:

- VRR = 1 / 3 = 33.33%.
- FAR = 2 / 3 = 66.67%.
- All three completed observations contain positive repair claims.

These are preliminary results from a small sample.

## Installation

The current machine is AWS EC2 running Amazon Linux 2023.

From the llm-security-repair directory:

```bash
python3.12 -m venv venv312
source venv312/bin/activate
python -m pip install -r requirements.txt
```

Vul4Py prepares separate environments for benchmark projects.
See vul4py/README.md for downloading projects and checking their test oracles.

## Reproduce the result aggregation

```bash
python3.12 scripts/export_results.py
```

Outputs:

- results.csv: all recorded attempts, including incomplete observations.
- metrics.json: counts, denominators, VRR and FAR.

Aggregation uses audited_eval.json when available and otherwise eval.json.
The archived JUnit reports and logs support the historical audits.

## API generation

The historical generation script is scripts/repair.py.
Its fixed instructions are stored in PROMPT.

It sends vulnerable source through the OpenAI Python client and requests:

- a unified-diff patch;
- success_claim;
- confidence between 0 and 1.

The configured model identifier is gpt-6-luna.
The API key is read from OPENAI_API_KEY.

Existing responses belong to the recorded experiment and must be preserved.
Future generation requires a separate run location and complete generation
records before additional repair attempts are made.

## Freezing and verification

The original responses are stored under results/<case>/.

For CVE-2023-30608, frozen.sha256 records the hashes of the response,
claim and patch. They were checked before and after verification.

```bash
sha256sum -c results/CVE-2023-30608/frozen.sha256
```

The evaluator uses:

```bash
python3.12 vul4py/scripts/evaluate.py --agent gpt --vuln-id CASE_ID
```

This command writes evaluation records. Use it for a prepared case;
preserve existing evidence when planning any further verification.

Verification performs these checks:

1. Apply the submitted patch to a copy of the vulnerable project.
2. Run functional tests.
3. Run security tests on that candidate.

The evaluator reads JUnit reports to check actual test execution.
Missing tests, execution errors and unavailable reports are incomplete.

A confirmed patch rejection sets A=F=S=0 and leaves tests unexecuted.
For completed verification, V=A*F*S and FA=C*(1-V).

The verification results are not sent to the repair model.

## Evidence

- results/<case>/: original responses, claims, patches and API latency.
- vul4py/runs/gpt/<case>/eval.json: evaluation records.
- audited_eval.json: indicators reconstructed from existing evidence.
- audit_evidence/: preserved historical responses, JUnit reports and logs.
- patch_apply.log: patch rejection evidence.
- format_error.json: diagnosis of the malformed response.

Historical eval.json files were preserved during auditing.

## Network communication

The Python application runs on EC2. DNS resolves the API hostname to
IP addresses. The client establishes a TCP connection, normally to port
443, and TLS encrypts the HTTPS communication.

The request carries instructions and source code; the response carries
the model output. JSON represents structured data.

Recorded API latency measures the client request/response duration.
It includes service processing and model generation as well as network
effects; it is not a separate measurement of network delay.

## Limitations and pending work

- Complete and document the fifth required attempt.
- Preserve tokens, generation timestamps, returned model identifier and
  API errors in future generation records. These historical metadata
  fields cannot be reconstructed reliably from response text alone.
- Enforce separate, non-overwriting generation runs.
- Historical results include audited evidence and must be identified as such.
- Passing Vul4Py checks establishes the benchmark's expected behavior;
  it does not prove the absence of all possible vulnerabilities.
- Future experiments should increase the sample and document their
  model, prompt, benchmark revision and execution environment.
