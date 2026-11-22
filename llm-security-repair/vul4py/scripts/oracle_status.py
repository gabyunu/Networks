def classify_oracle(rc, summary):
    """Return (status, indicator, reason) for one test suite."""
    if rc == 999:
        return "incomplete", None, "missing_tests"
    if rc not in (0, 1):
        return "incomplete", None, "execution_error"
    if summary is None:
        return "incomplete", None, "missing_or_invalid_report"
    if summary["errored"] > 0:
        return "incomplete", None, "test_execution_error"
    if summary["passed"] + summary["failed"] == 0:
        return "incomplete", None, "no_executed_tests"
    if rc == 0 and summary["failed"] == 0:
        return "passed", 1, ""
    if rc == 1 and summary["failed"] > 0:
        return "failed", 0, "test_failures"
    return "incomplete", None, "inconsistent_report"


def repair_metrics(A, F, S, C, verification_status):
    indicators = (A, F, S)

    if verification_status != "complete":
        return None, None

    if any(value not in (0, 1) for value in indicators):
        return None, None

    verified_repair = A * F * S
    false_assurance = C * (1 - verified_repair) if C in (0, 1) else None

    return verified_repair, false_assurance
