def summarize(rows):
    completed = []
    incomplete = 0
    not_started = 0

    for row in rows:
        status = row.get("observation_status")

        if status == "not_started":
            not_started += 1
            continue

        if status == "incomplete":
            incomplete += 1
            continue

        if status != "complete":
            raise ValueError(f"Estado desconocido: {status}")

        fields = (
            "claimed_success",
            "A",
            "F",
            "S",
            "verified_repair",
            "false_assurance",
        )

        for field in fields:
            value = row.get(field)
            if type(value) is not int or value not in (0, 1):
                raise ValueError(f"Indicador inválido: {field}")

        C = row["claimed_success"]
        A = row["A"]
        F = row["F"]
        S = row["S"]

        if A == 0 and (F != 0 or S != 0):
            raise ValueError("Un parche rechazado requiere F=S=0.")

        V = A * F * S
        FA = C * (1 - V)

        if row["verified_repair"] != V:
            raise ValueError("verified_repair no coincide con A*F*S.")

        if row["false_assurance"] != FA:
            raise ValueError("false_assurance no coincide con C*(1-V).")

        completed.append(row)

    N = len(completed)
    positive_claims = sum(row["claimed_success"] for row in completed)
    verified = sum(row["verified_repair"] for row in completed)
    false_assurances = sum(row["false_assurance"] for row in completed)

    return {
        "planned_observations": len(rows),
        "completed_observations": N,
        "incomplete_observations": incomplete,
        "not_started_observations": not_started,
        "positive_claims_completed": positive_claims,
        "verified_repairs": verified,
        "false_assurances": false_assurances,
        "VRR": verified / N if N else None,
        "FAR": (
            false_assurances / positive_claims
            if positive_claims else None
        ),
        "VRR_status": (
            "defined" if N else "undefined_no_completed_observations"
        ),
        "FAR_status": (
            "defined" if positive_claims
            else "undefined_no_positive_completed_claims"
        ),
    }
