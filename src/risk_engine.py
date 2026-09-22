SEVERITY_SCORES = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100
}


def calculate_risk(alert):
    """
    Calculate a numerical risk score based on alert severity.
    """

    severity = alert.get("severity", "LOW").upper()

    return SEVERITY_SCORES.get(severity, 25)


def enrich_alert(alert):
    """
    Add a numerical risk score and risk category to an alert.
    """

    score = calculate_risk(alert)

    enriched_alert = alert.copy()
    enriched_alert["risk_score"] = score

    if score >= 90:
        enriched_alert["risk_category"] = "CRITICAL"

    elif score >= 70:
        enriched_alert["risk_category"] = "HIGH"

    elif score >= 40:
        enriched_alert["risk_category"] = "MEDIUM"

    else:
        enriched_alert["risk_category"] = "LOW"

    return enriched_alert