from collections import OrderedDict

from app.services.detection_service import detect_sensitive_data

WEIGHTS = {
    "aadhaar": 30,
    "pan": 20,
    "bank_account": 25,
    "ifsc": 10,
    "phone": 15,
    "email": 10,
    "dob": 15,
    "pin": 20,
}

RISK_LEVELS = [
    (0, 24, "Low"),
    (25, 49, "Moderate"),
    (50, 74, "High"),
    (75, 100, "Critical"),
]


def _risk_level_for(score):
    for lower, upper, label in RISK_LEVELS:
        if lower <= score <= upper:
            return label
    return "Critical"


def calculate_privacy_risk(text_or_findings):
    findings = []
    if isinstance(text_or_findings, list):
        findings = text_or_findings
    else:
        findings = detect_sensitive_data(text_or_findings or "")

    unique = []
    seen = set()
    for item in findings:
        key = (item.get("type"), item.get("value"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    category_summary = OrderedDict()
    category_contributions = OrderedDict()
    explanations = []

    for category in WEIGHTS:
        category_summary[category] = 0
        category_contributions[category] = 0

    for item in unique:
        category = item.get("type")
        if category not in WEIGHTS:
            continue
        category_summary[category] += 1
        category_contributions[category] += WEIGHTS[category]

    total_score = min(100, sum(category_contributions.values()))
    risk_level = _risk_level_for(total_score)

    for category, weight in WEIGHTS.items():
        count = category_summary.get(category, 0)
        contribution = category_contributions.get(category, 0)
        if count > 0:
            explanations.append(
                f"{category.replace('_', ' ').title()} detected {count} time(s); contributed {contribution} points."
            )

    if not explanations:
        explanations.append("No sensitive findings were detected.")

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "detected_category_summary": category_summary,
        "score_contribution_of_each_category": category_contributions,
        "explanations": explanations,
    }
