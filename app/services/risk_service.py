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


REMEDIATION_GUIDELINES = {
    "aadhaar": "Aadhaar / National ID: Mask the first 8 digits (e.g. XXXX XXXX 1234) per UIDAI regulations before distributing or archiving.",
    "pan": "PAN Tax Identifier: Redact Permanent Account Numbers from non-tax documents to prevent financial identity exposure.",
    "bank_account": "Bank Account Number: Obfuscate to the last 4 digits (e.g. XXXXXXXX1234) in compliance with PCI-DSS and banking security guidelines.",
    "ifsc": "IFSC Code: Remove branch routing codes when coupled with account holder data to prevent financial fraud targeting.",
    "phone": "Personal Phone Number: Mask contact digits to mitigate spamming, smishing, and unauthorized social engineering.",
    "email": "Email Address: Sanitize or partially mask email handles (e.g. us***@domain.com) in shared public documents to avoid spear-phishing.",
    "dob": "Date of Birth: Obfuscate full birth dates (retain year only if required) to prevent identity verification bypasses.",
    "pin": "Postal PIN Code: Remove precise postal location codes if paired with identity details to avoid geographic profiling.",
}


def get_remediations_for_categories(categories):
    remediations = []
    for cat in categories:
        if cat in REMEDIATION_GUIDELINES:
            remediations.append(REMEDIATION_GUIDELINES[cat])
    if not remediations:
        remediations.append("No immediate remediation required: Document appears clean of supported sensitive categories.")
    return remediations


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

    active_categories = [cat for cat in WEIGHTS if category_summary.get(cat, 0) > 0]
    remediations = get_remediations_for_categories(active_categories)

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "detected_category_summary": category_summary,
        "score_contribution_of_each_category": category_contributions,
        "explanations": explanations,
        "remediations": remediations,
    }
