import re
from datetime import datetime

from app.services.extraction_service import normalize_extracted_text


SENSITIVE_TYPES = {
    "aadhaar": "aadhaar",
    "pan": "pan",
    "bank_account": "bank_account",
    "ifsc": "ifsc",
    "phone": "phone",
    "email": "email",
    "dob": "dob",
    "pin": "pin",
}


def _context_for(text, position, length):
    start = max(0, position - 40)
    end = min(len(text), position + length + 40)
    return text[start:end].lower()


def _safe_value(value):
    return re.sub(r"\s+", "", value.strip())


def _get_confidence(type_name, evidence):
    return {
        "aadhaar": 0.95,
        "pan": 0.96,
        "bank_account": 0.88,
        "ifsc": 0.97,
        "phone": 0.92,
        "email": 0.98,
        "dob": 0.94,
        "pin": 0.9,
    }.get(type_name, 0.8), evidence


def _build_context_snippet(text, position, match_length, window=35):
    if not text:
        return ""
    start = max(0, position - window)
    end = min(len(text), position + match_length + window)

    prefix = text[start:position]
    suffix = text[position + match_length : end]

    prefix_clean = re.sub(r"\s+", " ", prefix)
    suffix_clean = re.sub(r"\s+", " ", suffix)

    lead_ellipsis = "... " if start > 0 else ""
    trail_ellipsis = " ..." if end < len(text) else ""

    return f"{lead_ellipsis}{prefix_clean}[MATCH]{suffix_clean}{trail_ellipsis}".strip()


def _add_finding(findings, type_name, value, position, evidence, context_snippet=""):
    cleaned_value = value.strip()
    if not cleaned_value:
        return
    confidence, evidence_text = _get_confidence(type_name, evidence)
    findings.append(
        {
            "type": type_name,
            "value": cleaned_value,
            "position": position,
            "confidence": confidence,
            "evidence": evidence_text,
            "context_snippet": context_snippet or "[MATCH]",
        }
    )


def _is_valid_date(date_str):
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d/%m/%y", "%d-%m-%y"):
        try:
            datetime.strptime(date_str, fmt)
            return True
        except ValueError:
            continue
    return False


def detect_sensitive_data(text):
    if not text:
        return []

    normalized = normalize_extracted_text(text)
    findings = []

    # Email
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    for match in email_pattern.finditer(normalized):
        value = match.group(0)
        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["email"],
            value,
            match.start(),
            "Email regex matched a valid email address.",
            snippet,
        )

    # PAN
    pan_pattern = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE)
    for match in pan_pattern.finditer(normalized):
        value = match.group(0).upper()
        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["pan"],
            value,
            match.start(),
            "PAN pattern matched a valid format.",
            snippet,
        )

    # IFSC
    ifsc_pattern = re.compile(r"\b[A-Z]{4}[0][A-Z0-9]{6}\b")
    for match in ifsc_pattern.finditer(normalized):
        value = match.group(0).upper()
        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["ifsc"],
            value,
            match.start(),
            "IFSC pattern matched a valid bank code format.",
            snippet,
        )

    # Phone
    phone_pattern = re.compile(
        r"(?:\+?91[\s-]?)?(?:\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}|\(?\d{5}\)?[\s-]?\d{5}|\d{10})"
    )
    for match in phone_pattern.finditer(normalized):
        value = match.group(0)
        compact = re.sub(r"[^0-9+]", "", value)
        digits_only = re.sub(r"\D", "", compact)

        if len(digits_only) == 12 and not digits_only.startswith("91"):
            continue
        if len(digits_only) not in {10, 12}:
            continue

        context = _context_for(normalized, match.start(), len(value)).lower()
        has_context = any(keyword in context for keyword in ["phone", "mobile", "contact", "tel", "call", "cell", "ph"])
        if not has_context and not compact.startswith("+91"):
            continue

        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["phone"],
            value,
            match.start(),
            "Phone pattern matched a valid Indian contact number format.",
            snippet,
        )

    # Aadhaar
    aadhaar_pattern = re.compile(r"(?<!\d)(?:\d[ -]?){12}(?!\d)")
    for match in aadhaar_pattern.finditer(normalized):
        value = match.group(0)
        compact = re.sub(r"[^0-9]", "", value)
        if len(compact) != 12:
            continue
        context = _context_for(normalized, match.start(), len(value)).lower()
        if "aadhaar" not in context and "uid" not in context and "unique identification" not in context:
            continue
        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["aadhaar"],
            value,
            match.start(),
            "Aadhaar pattern matched a 12-digit identifier in an Aadhaar context.",
            snippet,
        )

    # Bank account number
    bank_pattern = re.compile(r"(?<!\d)(\d{9,18})(?!\d)")
    for match in bank_pattern.finditer(normalized):
        value = match.group(0)
        context = _context_for(normalized, match.start(), len(value)).lower()
        has_context = any(
            keyword in context
            for keyword in ["account", "a/c", "bank", "bank a/c", "account no", "acct", "acc no"]
        )
        if not has_context:
            continue
        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["bank_account"],
            value,
            match.start(),
            "Bank account number matched a numeric identifier in a financial context.",
            snippet,
        )

    # Date of Birth
    dob_pattern = re.compile(
        r"\b(?:0?[1-9]|[12]\d|3[01])(?:[/-](?:0?[1-9]|1[0-2]))(?:[/-](?:\d{4}|\d{2}))\b"
    )
    for match in dob_pattern.finditer(normalized):
        value = match.group(0)
        compact = value.replace("/", "-")
        if not _is_valid_date(compact):
            continue
        if "dob" not in _context_for(normalized, match.start(), len(value)).lower() and "date of birth" not in normalized.lower():
            if re.search(r"\b(?:birth|dob|date of birth)\b", normalized, re.IGNORECASE) is None:
                continue
        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["dob"],
            value,
            match.start(),
            "Date of birth matched a valid date format.",
            snippet,
        )

    # PIN / Postal Code
    pin_pattern = re.compile(r"(?<!\d)(?:\d[ -]?){6}(?!\d)")
    for match in pin_pattern.finditer(normalized):
        value = match.group(0)
        compact = re.sub(r"[^0-9]", "", value)
        if len(compact) != 6:
            continue
        context = _context_for(normalized, match.start(), len(value)).lower()
        if "pin" not in context and "postal" not in context and "zip" not in context and "pincode" not in context:
            continue
        snippet = _build_context_snippet(normalized, match.start(), len(value))
        _add_finding(
            findings,
            SENSITIVE_TYPES["pin"],
            value,
            match.start(),
            "PIN/postal code matched a six-digit location code in a location context.",
            snippet,
        )

    return findings
