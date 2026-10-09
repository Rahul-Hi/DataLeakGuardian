import re


def mask_sensitive_value(category, value):
    text = str(value).strip()
    if not text:
        return ""

    if category == "aadhaar":
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return f"XXXX XXXX {digits[-4:]}"
        return "XXXX"

    if category == "pan":
        digits = re.sub(r"\D", "", text)
        letters = re.sub(r"\d", "", text.upper())
        if len(digits) >= 4:
            return f"XXXXX{digits[-4:]}{letters[-1:] if letters else 'X'}"
        return "XXXXX"

    if category == "bank_account":
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "X" * (len(digits) - 4) + digits[-4:]
        return "X" * len(digits)

    if category == "ifsc":
        return "XXXX" + text[-6:]

    if category == "phone":
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "X" * (len(digits) - 4) + digits[-4:]
        return "X" * len(digits)

    if category == "email":
        if "@" in text:
            local, domain = text.split("@", 1)
            masked_local = local[:2] + "*" * max(1, len(local) - 2)
            return f"{masked_local}@{domain}"
        return "***"

    if category == "dob":
        return "XX/XX/" + text[-4:]

    if category == "pin":
        digits = re.sub(r"\D", "", text)
        return "X" * len(digits)

    return "***"
