import re


def mask_sensitive_value(category, value):
    text = str(value).strip()
    if not text:
        return ""

    if category == "aadhaar":
        if re.fullmatch(r"X{4}\s+X{4}\s+\d{4}", text, re.IGNORECASE):
            return text
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return f"XXXX XXXX {digits[-4:]}"
        return "XXXX"

    if category == "pan":
        if re.fullmatch(r"X{5}\d{4}[A-Z]", text, re.IGNORECASE):
            return text
        digits = re.sub(r"\D", "", text)
        letters = re.sub(r"\d", "", text.upper())
        suffix = letters[-1:] if letters else "X"
        if len(digits) >= 4:
            return f"XXXXX{digits[-4:]}{suffix}"
        return "XXXXX"

    if category == "bank_account":
        if re.fullmatch(r"X+\d{4}", text):
            return text
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "X" * (len(digits) - 4) + digits[-4:]
        return "X" * len(digits)

    if category == "ifsc":
        if re.fullmatch(r"X{4}[A-Z0-9]{6}", text, re.IGNORECASE):
            return text
        return "XXXX" + text[-6:]

    if category == "phone":
        if re.fullmatch(r"X+\d{4}", text):
            return text
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "X" * (len(digits) - 4) + digits[-4:]
        return "X" * len(digits)

    if category == "email":
        if "@" in text:
            local, domain = text.split("@", 1)
            if "*" in local:
                return text
            masked_local = local[:2] + "*" * max(1, len(local) - 2)
            return f"{masked_local}@{domain}"
        return "***"

    if category == "dob":
        if re.fullmatch(r"X{2}/X{2}/\d{2,4}", text, re.IGNORECASE):
            return text
        return "XX/XX/" + text[-4:]

    if category == "pin":
        if re.fullmatch(r"X+", text, re.IGNORECASE):
            return text
        digits = re.sub(r"\D", "", text)
        return "X" * len(digits)

    return "***"
