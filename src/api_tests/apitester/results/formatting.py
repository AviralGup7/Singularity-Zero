def clean_text(value: object, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def clean_bool(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def clean_number(value: object, *, digits: int = 3) -> str:
    if value in (None, ""):
        return "n/a"
    try:
        rounded = round(float(str(value)), digits)
        if digits == 0:
            return str(int(rounded))
        return str(rounded)
    except (TypeError, ValueError):
        return clean_text(value, "n/a")
