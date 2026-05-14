from urllib.parse import urlparse


class SchemaValidationError(ValueError):
    pass


def _require_mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SchemaValidationError(f"{name} must be a mapping")
    return value


def _require_list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise SchemaValidationError(f"{name} must be a list")
    return value


def _require_url(value: object, name: str) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if not parsed.scheme or not parsed.netloc:
        raise SchemaValidationError(f"{name} must be an absolute URL")
    return text


def validate_recon_payload(payload: dict[str, object]) -> dict[str, object]:
    data = _require_mapping(payload, "recon payload")
    urls = data.get("urls", [])
    for index, url in enumerate(_require_list(urls, "recon payload.urls")):
        _require_url(url, f"recon payload.urls[{index}]")
    live_hosts = data.get("live_hosts", [])
    _require_list(live_hosts, "recon payload.live_hosts")
    return data


def validate_detection_payload(payload: dict[str, object]) -> dict[str, object]:
    data = _require_mapping(payload, "detection payload")
    for key, items in data.items():
        bucket = _require_list(items, f"detection payload.{key}")
        for index, item in enumerate(bucket):
            row = _require_mapping(item, f"detection payload.{key}[{index}]")
            if "url" in row:
                _require_url(row.get("url"), f"detection payload.{key}[{index}].url")
    return data


def validate_analysis_payload(payload: dict[str, object]) -> dict[str, object]:
    data = _require_mapping(payload, "analysis payload")
    findings = _require_list(data.get("findings", []), "analysis payload.findings")
    for index, item in enumerate(findings):
        row = _require_mapping(item, f"analysis payload.findings[{index}]")
        _require_url(row.get("url"), f"analysis payload.findings[{index}].url")
    return data


def validate_decision_payload(payload: dict[str, object]) -> dict[str, object]:
    data = _require_mapping(payload, "decision payload")
    findings = _require_list(data.get("findings", []), "decision payload.findings")
    for index, item in enumerate(findings):
        row = _require_mapping(item, f"decision payload.findings[{index}]")
        if "decision" not in row:
            raise SchemaValidationError(f"decision payload.findings[{index}] is missing decision")
    return data


def validate_execution_payload(payload: dict[str, object]) -> dict[str, object]:
    data = _require_mapping(payload, "execution payload")
    _require_mapping(data.get("results", {}), "execution payload.results")
    _require_list(data.get("errors", []), "execution payload.errors")
    return data
