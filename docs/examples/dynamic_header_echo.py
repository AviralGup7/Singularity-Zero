from typing import Any

PLUGIN_MANIFEST = {
    "id": "example.header_echo",
    "name": "Header Echo Check",
    "version": "1.0.0",
    "kind": "analysis",
    "description": "Example dynamic check that reports a low-risk debug header signal.",
    "group": "exposure",
    "entrypoint": "run",
    "sandbox": "process",
    "enabled_by_default": False,
    "capabilities": ["passive-http"],
    "tags": ["example", "headers"],
    "timeout_seconds": 10,
}


def run(payload: dict[str, Any]) -> list[dict[str, Any]]:
    response = payload.get("response", {})

    headers = response.get("headers", {})
    normalized = {str(key).lower(): value for key, value in headers.items()}
    if "x-debug" not in normalized:
        return []
    return [
        {
            "title": "Debug header exposed",
            "severity": "low",
            "confidence": 0.7,
            "evidence": {"header": "x-debug", "value": normalized["x-debug"]},
        }
    ]
