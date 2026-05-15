import hashlib
import json
from typing import Any
from urllib.parse import urlparse

REQUIRED_CONFIG_FIELDS = ("target_name", "output_dir")
CONFIG_DEFAULTS = {
    "http_timeout_seconds": 12,
    "mode": "default",
}

OUTPUT_JSON_SCHEMA = {
    "validation_result": {
        "schema_version": "validation_result.v2",
        "required_fields": (
            "schema_version",
            "validator",
            "category",
            "status",
            "url",
            "in_scope",
            "scope_reason",
            "score",
            "confidence",
            "validation_state",
            "signals",
            "evidence",
            "http",
            "error",
            "validation_actions",
        ),
    },
    "validation_runtime": {
        "schema_version": "validation_runtime.v2",
        "required_fields": ("schema_version", "results", "errors", "settings"),
    },
}

LOGGING_FORMAT = {
    "progress_prefix": "PIPELINE_PROGRESS ",
    "warning_prefix": "Warning: ",
    "error_prefix": "Error: ",
}

JSON_FORMAT = {
    "indent": 2,
    "ensure_ascii": True,
}

TIMEOUT_DEFAULTS = {
    "http_request_seconds": 12,
    "tool_command_seconds": 120,
    "api_test_seconds": 10,
}

RETRY_DEFAULTS = {
    "retry_attempts": 0,
    "retry_backoff_seconds": 2.0,
    "retry_backoff_multiplier": 1.0,
    "retry_max_backoff_seconds": 2.0,
    "retry_on_timeout": True,
    "retry_on_error": True,
}

SCOPE_RULES = {
    "host_match": "exact_or_host_family",
    "empty_scope_behavior": "allow_with_scope_unavailable_reason",
    "missing_host_behavior": "deny",
}

DEDUP_KEYS = {
    "sensitive_data_scanner": ("url", "indicator", "snippet_prefix"),
    "technology_fingerprint": ("url", "technology"),
    "behavior_replay": ("endpoint_key", "parameter", "variant", "mutated_url"),
    "finding_identity": ("module", "category", "endpoint_base", "title", "evidence_json"),
}

VALIDATION_RESULT_SCHEMA_VERSION = OUTPUT_JSON_SCHEMA["validation_result"]["schema_version"]
VALIDATION_RUNTIME_SCHEMA_VERSION = OUTPUT_JSON_SCHEMA["validation_runtime"]["schema_version"]


def same_host_family(left: str, right: str) -> bool:
    left_labels = [part for part in left.lower().split(".") if part]
    right_labels = [part for part in right.lower().split(".") if part]
    if not left_labels or not right_labels:
        return False
    return left_labels[-2:] == right_labels[-2:]


def scope_match(url: str, scope_hosts: set[str]) -> tuple[bool, str]:
    host = (urlparse(str(url)).hostname or "").lower()
    if not host:
        return False, "missing_host"
    if not scope_hosts:
        return True, "scope_unavailable"
    if host in scope_hosts:
        return True, "exact_match"
    if any(same_host_family(host, allowed) for allowed in scope_hosts):
        return True, "host_family_match"
    return False, "outside_scope"


def dedup_key(*parts: object) -> str:
    normalized = [str(part).strip() for part in parts]
    return "|".join(normalized)


def dedup_digest(*parts: object, length: int = 12) -> str:
    # Use a stronger hash (SHA-256) for non-cryptographic dedup keys
    digest = hashlib.sha256(dedup_key(*parts).encode("utf-8")).hexdigest()
    return digest[: max(4, int(length))]


def json_payload(payload: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(payload, indent=JSON_FORMAT["indent"])
    return json.dumps(payload, ensure_ascii=bool(JSON_FORMAT["ensure_ascii"]))


def validation_finding_fixture(**overrides: Any) -> dict[str, Any]:
    fixture = {
        "schema_version": VALIDATION_RESULT_SCHEMA_VERSION,
        "validator": "fixture",
        "category": "fixture",
        "status": "ok",
        "url": "https://example.com",
        "in_scope": True,
        "scope_reason": "exact_match",
        "score": 1,
        "confidence": 0.1,
        "validation_state": "passive_only",
        "signals": [],
        "evidence": {},
        "http": {
            "requested_url": "https://example.com",
            "final_url": "https://example.com",
            "status_code": 200,
            "redirect_count": 0,
            "attempts": 1,
            "timeout_seconds": TIMEOUT_DEFAULTS["http_request_seconds"],
            "latency_seconds": 0.01,
            "error": "",
        },
        "error": {},
        "validation_actions": [
            {
                "action": "passive_review",
                "score": 1,
                "reason": "Record evidence and keep this item for manual/passive follow-up.",
            }
        ],
    }
    fixture.update(overrides)
    return fixture


def validation_runtime_fixture(**overrides: Any) -> dict[str, Any]:
    fixture = {
        "schema_version": VALIDATION_RUNTIME_SCHEMA_VERSION,
        "results": {"fixture_validation": [validation_finding_fixture()]},
        "errors": [],
        "settings": {
            "timeout_seconds": TIMEOUT_DEFAULTS["http_request_seconds"],
            "retry_attempts": RETRY_DEFAULTS["retry_attempts"],
            "retry_backoff_seconds": RETRY_DEFAULTS["retry_backoff_seconds"],
            "active_probe_enabled": True,
            "per_validator_limit": 10,
            "scope_hosts_count": 1,
            "enabled_validators": ["fixture"],
            "available_validators": ["fixture"],
        },
    }
    fixture.update(overrides)
    return fixture
