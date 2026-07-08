import hashlib
import json
import secrets
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

    common_slds = {
        "co",
        "com",
        "org",
        "gov",
        "edu",
        "net",
        "mil",
        "asn",
        "id",
        "ltd",
        "me",
        "plc",
        "sch",
    }

    def get_family_slice(labels: list[str]) -> list[str]:
        if len(labels) >= 3:
            tld = labels[-1]
            sld = labels[-2]
            if len(tld) == 2 and sld in common_slds:
                return labels[-3:]
        return labels[-2:]

    return get_family_slice(left_labels) == get_family_slice(right_labels)


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
    normalized = [str(part).replace("\\", "\\\\").replace("|", "\\|").strip() for part in parts]
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


_SYSTEM_RANDOM = secrets.SystemRandom()


def _positive_int(value: object, default: int) -> int:
    try:
        if isinstance(value, (int, float)):
            parsed = int(value)
        else:
            parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def _positive_float(value: object, default: float) -> float:
    try:
        if isinstance(value, (int, float)):
            parsed = float(value)
        else:
            parsed = float(str(value))
    except (TypeError, ValueError):
        return default
    return max(0.0, parsed)


class RetryPolicy:
    """Immutable retry configuration.

    This is a core contract class that defines retry policy without
    depending on pipeline-specific logic. Pipeline and execution layers
    both depend on this class.
    """

    def __init__(
        self,
        max_attempts: int = 1,
        initial_backoff_seconds: float = 0.0,
        backoff_multiplier: float = 2.0,
        max_backoff_seconds: float = 8.0,
        retry_on_timeout: bool = True,
        retry_on_error: bool = True,
        jitter_factor: float = 0.25,
    ) -> None:
        self.max_attempts = max_attempts
        self.initial_backoff_seconds = initial_backoff_seconds
        self.backoff_multiplier = backoff_multiplier
        self.max_backoff_seconds = max_backoff_seconds
        self.retry_on_timeout = retry_on_timeout
        self.retry_on_error = retry_on_error
        self.jitter_factor = jitter_factor

    @classmethod
    def from_settings(
        cls,
        global_settings: dict[str, Any] | None = None,
        tool_settings: dict[str, Any] | None = None,
    ) -> "RetryPolicy":
        global_settings = global_settings or {}
        tool_settings = tool_settings or {}
        retry_attempts = _positive_int(
            tool_settings.get(
                "retry_attempts",
                global_settings.get("retry_attempts", RETRY_DEFAULTS["retry_attempts"]),
            ),
            int(RETRY_DEFAULTS["retry_attempts"]),
        )
        return cls(
            max_attempts=max(1, retry_attempts + 1),
            initial_backoff_seconds=_positive_float(
                tool_settings.get(
                    "retry_backoff_seconds",
                    global_settings.get(
                        "retry_backoff_seconds", RETRY_DEFAULTS["retry_backoff_seconds"]
                    ),
                ),
                float(RETRY_DEFAULTS["retry_backoff_seconds"]),
            ),
            backoff_multiplier=max(
                1.0,
                _positive_float(
                    tool_settings.get(
                        "retry_backoff_multiplier",
                        global_settings.get(
                            "retry_backoff_multiplier",
                            RETRY_DEFAULTS["retry_backoff_multiplier"],
                        ),
                    ),
                    float(RETRY_DEFAULTS["retry_backoff_multiplier"]),
                ),
            ),
            max_backoff_seconds=max(
                0.0,
                _positive_float(
                    tool_settings.get(
                        "retry_max_backoff_seconds",
                        global_settings.get(
                            "retry_max_backoff_seconds",
                            RETRY_DEFAULTS["retry_max_backoff_seconds"],
                        ),
                    ),
                    float(RETRY_DEFAULTS["retry_max_backoff_seconds"]),
                ),
            ),
            retry_on_timeout=bool(
                tool_settings.get(
                    "retry_on_timeout",
                    global_settings.get("retry_on_timeout", RETRY_DEFAULTS["retry_on_timeout"]),
                )
            ),
            retry_on_error=bool(
                tool_settings.get(
                    "retry_on_error",
                    global_settings.get("retry_on_error", RETRY_DEFAULTS["retry_on_error"]),
                )
            ),
            jitter_factor=_positive_float(
                tool_settings.get("retry_jitter", global_settings.get("retry_jitter", 0.25)),
                0.25,
            ),
        )

    def delay_for_attempt(self, attempt_number: int, jitter: float | None = None) -> float:
        """Calculate backoff with exponential growth and jitter to prevent thundering herd."""
        if attempt_number <= 1:
            return 0.0
        effective_backoff = max(0.0, self.initial_backoff_seconds)
        base_delay = effective_backoff * (self.backoff_multiplier ** max(0, attempt_number - 2))
        if self.max_backoff_seconds > 0:
            base_delay = min(base_delay, self.max_backoff_seconds)

        jitter_factor = self.jitter_factor if jitter is None else max(0.0, float(jitter))
        jitter_range = base_delay * jitter_factor
        jittered = base_delay + (_SYSTEM_RANDOM.random() * 2 - 1) * jitter_range
        return float(max(0.0, jittered))
