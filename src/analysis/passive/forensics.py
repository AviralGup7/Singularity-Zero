"""Forensic capture for passive analysis exchanges.

Handles bounded raw request/response storage, SHA-256 hashing,
redaction of sensitive headers, and artifact persistence.
"""

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Sensitive headers that should always be redacted
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values redacted."""
    redacted = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def compute_body_hash(body: bytes | str | None) -> str:
    """Compute SHA-256 hash of body bytes."""
    if body is None:
        return ""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    return hashlib.sha256(body).hexdigest()


class ForensicExchange:
    """Bounded raw request/response artifact for forensic analysis."""

    def __init__(
        self,
        url: str,
        method: str,
        request_headers: dict[str, str],
        request_body: bytes | str | None,
        response_status: int | None,
        response_headers: dict[str, str],
        response_body: bytes | str | None,
        latency_seconds: float,
        *,
        max_body_bytes: int = 1024 * 512,  # 512KB default
        correlation_id: str | None = None,
    ) -> None:
        self.timestamp = datetime.now(UTC).isoformat()
        self.url = url
        self.method = method
        self.latency_seconds = latency_seconds
        self.correlation_id = correlation_id or ""

        # Request
        self.request_headers = redact_headers(request_headers)
        self.request_body_raw, self.request_truncated = self._bound_body(request_body, max_body_bytes)
        self.request_hash = compute_body_hash(request_body)

        # Response
        self.response_status = response_status
        self.response_headers = redact_headers(response_headers)
        self.response_body_raw, self.response_truncated = self._bound_body(response_body, max_body_bytes)
        self.response_hash = compute_body_hash(response_body)

        # Unique ID for this exchange
        self.exchange_id = hashlib.sha256(
            f"{self.timestamp}-{self.url}-{self.method}-{self.request_hash}-{self.response_hash}".encode()
        ).hexdigest()[:16]

    def _bound_body(self, body: bytes | str | None, max_bytes: int) -> tuple[str, bool]:
        if body is None:
            return "", False

        raw_bytes = body if isinstance(body, bytes) else body.encode("utf-8", errors="replace")
        truncated = len(raw_bytes) > max_bytes
        content = raw_bytes[:max_bytes].decode("utf-8", errors="replace")
        return content, truncated

    def to_dict(self) -> dict[str, Any]:
        return {
            "exchange_id": self.exchange_id,
            "timestamp": self.timestamp,
            "url": self.url,
            "method": self.method,
            "latency_seconds": self.latency_seconds,
            "correlation_id": self.correlation_id,
            "request": {
                "headers": self.request_headers,
                "body_snippet": self.request_body_raw,
                "body_hash": self.request_hash,
                "truncated": self.request_truncated,
            },
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body_snippet": self.response_body_raw,
                "body_hash": self.response_hash,
                "truncated": self.response_truncated,
            },
        }


def save_forensic_exchange(
    output_dir: Path,
    exchange: ForensicExchange,
    target_name: str,
) -> Path:
    """Persist forensic exchange to disk."""
    forensics_dir = output_dir / target_name / "forensics"
    forensics_dir.mkdir(parents=True, exist_ok=True)

    file_path = forensics_dir / f"exchange_{exchange.exchange_id}.json"
    file_path.write_text(json.dumps(exchange.to_dict(), indent=2), encoding="utf-8")
    return file_path
