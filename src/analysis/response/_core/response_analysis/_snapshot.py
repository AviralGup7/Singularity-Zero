"""Response snapshot system for capturing endpoint characteristics."""

from typing import Any

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.patterns import JWT_RE
from src.analysis.passive.runtime import extract_key_fields


def response_snapshot_system(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build snapshots of responses for later comparison and analysis."""
    snapshots: list[dict[str, Any]] = []
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue
        body = response.get("body_text") or ""
        headers = {
            str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
        }
        key_patterns = []
        if JWT_RE.search(body):
            key_patterns.append("jwt_like_token")
        if any(token in body.lower() for token in ("oauth", "signin", "login", "session")):
            key_patterns.append("auth_keyword")
        if "location" in headers:
            key_patterns.append("redirect_header")
        if any(
            token in (response.get("content_type") or "").lower()
            for token in ("json", "javascript")
        ):
            key_patterns.append("structured_content")
        if extract_key_fields(body):
            key_patterns.append("keyed_response")
        snapshots.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "status_code": response.get("status_code"),
                "content_type": response.get("content_type", ""),
                "response_length": int(response.get("body_length", len(body))),
                "header_keys": sorted(headers.keys())[:20],
                "security_headers": sorted(
                    key
                    for key in headers.keys()
                    if key
                    in {
                        "content-security-policy",
                        "location",
                        "permissions-policy",
                        "referrer-policy",
                        "strict-transport-security",
                        "x-frame-options",
                    }
                ),
                "key_patterns": key_patterns,
            }
        )
    snapshots.sort(key=lambda item: (item["endpoint_type"] in {"AUTH", "STATIC"}, item["url"]))
    return snapshots[:150]
