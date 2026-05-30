import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

TOKEN_PARAM_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "key",
    "token",
}
THIRD_PARTY_KEY_PATTERNS = (
    ("stripe_publishable_key", re.compile(r"\bpk_live_[A-Za-z0-9]{16,}\b")),
    ("mapbox_token", re.compile(r"\bpk\.[A-Za-z0-9._-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def _mask_secret(secret: str) -> str:
    value = str(secret or "").strip()
    if len(value) <= 12:
        return value[:3] + "***" if value else ""
    return f"{value[:6]}...{value[-4:]}"


def _base_url(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}/"


def _candidate(
    *,
    key_value: str,
    source_url: str,
    source_type: str,
    placement: str,
    provider: str,
    param_name: str = "",
) -> dict[str, str]:
    return {
        "key_value": key_value,
        "masked_key": _mask_secret(key_value),
        "source_url": source_url,
        "base_url": _base_url(source_url),
        "source_type": source_type,
        "placement": placement,
        "provider": provider,
        "param_name": param_name,
    }


def discover_api_key_candidates(
    urls: list[str] | set[str], responses: list[dict[str, Any]], limit: int = 12
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for raw_url in sorted(str(url) for url in urls):
        parsed = urlparse(raw_url)
        if not parsed.scheme or not parsed.netloc:
            continue
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            lowered_name = name.strip().lower()
            secret = str(value or "").strip()
            if lowered_name not in TOKEN_PARAM_NAMES or not secret:
                continue
            provider = "jwt_like_token" if JWT_RE.search(secret) else "query_token"
            key = (raw_url, secret)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                _candidate(
                    key_value=secret,
                    source_url=raw_url,
                    source_type="query_parameter",
                    placement=f"query:{lowered_name}",
                    provider=provider,
                    param_name=lowered_name,
                )
            )
            if len(candidates) >= limit:
                return candidates

    for response in responses:
        source_url = str(response.get("url", "")).strip()
        body = str(response.get("body_text", "") or "")
        if not source_url or not body:
            continue
        for provider, pattern in THIRD_PARTY_KEY_PATTERNS:
            for match in pattern.finditer(body):
                secret = match.group(0)
                key = (source_url, secret)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    _candidate(
                        key_value=secret,
                        source_url=source_url,
                        source_type="response_body",
                        placement="response_body",
                        provider=provider,
                    )
                )
                if len(candidates) >= limit:
                    return candidates

    return candidates
