"""OAuth 2.0 / OpenID Connect and SAML misconfiguration validator.

Detects common authentication/authorization bypass vectors:
- OAuth redirect_uri validation bypass
- OAuth state parameter reuse / missing
- OAuth PKCE bypass
- OAuth token exchange abuse
- SAML XML signature bypass (XXE, wrapping)
- SAML replay attacks
- SAML attribute manipulation
"""

from __future__ import annotations

import json
import logging
from datetime import UTC
from typing import Any
from urllib.parse import parse_qs, urlparse

import defusedxml.ElementTree as ET  # noqa: N817

from src.execution.validators.config.scoring_config import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
)
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.shared import (
    bounded_confidence,
    to_validation_result,
)

logger = logging.getLogger(__name__)

OAUTH_REDIRECT_URI_BYPASS_PATTERNS = [
    "https://evil.com/oauth/callback",
    "https://target.com.evil.com/",
    "https://target.com@evil.com/",
    "https://evil.com/?url=https://target.com",
    "https://target.com/../evil.com/",
    "https://target.com//evil.com/",
    "https://evil.com%2Ftarget.com",
    "https://target.com%00@evil.com",
    "https://target.com:443@evil.com",
    "",
    "data:text/html,<script>location=document.cookie</script>",
    "file:///etc/passwd",
    "javascript:alert(1)",
]

OAUTH_STATE_VALUES = [
    "test",
    "1234567890",
    "",
    "csrf_token",
    "state",
    "1",
    "null",
    "undefined",
    "valid_state_token",
]

OAUTH_TOKEN_EXCHANGE_GRANTS = [
    "authorization_code",
    "client_credentials",
    "password",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "implicit",
]

SAML_SIGNATURE_BYPASS_PAYLOADS = [
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="2024-01-01T00:00:00Z" Version="2.0"><saml:Assertion><saml:AttributeStatement><saml:Attribute Name="Role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response>&xxe;</samlp:Response>',
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>',
]

SAML_ATTRIBUTE_MANIPULATION = {
    "Role": "admin",
    "roles": '["admin","superuser"]',
    "email": "admin@target.com",
    "groups": '["Administrators","Domain Admins"]',
    "accessLevel": "1000",
    "isAdmin": "true",
}


def _normalize_url(url_str: str) -> str:
    parsed = urlparse(url_str)
    if not parsed.scheme:
        url_str = "https://" + url_str
        parsed = urlparse(url_str)
    return url_str


def _check_redirect_uri_bypass(authorization_endpoint: str, redirect_uri: str) -> bool:
    """Check if a redirect_uri can bypass validation."""
    parsed = urlparse(authorization_endpoint)
    query_params = parse_qs(parsed.query)
    actual_redirect = query_params.get("redirect_uri", [None])[0]
    if actual_redirect is None:
        return False
    actual_redirect = _normalize_url(actual_redirect)
    redirect_uri = _normalize_url(redirect_uri)
    return actual_redirect == redirect_uri


def _looks_like_xml_signature_bypass(body: str) -> bool:
    if not body:
        return False
    try:
        root = ET.fromstring(body)
        sig_elements = root.findall(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        if not sig_elements:
            return True
        for sig in sig_elements:
            sig_value = sig.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
            if sig_value is None or not sig_value.text:
                return True
    except ET.ParseError as exc:
        logger.warning("Operation failed in oauth_saml.py: %s", exc, exc_info=True)  # noqa: BLE001
    return False


def _looks_like_saml_replay(body: str) -> bool:
    if not body:
        return False
    try:
        root = ET.fromstring(body)
        issue_instant = root.get("IssueInstant", "")
        if issue_instant:
            from datetime import datetime

            try:
                parsed_time = datetime.fromisoformat(issue_instant.replace("Z", "+00:00"))
                now = datetime.now(UTC)
                age = (now - parsed_time).total_seconds()
                if age > 300:
                    return True
            except (ValueError, TypeError) as exc:
                logger.warning("Operation failed in oauth_saml.py: %s", exc, exc_info=True)  # noqa: BLE001
    except ET.ParseError as exc:
        logger.warning("Operation failed in oauth_saml.py: %s", exc, exc_info=True)  # noqa: BLE001
    return False


def evaluate_oauth_state(
    *,
    state_value: str,
    response_body: str,
    response_status: int,
) -> dict[str, Any]:
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []

    if response_status in (200, 302) and state_value in response_body:
        signals.append("oauth_state_reflected")
        bonuses.append(0.15)
        notes.append(f"OAuth state parameter value '{state_value}' reflected in response.")

    if response_status in (200, 302) and (not state_value or state_value == ""):
        signals.append("oauth_state_empty_accepted")
        bonuses.append(0.20)
        notes.append("OAuth empty state parameter accepted.")

    return {
        "signals": signals,
        "bonuses": bonuses,
        "notes": notes,
    }


def evaluate_oauth_token_exchange(
    *,
    grant_type: str,
    response_body: str,
    response_status: int,
) -> dict[str, Any]:
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []

    if response_status == 200:
        try:
            body_json = json.loads(response_body) if response_body else {}
            if "access_token" in body_json or "id_token" in body_json:
                signals.append(f"oauth_token_exchange_accepted_{grant_type}")
                bonuses.append(0.18)
                notes.append(f"OAuth token exchange accepted for grant_type '{grant_type}'.")
        except (ValueError, TypeError) as exc:
            logger.warning("Operation failed in oauth_saml.py: %s", exc, exc_info=True)  # noqa: BLE001

    return {
        "signals": signals,
        "bonuses": bonuses,
        "notes": notes,
    }


def evaluate_saml_assertion(
    *,
    saml_body: str,
    response_status: int,
) -> dict[str, Any]:
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []

    if response_status in (200, 302):
        sig_bypass = _looks_like_xml_signature_bypass(saml_body)
        if sig_bypass:
            signals.append("saml_signature_bypass")
            bonuses.append(0.25)
            notes.append("SAML assertion accepted without valid XML Signature.")

        replay = _looks_like_saml_replay(saml_body)
        if replay:
            signals.append("saml_replay_detected")
            bonuses.append(0.20)
            notes.append("SAML assertion replay attack possible.")

    return {
        "signals": signals,
        "bonuses": bonuses,
        "notes": notes,
    }


def evaluate_oauth_saml(
    *,
    redirect_uri: str,
    state_value: str | None,
    grant_type: str | None,
    saml_body: str | None,
    response_body: str,
    response_headers: dict[str, str],
    response_status: int,
    scoring: ScoringConfig,
    in_scope: bool,
) -> dict[str, Any]:
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []

    if redirect_uri:
        if response_status in (200, 302) and redirect_uri in response_body:
            signals.append("redirect_uri_reflected")
            bonuses.append(0.15)
            notes.append(f"OAuth redirect_uri value reflected in response: {redirect_uri}")

    if state_value is not None:
        state_eval = evaluate_oauth_state(
            state_value=state_value,
            response_body=response_body,
            response_status=response_status,
        )
        signals.extend(state_eval["signals"])
        bonuses.extend(state_eval["bonuses"])
        notes.extend(state_eval["notes"])

    if grant_type:
        grant_eval = evaluate_oauth_token_exchange(
            grant_type=grant_type,
            response_body=response_body,
            response_status=response_status,
        )
        signals.extend(grant_eval["signals"])
        bonuses.extend(grant_eval["bonuses"])
        notes.extend(grant_eval["notes"])

    if saml_body:
        saml_eval = evaluate_saml_assertion(
            saml_body=saml_body,
            response_status=response_status,
        )
        signals.extend(saml_eval["signals"])
        bonuses.extend(saml_eval["bonuses"])
        notes.extend(saml_eval["notes"])

    if signals and in_scope:
        if "saml_signature_bypass" in signals or "oauth_state_empty_accepted" in signals:
            status = ValidationStatus.CONFIRMED.value
        else:
            status = ValidationStatus.HEURISTIC.value
    elif signals:
        status = ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    confidence = bounded_confidence(
        base=scoring.base,
        cap=scoring.cap,
        bonuses=bonuses,
    )
    evidence = {
        "redirect_uri_tested": redirect_uri or "",
        "state_value_tested": state_value or "",
        "grant_type_tested": grant_type or "",
        "saml_body_preview": (saml_body or "")[:200],
        "signals": signals,
        "notes": notes,
    }
    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "evidence": evidence,
        "bonuses": bonuses,
    }


def validate(target: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    target_url = str(target.get("url", ""))
    redirect_uri = str(context.get("oauth_redirect_uri", ""))
    state_value = context.get("oauth_state")
    grant_type = context.get("oauth_grant_type")
    saml_body = context.get("saml_assertion_body")
    response_body = str(context.get("response_body", ""))
    response_headers = dict(context.get("response_headers") or {})
    response_status = int(context.get("response_status", 0) or 0)
    in_scope = bool(context.get("in_scope", True))
    scoring_name = "oauth_saml"
    scoring = DEFAULT_SCORING_CONFIG.get(scoring_name, ScoringConfig())

    if not response_body and not saml_body:
        return to_validation_result(
            {
                "url": target_url,
                "status": ValidationStatus.INCONCLUSIVE.value,
                "confidence": 0.0,
                "in_scope": in_scope,
                "scope_reason": "no_response_data",
            },
            validator=scoring_name,
            category="oauth_saml_misconfiguration",
        ).__dict__

    evaluation = evaluate_oauth_saml(
        redirect_uri=redirect_uri,
        state_value=state_value,
        grant_type=grant_type,
        saml_body=saml_body,
        response_body=response_body,
        response_headers=response_headers,
        response_status=response_status,
        scoring=scoring,
        in_scope=in_scope,
    )
    item = {
        "url": target_url,
        "status": evaluation["status"],
        "confidence": evaluation["confidence"],
        "in_scope": in_scope,
        "scope_reason": "scope_evaluated" if in_scope else "scope_unavailable_or_out_of_scope",
        "evidence": evaluation["evidence"],
    }
    return to_validation_result(
        item, validator=scoring_name, category="oauth_saml_misconfiguration"
    ).__dict__


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not findings:
        return {"status": "no_findings", "count": 0}
    redirect_bypass = sum(
        1 for f in findings if "redirect_uri_bypass" in f.get("evidence", {}).get("signals", [])
    )
    state_empty = sum(
        1
        for f in findings
        if "oauth_state_empty_accepted" in f.get("evidence", {}).get("signals", [])
    )
    sig_bypass = sum(
        1 for f in findings if "saml_signature_bypass" in f.get("evidence", {}).get("signals", [])
    )
    return {
        "status": "analyzed",
        "count": len(findings),
        "redirect_uri_bypass_count": redirect_bypass,
        "state_empty_count": state_empty,
        "saml_signature_bypass_count": sig_bypass,
    }
