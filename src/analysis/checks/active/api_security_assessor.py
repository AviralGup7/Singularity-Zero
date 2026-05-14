"""Automated API security posture assessment.

Evaluates API endpoints for common security misconfigurations.
Runs automatically during scan.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class APIFinding:
    """A single API security finding."""

    endpoint: str
    method: str
    check: str
    severity: str
    message: str
    recommendation: str
    details: str = ""


class APISecurityAssessor:
    """Automatically assesses API security posture."""

    def assess_endpoints(self, endpoints: list[dict[str, Any]]) -> list[APIFinding]:
        """Assess API endpoints for security issues."""
        findings: list[APIFinding] = []

        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            response = ep.get("response", {})
            headers = response.get("headers", {})
            status_code = response.get("status_code", 0)
            body = response.get("body", "")

            # Check for verbose error messages
            findings.extend(self._check_verbose_errors(url, method, body))

            # Check for missing rate limiting indicators
            findings.extend(self._check_rate_limiting(url, method, headers))

            # Check for excessive data exposure
            findings.extend(self._check_data_exposure(url, method, body))

            # Check for mass assignment vulnerability indicators
            findings.extend(self._check_mass_assignment(url, method, body))

            # Check for improper HTTP methods
            findings.extend(self._check_http_methods(url, method, headers))

            # Check for missing authentication
            findings.extend(self._check_missing_auth(url, method, status_code, headers))

            # Check for CORS misconfiguration
            findings.extend(self._check_cors(url, method, headers))

        return findings

    def _check_verbose_errors(self, url: str, method: str, body: str) -> list[APIFinding]:
        """Check for verbose error messages."""
        findings: list[APIFinding] = []
        error_patterns = [
            r"stack\s*trace",
            r"exception\s*in\s*thread",
            r"fatal\s*error",
            r"internal\s*server\s*error",
            r"traceback",
            r"at\s+\w+\.\w+\(",
            r"Caused by:",
            r"SQLSTATE",
            r"SQL syntax",
        ]

        for pattern in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(
                    APIFinding(
                        endpoint=url,
                        method=method,
                        check="verbose_errors",
                        severity="medium",
                        message="Verbose error messages exposed",
                        recommendation="Implement generic error messages for production",
                        details=f"Pattern '{pattern}' found in response",
                    )
                )
                break

        return findings

    def _check_rate_limiting(
        self, url: str, method: str, headers: dict[str, str]
    ) -> list[APIFinding]:
        """Check for rate limiting headers."""
        findings: list[APIFinding] = []
        rate_limit_headers = [
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "rate-limit",
            "retry-after",
            "x-rate-limit",
        ]

        headers_lower = {k.lower(): v for k, v in headers.items()}
        has_rate_limit = any(h in headers_lower for h in rate_limit_headers)

        if not has_rate_limit:
            findings.append(
                APIFinding(
                    endpoint=url,
                    method=method,
                    check="rate_limiting",
                    severity="low",
                    message="No rate limiting headers detected",
                    recommendation="Implement rate limiting with standard headers",
                )
            )

        return findings

    def _check_data_exposure(self, url: str, method: str, body: str) -> list[APIFinding]:
        """Check for excessive data exposure."""
        findings: list[APIFinding] = []
        sensitive_patterns = [
            (r'"password"\s*:\s*"[^"]+"', "Password field in response"),
            (r'"secret"\s*:\s*"[^"]+"', "Secret field in response"),
            (r'"api_key"\s*:\s*"[^"]+"', "API key in response"),
            (r'"token"\s*:\s*"[^"]+"', "Token in response"),
            (r'"ssn"\s*:\s*"[^"]+"', "SSN in response"),
            (r'"credit_card"\s*:\s*"[^"]+"', "Credit card in response"),
        ]

        for pattern, message in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(
                    APIFinding(
                        endpoint=url,
                        method=method,
                        check="data_exposure",
                        severity="high",
                        message=message,
                        recommendation="Remove sensitive fields from API responses",
                    )
                )

        return findings

    def _check_mass_assignment(self, url: str, method: str, body: str) -> list[APIFinding]:
        """Check for mass assignment indicators."""
        findings: list[APIFinding] = []
        mass_assignment_indicators = [
            '"is_admin"',
            '"role"',
            '"permissions"',
            '"user_type"',
            '"account_type"',
            '"is_superadmin"',
        ]

        for indicator in mass_assignment_indicators:
            if indicator.lower() in body.lower():
                findings.append(
                    APIFinding(
                        endpoint=url,
                        method=method,
                        check="mass_assignment",
                        severity="medium",
                        message=f"Potential mass assignment vector: {indicator}",
                        recommendation="Implement allowlists for updatable fields",
                    )
                )
                break

        return findings

    def _check_http_methods(
        self, url: str, method: str, headers: dict[str, str]
    ) -> list[APIFinding]:
        """Check for improper HTTP method support."""
        findings: list[APIFinding] = []
        allow_header = headers.get("Allow", headers.get("allow", ""))

        if allow_header:
            dangerous_methods = ["DELETE", "PUT", "PATCH"]
            allowed = [m.strip().upper() for m in allow_header.split(",")]

            for dm in dangerous_methods:
                if dm in allowed:
                    findings.append(
                        APIFinding(
                            endpoint=url,
                            method=method,
                            check="http_methods",
                            severity="low",
                            message=f"Dangerous HTTP method {dm} is allowed",
                            recommendation="Restrict HTTP methods to only what's needed",
                        )
                    )

        return findings

    def _check_missing_auth(
        self, url: str, method: str, status_code: int, headers: dict[str, str]
    ) -> list[APIFinding]:
        """Check for missing authentication on sensitive endpoints."""
        findings: list[APIFinding] = []
        sensitive_paths = ["/admin", "/api/admin", "/api/users", "/api/config", "/api/settings"]

        if any(path in url.lower() for path in sensitive_paths):
            if status_code == 200:
                findings.append(
                    APIFinding(
                        endpoint=url,
                        method=method,
                        check="missing_auth",
                        severity="high",
                        message="Sensitive endpoint accessible without authentication",
                        recommendation="Require authentication for sensitive endpoints",
                    )
                )

        return findings

    def _check_cors(self, url: str, method: str, headers: dict[str, str]) -> list[APIFinding]:
        """Check for CORS misconfiguration."""
        findings: list[APIFinding] = []
        acao = headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            findings.append(
                APIFinding(
                    endpoint=url,
                    method=method,
                    check="cors",
                    severity="medium",
                    message="CORS allows all origins (wildcard *)",
                    recommendation="Restrict CORS to specific trusted origins",
                )
            )
        elif acao == "null":
            findings.append(
                APIFinding(
                    endpoint=url,
                    method=method,
                    check="cors",
                    severity="medium",
                    message="CORS allows null origin",
                    recommendation="Do not allow 'null' as a CORS origin",
                )
            )

        return findings

    def get_summary(self, findings: list[APIFinding]) -> dict[str, Any]:
        """Get assessment summary."""
        by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_check: dict[str, int] = {}

        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_check[f.check] = by_check.get(f.check, 0) + 1

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_check": by_check,
            "findings": [
                {
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "check": f.check,
                    "severity": f.severity,
                    "message": f.message,
                }
                for f in findings
            ],
        }
