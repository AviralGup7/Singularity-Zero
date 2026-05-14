"""Automated security headers analysis.

Checks HTTP responses for missing or misconfigured security headers.
Runs automatically on all responses during passive analysis.
"""

from dataclasses import dataclass


@dataclass
class HeaderFinding:
    """A single security header finding."""

    header: str
    status: str  # missing, misconfigured, weak, good
    severity: str
    message: str
    recommendation: str
    current_value: str = ""
    expected_value: str = ""


class SecurityHeadersAnalyzer:
    """Analyzes HTTP responses for security header issues."""

    REQUIRED_HEADERS: dict[str, dict[str, str]] = {
        "strict-transport-security": {
            "severity": "high",
            "message": "Missing HSTS header",
            "recommendation": "Add Strict-Transport-Security header with max-age of at least 31536000",
            "expected_pattern": "max-age=",
        },
        "content-security-policy": {
            "severity": "high",
            "message": "Missing Content-Security-Policy header",
            "recommendation": "Implement a restrictive Content-Security-Policy",
            "expected_pattern": None,  # type: ignore[dict-item]
        },
        "x-content-type-options": {
            "severity": "medium",
            "message": "Missing X-Content-Type-Options header",
            "recommendation": "Add X-Content-Type-Options: nosniff",
            "expected_pattern": "nosniff",
        },
        "x-frame-options": {
            "severity": "medium",
            "message": "Missing X-Frame-Options header",
            "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN",
            "expected_pattern": None,  # type: ignore[dict-item]
        },
        "x-xss-protection": {
            "severity": "low",
            "message": "Missing X-XSS-Protection header",
            "recommendation": "Add X-XSS-Protection: 1; mode=block (legacy browsers only)",
            "expected_pattern": "1",
        },
        "referrer-policy": {
            "severity": "medium",
            "message": "Missing Referrer-Policy header",
            "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
            "expected_pattern": None,  # type: ignore[dict-item]
        },
        "permissions-policy": {
            "severity": "low",
            "message": "Missing Permissions-Policy header",
            "recommendation": "Add Permissions-Policy to restrict browser features",
            "expected_pattern": None,  # type: ignore[dict-item]
        },
    }

    DANGEROUS_HEADERS: dict[str, dict[str, str]] = {
        "server": {"severity": "low", "message": "Server header exposes server software"},
        "x-powered-by": {
            "severity": "low",
            "message": "X-Powered-By header exposes technology stack",
        },
        "x-aspnet-version": {
            "severity": "medium",
            "message": "X-AspNet-Version header exposes framework version",
        },
    }

    def analyze_headers(self, headers: dict[str, str]) -> list[HeaderFinding]:
        """Analyze response headers for security issues."""
        findings: list[HeaderFinding] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for missing required headers
        for header, config in self.REQUIRED_HEADERS.items():
            if header not in headers_lower:
                findings.append(
                    HeaderFinding(
                        header=header,
                        status="missing",
                        severity=config["severity"],
                        message=config["message"],
                        recommendation=config["recommendation"],
                    )
                )
            elif config.get("expected_pattern"):
                value = headers_lower[header]
                if config["expected_pattern"] not in value.lower():
                    findings.append(
                        HeaderFinding(
                            header=header,
                            status="misconfigured",
                            severity=config["severity"],
                            message=f"{header} is misconfigured",
                            recommendation=config["recommendation"],
                            current_value=value,
                            expected_value=config["expected_pattern"],
                        )
                    )

        # Check for dangerous headers
        for header, config in self.DANGEROUS_HEADERS.items():
            if header in headers_lower:
                findings.append(
                    HeaderFinding(
                        header=header,
                        status="present",
                        severity=config["severity"],
                        message=config["message"],
                        recommendation=f"Remove {header} header",
                        current_value=headers_lower[header],
                    )
                )

        return findings

    def get_score(self, findings: list[HeaderFinding]) -> float:
        """Calculate security headers score (0-100)."""
        if not findings:
            return 100.0

        severity_penalties = {"high": 15, "medium": 10, "low": 5}
        total_penalty = sum(severity_penalties.get(f.severity, 0) for f in findings)

        return max(0, 100 - total_penalty)
