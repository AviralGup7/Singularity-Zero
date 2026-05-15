"""Automated sensitive data exposure scanner.

Scans HTTP responses for leaked sensitive data patterns.
Runs automatically on all responses during security analysis.

Patterns based on OWASP sensitive data exposure checklist.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SensitiveDataFinding:
    """A single sensitive data exposure finding."""

    url: str
    data_type: str
    severity: str
    match: str  # Redacted match
    context: str  # Surrounding context (redacted)
    count: int


class SensitiveDataScanner:
    """Automatically scans for sensitive data exposure.

    Patterns based on OWASP sensitive data exposure checklist.
    """

    PATTERNS: list[dict[str, Any]] = [
        # API Keys and Tokens
        {
            "name": "AWS Access Key",
            "regex": r"AKIA[0-9A-Z]{16}",
            "severity": "critical",
            "data_type": "api_key",
        },
        {
            "name": "AWS Secret Key",
            "regex": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            "severity": "critical",
            "data_type": "api_key",
        },
        {
            "name": "Google API Key",
            "regex": r"AIza[0-9A-Za-z_-]{35}",
            "severity": "high",
            "data_type": "api_key",
        },
        {
            "name": "GitHub Token",
            "regex": r"ghp_[0-9a-zA-Z]{36}",
            "severity": "critical",
            "data_type": "api_key",
        },
        {
            "name": "Slack Token",
            "regex": r"xox[baprs]-[0-9a-zA-Z-]+",
            "severity": "high",
            "data_type": "api_key",
        },
        {
            "name": "JWT Token",
            "regex": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "severity": "high",
            "data_type": "token",
        },
        # PII
        {
            "name": "Email Address",
            "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "severity": "medium",
            "data_type": "pii",
        },
        {
            "name": "Phone Number",
            "regex": r"\+?[1-9]\d{1,14}",
            "severity": "medium",
            "data_type": "pii",
        },
        {
            "name": "SSN (US)",
            "regex": r"\b\d{3}-\d{2}-\d{4}\b",
            "severity": "critical",
            "data_type": "pii",
        },
        {
            "name": "Credit Card Number",
            "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "severity": "critical",
            "data_type": "financial",
        },
        # Credentials
        {
            "name": "Password in URL",
            "regex": r"(?i)password\s*[=:]\s*\S+",
            "severity": "critical",
            "data_type": "credential",
        },
        {
            "name": "Private Key",
            "regex": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            "severity": "critical",
            "data_type": "credential",
        },
        {
            "name": "Database Connection String",
            "regex": r"(?i)(mysql|postgres|mongodb|redis):\/\/[^\s]+:[^\s]+@[^\s]+",
            "severity": "critical",
            "data_type": "credential",
        },
        # Infrastructure
        {
            "name": "Internal IP Address",
            "regex": r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
            "severity": "low",
            "data_type": "infrastructure",
        },
        {
            "name": "Stack Trace",
            "regex": r"(?i)(traceback|stacktrace|at [a-zA-Z_]+\.[a-zA-Z_]+\.[a-zA-Z_]+\()",
            "severity": "medium",
            "data_type": "infrastructure",
        },
        {
            "name": "Debug Mode Enabled",
            "regex": r'(?i)(debug\s*=\s*true|debug_mode\s*:\s*true|"debug":\s*true)',
            "severity": "medium",
            "data_type": "infrastructure",
        },
    ]

    def __init__(self) -> None:
        self._compiled_patterns: list[dict[str, Any]] = [
            {**p, "compiled": re.compile(p["regex"])} for p in self.PATTERNS
        ]
        self._findings: list[SensitiveDataFinding] = []

    def scan_response(
        self, url: str, response_body: str, response_headers: str = ""
    ) -> list[SensitiveDataFinding]:
        """Scan a single response for sensitive data."""
        findings: list[SensitiveDataFinding] = []
        content = response_body + "\n" + response_headers

        for pattern in self._compiled_patterns:
            matches = pattern["compiled"].findall(content)
            if matches:
                # Redact matches for safe reporting
                redacted_matches = [self._redact(m) for m in matches[:5]]

                finding = SensitiveDataFinding(
                    url=url,
                    data_type=pattern["data_type"],
                    severity=pattern["severity"],
                    match=redacted_matches[0] if redacted_matches else "",
                    context=self._get_context(content, matches[0]) if matches else "",
                    count=len(matches),
                )
                findings.append(finding)

        return findings

    def scan_multiple_responses(
        self, responses: list[dict[str, Any]]
    ) -> list[SensitiveDataFinding]:
        """Scan multiple responses."""
        all_findings: list[SensitiveDataFinding] = []
        for resp in responses:
            url = resp.get("url", "")
            body = resp.get("body", "")
            headers = resp.get("headers", "")

            findings = self.scan_response(url, body, headers)
            all_findings.extend(findings)

        self._findings = all_findings
        return all_findings

    def _redact(self, match: str) -> str:
        """Redact sensitive data for safe reporting."""
        if len(match) <= 8:
            return match[:2] + "..." + match[-2:]
        return match[:4] + "..." + match[-4:]

    def _get_context(self, content: str, match: str, context_size: int = 50) -> str:
        """Get surrounding context for a match."""
        idx = content.find(str(match))
        if idx == -1:
            return ""

        start = max(0, idx - context_size)
        end = min(len(content), idx + len(str(match)) + context_size)
        context = content[start:end]

        return "..." + context + "..." if start > 0 or end < len(content) else context

    def get_findings_by_severity(self, severity: str) -> list[SensitiveDataFinding]:
        """Get findings filtered by severity."""
        return [f for f in self._findings if f.severity == severity]

    def get_findings_by_type(self, data_type: str) -> list[SensitiveDataFinding]:
        """Get findings filtered by data type."""
        return [f for f in self._findings if f.data_type == data_type]

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all sensitive data findings."""
        return {
            "total_findings": len(self._findings),
            "by_severity": {
                "critical": len(self.get_findings_by_severity("critical")),
                "high": len(self.get_findings_by_severity("high")),
                "medium": len(self.get_findings_by_severity("medium")),
                "low": len(self.get_findings_by_severity("low")),
            },
            "by_type": {
                dt: len(self.get_findings_by_type(dt))
                for dt in {f.data_type for f in self._findings}
            },
            "findings": [
                {
                    "url": f.url,
                    "data_type": f.data_type,
                    "severity": f.severity,
                    "match": f.match,
                    "count": f.count,
                }
                for f in self._findings
            ],
        }
