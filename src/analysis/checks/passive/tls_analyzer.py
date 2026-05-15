"""Automated TLS/SSL configuration analyzer.

Checks TLS/SSL configuration of target servers for known vulnerabilities.
Runs automatically during scan initialization.
"""

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TLSFinding:
    """A single TLS/SSL configuration finding."""

    check: str
    status: str  # pass, fail, warning
    severity: str
    message: str
    details: str = ""


class TLSAnalyzer:
    """Analyzes TLS/SSL configuration automatically."""

    # Weak ciphers that should not be used
    WEAK_CIPHERS: set[str] = {
        "RC4",
        "DES",
        "3DES",
        "MD5",
        "NULL",
        "EXPORT",
        "RC2",
        "IDEA",
        "SEED",
        "CAMELLIA",
    }

    # Known vulnerable cipher suites
    VULNERABLE_CIPHERS: list[str] = [
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_DES_CBC_SHA",
        "TLS_RSA_WITH_NULL_SHA",
        "TLS_RSA_WITH_NULL_MD5",
    ]

    def analyze_host(self, host: str, port: int = 443) -> list[TLSFinding]:
        """Analyze TLS configuration of a host."""
        findings: list[TLSFinding] = []

        # Check certificate
        cert_findings = self._check_certificate(host, port)
        findings.extend(cert_findings)

        # Check protocol versions
        protocol_findings = self._check_protocols(host, port)
        findings.extend(protocol_findings)

        # Check cipher suites
        cipher_findings = self._check_ciphers(host, port)
        findings.extend(cipher_findings)

        return findings

    def _check_certificate(self, host: str, port: int) -> list[TLSFinding]:
        """Check SSL certificate validity."""
        findings: list[TLSFinding] = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return findings

                    # Check expiration
                    not_after = cert.get("notAfter", "")
                    days_left = 999
                    if not_after and isinstance(not_after, str):
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.now()).days

                        if days_left < 0:
                            findings.append(
                                TLSFinding(
                                    check="certificate_expiry",
                                    status="fail",
                                    severity="critical",
                                    message="SSL certificate has expired",
                                    details=f"Expired {abs(days_left)} days ago",
                                )
                            )
                        elif days_left < 30:
                            findings.append(
                                TLSFinding(
                                    check="certificate_expiry",
                                    status="warning",
                                    severity="medium",
                                    message="SSL certificate expires soon",
                                    details=f"{days_left} days remaining",
                                )
                            )

                    # Check subject
                    subject_items: Any = cert.get("subject", [])
                    subject: dict[str, str] = {}
                    for item in subject_items:
                        if isinstance(item, (list, tuple)) and len(item) > 0:
                            attr = item[0]
                            if isinstance(attr, (list, tuple)) and len(attr) >= 2:
                                subject[attr[0]] = attr[1]
                    if "commonName" not in subject:
                        findings.append(
                            TLSFinding(
                                check="certificate_subject",
                                status="warning",
                                severity="low",
                                message="Certificate missing Common Name",
                            )
                        )

        except ssl.SSLCertVerificationError as e:
            findings.append(
                TLSFinding(
                    check="certificate_verification",
                    status="fail",
                    severity="high",
                    message="SSL certificate verification failed",
                    details=str(e),
                )
            )
        except Exception as e:
            findings.append(
                TLSFinding(
                    check="certificate_check",
                    status="fail",
                    severity="medium",
                    message="Failed to check certificate",
                    details=str(e),
                )
            )

        return findings

    def _check_protocols(self, host: str, port: int) -> list[TLSFinding]:
        """Check supported TLS protocol versions."""
        findings: list[TLSFinding] = []
        protocols: list[tuple[Any, str, str]] = [
            (ssl.TLSVersion.SSLv3, "SSLv3", "critical"),
            (ssl.TLSVersion.TLSv1, "TLSv1.0", "high"),
            (ssl.TLSVersion.TLSv1_1, "TLSv1.1", "medium"),
        ]

        for tls_version, name, severity in protocols:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = tls_version
                context.maximum_version = tls_version

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        findings.append(
                            TLSFinding(
                                check=f"protocol_{name}",
                                status="fail",
                                severity=severity,
                                message=f"Deprecated protocol {name} is enabled",
                                details=f"Disable {name} and use TLS 1.2 or higher",
                            )
                        )
            except Exception:
                pass  # Protocol not supported - good

        return findings

    def _check_ciphers(self, host: str, port: int) -> list[TLSFinding]:
        """Check for weak cipher suites."""
        findings: list[TLSFinding] = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in self.WEAK_CIPHERS:
                            if weak in cipher_name.upper():
                                findings.append(
                                    TLSFinding(
                                        check="weak_cipher",
                                        status="fail",
                                        severity="high",
                                        message=f"Weak cipher in use: {cipher_name}",
                                        details=f"Remove {weak} from cipher suite configuration",
                                    )
                                )
        except Exception as e:
            logger.debug("Cipher check failed for %s:%d: %s", host, port, e)

        return findings

    def get_score(self, findings: list[TLSFinding]) -> float:
        """Calculate TLS security score (0-100)."""
        if not findings:
            return 100.0

        severity_penalties = {"critical": 25, "high": 15, "medium": 10, "low": 5}
        total_penalty = sum(severity_penalties.get(f.severity, 0) for f in findings)

        return max(0, 100 - total_penalty)
