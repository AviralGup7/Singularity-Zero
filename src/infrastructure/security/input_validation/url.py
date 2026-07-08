"""URL validation with SSRF and open redirect prevention."""

import ipaddress
import logging
import re
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from src.core.security.sensitive_names import (
    SENSITIVE_QUERY_PARAMS as _CENTRAL_SENSITIVE_QUERY_PARAMS,
)
from src.core.utils.url_validation import PRIVATE_NETWORKS as _CENTRAL_PRIVATE_NETWORKS
from src.infrastructure.security.config import SecurityConfig
from src.infrastructure.security.input_validation.base import ValidationResult

logger = logging.getLogger(__name__)


class URLValidator:
    """URL validation with SSRF and open redirect prevention."""

    INTERNAL_IP_RANGES = list(_CENTRAL_PRIVATE_NETWORKS)

    SSRF_PATTERNS = [
        r"localhost",
        r"127\.\d+\.\d+\.\d+",
        r"0\.0\.0\.0",
        r"0x7f\.0\.0\.1",
        r"2130706433",
        r"\[::1\]",
        r"\[::\]",
        r"metadata\.google\.internal",
        r"169\.254\.169\.254",
        r"metadata\.azure\.com",
        r"instance-data\.amazonaws\.com",
    ]

    OPEN_REDIRECT_PATTERNS = [
        r"javascript:",
        r"data:",
        r"vbscript:",
        r"\\x",
        r"\\u",
        r"\\/",
    ]

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._blocklist_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SSRF_PATTERNS + self.OPEN_REDIRECT_PATTERNS
        ]
        self._allowed_schemes = set(config.input_validation.allowed_url_schemes)

    def validate(self, url: str, *, allow_internal: bool = False) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        if not url:
            return ValidationResult(valid=False, errors=["URL cannot be empty"])

        if len(url) > self.config.input_validation.max_url_length:
            errors.append(
                f"URL exceeds maximum length of {self.config.input_validation.max_url_length}"
            )

        try:
            parsed = urlparse(url)
        except Exception as exc:
            return ValidationResult(valid=False, errors=[f"Invalid URL format: {exc}"])

        if not parsed.scheme:
            errors.append("URL must include a scheme (http:// or https://)")

        if parsed.scheme.lower() not in self._allowed_schemes:
            errors.append(
                f"Scheme '{parsed.scheme}' not allowed. "
                f"Allowed: {', '.join(sorted(self._allowed_schemes))}"
            )

        if not parsed.netloc:
            errors.append("URL must include a hostname")

        for pattern in self._blocklist_patterns:
            if pattern.search(url):
                errors.append("URL contains potentially dangerous pattern")
                break

        if not allow_internal and parsed.hostname:
            if self._is_internal_ip(parsed.hostname):
                errors.append("Access to internal/private IP addresses is not allowed")

        if parsed.username or parsed.password:
            warnings.append("URL contains credentials which will be stripped")

        sanitized = self._sanitize_url(parsed)

        return ValidationResult(
            valid=not errors,
            sanitized=sanitized,
            errors=errors,
            warnings=warnings,
        )

    def validate_redirect_url(
        self,
        url: str,
        allowed_hosts: set[str] | None = None,
    ) -> ValidationResult:
        errors: list[str] = []

        if not url:
            return ValidationResult(valid=False, errors=["Redirect URL cannot be empty"])

        if url.startswith("//") or url.startswith("\\"):
            errors.append("Protocol-relative redirects are not allowed")
            return ValidationResult(valid=False, errors=errors)

        if url.startswith("/"):
            if url.startswith("//") or url.startswith("/\\"):
                errors.append("URL starts with path but may be interpreted as protocol-relative")
                return ValidationResult(valid=False, errors=errors)
            return ValidationResult(valid=True, sanitized=url)

        try:
            parsed = urlparse(url)
        except Exception as exc:
            return ValidationResult(valid=False, errors=[f"Invalid URL format: {exc}"])

        if allowed_hosts and parsed.hostname:
            if parsed.hostname.lower() not in {h.lower() for h in allowed_hosts}:
                errors.append(f"Redirect to '{parsed.hostname}' is not in allowed hosts")

        return ValidationResult(valid=not errors, sanitized=url, errors=errors)

    def _is_internal_ip(self, hostname: str) -> bool:
        from src.core.utils.url_validation import _host_resolves_to_private

        try:
            addr = ipaddress.ip_address(hostname)
            return any(addr in network for network in self.INTERNAL_IP_RANGES)
        except ValueError:
            pass

        if any(re.search(pattern, hostname, re.IGNORECASE) for pattern in self.SSRF_PATTERNS):
            return True

        return _host_resolves_to_private(hostname)

    def _sanitize_url(self, parsed: Any) -> str:
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        sanitized_query = parsed.query
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            filtered_params = {
                k: v for k, v in query_params.items() if k.lower() not in _CENTRAL_SENSITIVE_QUERY_PARAMS
            }
            sanitized_query = urlencode(filtered_params, doseq=True)

        return cast(
            str,
            urlunparse(
                (
                    parsed.scheme,
                    netloc,
                    parsed.path,
                    parsed.params,
                    sanitized_query,
                    "",
                )
            ),
        )
