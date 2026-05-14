"""Strict scope validation middleware for outbound request interception.

This module provides middleware components that validate and intercept
outbound HTTP requests, ensuring they only target hosts within the
explicitly defined scan boundaries. It supports exact hostname matching,
wildcard subdomain patterns, CIDR IP ranges, and implicit subdomain
allowance for parent domains.

Classes:
    ScopeViolationError: Exception raised when a request targets an out-of-scope host.
    ScopeCheckResult: Dataclass representing the result of a scope validation check.
    ScopeValidator: Core validator that checks URLs, hostnames, and IPs against scope.
    OutboundRequestInterceptor: Intercepts and validates outbound HTTP requests.
    CacheBypassMiddleware: Strips cache-related headers to prevent 304 responses.

Functions:
    validate_url_scope: Standalone function to validate a URL against scope hosts.
    create_scope_guard: Factory function that returns a decorator for HTTP request functions.
"""

import datetime
import ipaddress
import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_PATTERN = re.compile(r"^\[?([0-9a-fA-F:]+)\]?$")


@dataclass
class ScopeCheckResult:
    """Result of a scope validation check.

    Attributes:
        allowed: Whether the target is within the defined scope.
        reason: Human-readable explanation of the check result.
        matched_rule: The specific scope rule that matched, or None if no match.
        url: The original URL that was checked.
        hostname: The extracted hostname from the URL, or None.
        ip_address: The resolved IP address if available, or None.
    """

    allowed: bool
    reason: str
    matched_rule: str | None
    url: str
    hostname: str | None = None
    ip_address: str | None = None


@dataclass(frozen=True)
class SensitiveScopePolicy:
    """Policy for excluding sensitive internal subdomains from wildcard scope."""

    enabled: bool = True
    sensitive_labels: frozenset[str] = frozenset(
        {
            "admin",
            "artifactory",
            "ci",
            "git",
            "gitlab",
            "jenkins",
            "nexus",
            "secret",
            "secrets",
            "vault",
        }
    )


class ScopeViolationError(Exception):
    """Exception raised when a request targets a host outside the defined scope.

    Attributes:
        target_url: The URL that violated the scope boundary.
        reason: Explanation of why the request was rejected.
        scope_hosts: The set of allowed scope hosts at the time of violation.
    """

    def __init__(
        self,
        target_url: str,
        reason: str,
        scope_hosts: set[str],
    ) -> None:
        self.target_url = target_url
        self.reason = reason
        self.scope_hosts = frozenset(scope_hosts)
        super().__init__(
            f"Scope violation: {reason} | Target: {target_url} | "
            f"Allowed scope: {sorted(self.scope_hosts)}"
        )


class ScopeValidator:
    """Validates URLs, hostnames, and IP addresses against a defined scope.

    The validator supports multiple matching strategies:
    - Exact hostname match
    - Wildcard subdomain patterns (e.g., *.example.com)
    - CIDR range matching for IP addresses
    - Implicit subdomain allowance (parent domain matches all subdomains)

    Args:
        scope_hosts: A set of allowed hosts. Each entry can be:
            - An exact hostname: "example.com"
            - A wildcard subdomain: "*.example.com"
            - An IP address: "192.168.1.1"
            - A CIDR range: "192.168.1.0/24"

    Example:
        >>> validator = ScopeValidator({"example.com", "*.api.example.com", "10.0.0.0/8"})
        >>> result = validator.check("https://api.example.com/v1/users")
        >>> result.allowed
        True
    """

    def __init__(
        self,
        scope_hosts: set[str],
        sensitive_policy: SensitiveScopePolicy | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._sensitive_policy = sensitive_policy or SensitiveScopePolicy()
        self._raw_hosts: set[str] = set()
        self._exact_hostnames: set[str] = set()
        self._wildcard_domains: set[str] = set()
        self._exact_ips: set[str] = set()
        self._cidr_networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self._rules: list[str] = []

        for host in scope_hosts:
            self._add_host(host)

    def _is_sensitive_hostname(self, hostname: str) -> bool:
        """Return True when a hostname matches a protected internal label."""
        if not self._sensitive_policy.enabled:
            return False
        labels = [label for label in hostname.lower().split(".") if label]
        if not labels:
            return False
        return labels[0] in self._sensitive_policy.sensitive_labels

    def _has_explicit_sensitive_scope(self, hostname: str) -> bool:
        """Check whether a sensitive hostname was explicitly scoped."""
        if hostname in self._exact_hostnames:
            return True
        for wildcard_domain in self._wildcard_domains:
            if hostname == wildcard_domain or hostname.endswith(f".{wildcard_domain}"):
                first_label = wildcard_domain.split(".", 1)[0]
                if first_label in self._sensitive_policy.sensitive_labels:
                    return True
        return False

    def _add_host(self, host: str) -> None:
        """Parse and index a single scope host entry.

        Args:
            host: A host entry (hostname, wildcard, IP, or CIDR range).
        """
        normalized = host.strip().lower()
        if not normalized:
            return

        if normalized in self._raw_hosts:
            return

        self._raw_hosts.add(normalized)

        if self._is_cidr_range(normalized):
            try:
                network = ipaddress.ip_network(normalized, strict=False)
                self._cidr_networks.append((network, normalized))
            except ValueError:
                pass
        elif self._is_ip_address(normalized):
            self._exact_ips.add(normalized)
        elif normalized.startswith("*."):
            domain = normalized[2:]
            self._wildcard_domains.add(domain)
        else:
            self._exact_hostnames.add(normalized)

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        """Check if a string is a valid IPv4 or IPv6 address.

        Args:
            host: The string to check.

        Returns:
            True if the string is a valid IP address.
        """
        if _IPV4_PATTERN.match(host):
            return True
        ipv6_match = _IPV6_PATTERN.match(host)
        if ipv6_match:
            try:
                ipaddress.ip_address(ipv6_match.group(1))
                return True
            except ValueError:
                pass
        return False

    @staticmethod
    def _is_cidr_range(host: str) -> bool:
        """Check if a string is a valid CIDR range.

        Args:
            host: The string to check.

        Returns:
            True if the string contains '/' and is a valid network.
        """
        if "/" not in host:
            return False
        try:
            ipaddress.ip_network(host, strict=False)
            return True
        except ValueError:
            return False

    def check(self, url: str) -> ScopeCheckResult:
        """Validate a complete URL against the defined scope.

        Parses the URL, extracts the hostname, and validates it against
        all scope rules. If the hostname is an IP address, it is validated
        using IP/CIDR matching.

        Args:
            url: The full URL to validate.

        Returns:
            A ScopeCheckResult indicating whether the URL is allowed.

        Example:
            >>> validator = ScopeValidator({"example.com"})
            >>> result = validator.check("https://www.example.com/page")
            >>> result.allowed
            True
        """
        try:
            parsed = urlparse(url)
        except Exception as exc:
            return ScopeCheckResult(
                allowed=False,
                reason=f"Failed to parse URL: {exc}",
                matched_rule=None,
                url=url,
            )

        hostname = parsed.hostname
        if not hostname:
            return ScopeCheckResult(
                allowed=False,
                reason="URL does not contain a valid hostname",
                matched_rule=None,
                url=url,
            )

        hostname = hostname.lower()

        if self._is_ip_address(hostname):
            return self.check_ip(hostname, url=url)

        return self.check_hostname(hostname, url=url)

    def check_hostname(self, hostname: str, url: str = "") -> ScopeCheckResult:
        """Validate a hostname against the defined scope.

        Matching is performed in the following order:
        1. Exact hostname match (case-insensitive)
        2. Wildcard subdomain match (*.domain.com)
        3. Implicit subdomain match (parent domain allows subdomains)

        Args:
            hostname: The hostname to validate.
            url: Optional original URL for the result context.

        Returns:
            A ScopeCheckResult indicating whether the hostname is allowed.
        """
        hostname = hostname.lower().strip()
        url_context = url or hostname

        with self._lock:
            if hostname in self._exact_hostnames:
                return ScopeCheckResult(
                    allowed=True,
                    reason=f"Exact match for hostname '{hostname}'",
                    matched_rule=hostname,
                    url=url_context,
                    hostname=hostname,
                )

            if self._is_sensitive_hostname(hostname) and not self._has_explicit_sensitive_scope(
                hostname
            ):
                return ScopeCheckResult(
                    allowed=False,
                    reason=(
                        f"Sensitive internal hostname '{hostname}' is excluded from wildcard "
                        "scope; add it explicitly to scan it"
                    ),
                    matched_rule=None,
                    url=url_context,
                    hostname=hostname,
                )

            for wildcard_domain in self._wildcard_domains:
                if hostname == wildcard_domain or hostname.endswith(f".{wildcard_domain}"):
                    return ScopeCheckResult(
                        allowed=True,
                        reason=f"Wildcard match: '{hostname}' matches '*.{wildcard_domain}'",
                        matched_rule=f"*.{wildcard_domain}",
                        url=url_context,
                        hostname=hostname,
                    )

            for parent_domain in self._exact_hostnames:
                if hostname.endswith(f".{parent_domain}"):
                    return ScopeCheckResult(
                        allowed=True,
                        reason=f"Implicit subdomain match: '{hostname}' is a subdomain of '{parent_domain}'",
                        matched_rule=parent_domain,
                        url=url_context,
                        hostname=hostname,
                    )

        return ScopeCheckResult(
            allowed=False,
            reason=f"Hostname '{hostname}' is not within the defined scope",
            matched_rule=None,
            url=url_context,
            hostname=hostname,
        )

    def check_ip(self, ip: str, url: str = "") -> ScopeCheckResult:
        """Validate an IP address against the defined scope.

        Checks for exact IP match first, then checks against all
        configured CIDR ranges.

        Args:
            ip: The IP address to validate (IPv4 or IPv6).
            url: Optional original URL for the result context.

        Returns:
            A ScopeCheckResult indicating whether the IP is allowed.
        """
        ip = ip.strip().lower()
        url_context = url or ip

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ScopeCheckResult(
                allowed=False,
                reason=f"Invalid IP address: '{ip}'",
                matched_rule=None,
                url=url_context,
                ip_address=ip,
            )

        with self._lock:
            if ip in self._exact_ips:
                return ScopeCheckResult(
                    allowed=True,
                    reason=f"Exact match for IP address '{ip}'",
                    matched_rule=ip,
                    url=url_context,
                    ip_address=ip,
                )

            for network, rule_str in self._cidr_networks:
                try:
                    if addr in network:
                        return ScopeCheckResult(
                            allowed=True,
                            reason=f"IP '{ip}' is within CIDR range '{rule_str}'",
                            matched_rule=rule_str,
                            url=url_context,
                            ip_address=ip,
                        )
                except TypeError:
                    continue

        return ScopeCheckResult(
            allowed=False,
            reason=f"IP address '{ip}' is not within the defined scope",
            matched_rule=None,
            url=url_context,
            ip_address=ip,
        )

    def add_scope(self, host: str) -> None:
        """Dynamically add a host entry to the scope.

        The new entry is parsed and indexed according to its type
        (exact hostname, wildcard, IP, or CIDR range).

        Args:
            host: The host entry to add.
        """
        with self._lock:
            self._add_host(host)
            self._rules.append(host.strip().lower())
        logger.info("Added scope host: %s", host)

    def remove_scope(self, host: str) -> None:
        """Dynamically remove a host entry from the scope.

        Removes the host from all internal indexes. If the host
        does not exist, this is a no-op.

        Args:
            host: The host entry to remove.
        """
        normalized = host.strip().lower()
        with self._lock:
            self._raw_hosts.discard(normalized)

            if normalized in self._exact_hostnames:
                self._exact_hostnames.discard(normalized)
            elif normalized.startswith("*."):
                domain = normalized[2:]
                self._wildcard_domains.discard(domain)
            elif self._is_cidr_range(normalized):
                try:
                    network = ipaddress.ip_network(normalized, strict=False)
                    self._cidr_networks = [(n, r) for n, r in self._cidr_networks if n != network]
                except ValueError:
                    pass
            elif self._is_ip_address(normalized):
                self._exact_ips.discard(normalized)

            if normalized in self._rules:
                self._rules.remove(normalized)

        logger.info("Removed scope host: %s", host)

    def get_scope_rules(self) -> list[str]:
        """Return a list of all active scope rules.

        Returns:
            A list of scope rule strings as originally configured.
        """
        with self._lock:
            return list(self._rules)


class OutboundRequestInterceptor:
    """Intercepts outbound HTTP requests and validates them against scope.

    This class wraps HTTP request functions (such as those from the
    `requests` library) to validate target URLs before they are sent.
    Requests targeting out-of-scope hosts are blocked and logged.

    The interceptor is thread-safe and maintains an audit log of all
    intercepted requests, both allowed and blocked.

    Args:
        validator: A ScopeValidator instance configured with allowed hosts.
        logger_name: Name for the audit logger. Defaults to "scope_middleware".

    Example:
        >>> validator = ScopeValidator({"example.com"})
        >>> interceptor = OutboundRequestInterceptor(validator)
        >>> method, url = interceptor.intercept("GET", "https://example.com/api")
        >>> # method == "GET", url == "https://example.com/api"
        >>>
        >>> # This would raise ScopeViolationError:
        >>> # interceptor.intercept("GET", "https://evil.com/api")
    """

    def __init__(
        self,
        validator: ScopeValidator,
        logger_name: str = "scope_middleware",
    ) -> None:
        self._validator = validator
        self._lock = threading.Lock()
        self._audit_log: list[dict[str, Any]] = []
        self._logger = logging.getLogger(logger_name)
        self._blocked_count: int = 0
        self._allowed_count: int = 0

    @property
    def blocked_count(self) -> int:
        """Number of requests that have been blocked."""
        return self._blocked_count

    @property
    def allowed_count(self) -> int:
        """Number of requests that have been allowed."""
        return self._allowed_count

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Return a copy of the audit log."""
        with self._lock:
            return list(self._audit_log)

    def intercept(self, method: str, url: str, **kwargs: Any) -> tuple[str, str]:
        """Validate a request target URL against the scope.

        Checks the URL against the configured scope validator. If the
        URL is within scope, the method and URL are returned. If the
        URL is out of scope, a ScopeViolationError is raised and the
        attempt is logged.

        Args:
            method: The HTTP method (e.g., "GET", "POST").
            url: The target URL to validate.
            **kwargs: Additional request parameters (logged but not used).

        Returns:
            A tuple of (method, url) if the request is allowed.

        Raises:
            ScopeViolationError: If the URL is outside the defined scope.
        """
        result = self._validator.check(url)
        timestamp = datetime.datetime.now(tz=datetime.UTC).isoformat()

        entry = {
            "timestamp": timestamp,
            "method": method,
            "url": url,
            "allowed": result.allowed,
            "reason": result.reason,
            "matched_rule": result.matched_rule,
        }

        with self._lock:
            self._audit_log.append(entry)

        if result.allowed:
            with self._lock:
                self._allowed_count += 1
            self._logger.debug("ALLOWED: %s %s - %s", method, url, result.reason)
            return method, url
        else:
            with self._lock:
                self._blocked_count += 1
            self._logger.warning("BLOCKED: %s %s - %s", method, url, result.reason)
            raise ScopeViolationError(
                target_url=url,
                reason=result.reason,
                scope_hosts=set(self._validator.get_scope_rules()),
            )

    def wrap_session(self, session: Any) -> Any:
        """Wrap a requests.Session to intercept all outbound requests.

        Replaces the session's `request` method with a wrapped version
        that validates the target URL before sending the request.

        Args:
            session: A requests.Session instance to wrap.

        Returns:
            The same session object with its request method wrapped.

        Example:
            >>> import requests
            >>> session = requests.Session()
            >>> interceptor = OutboundRequestInterceptor(validator)
            >>> wrapped = interceptor.wrap_session(session)
            >>> # All requests through wrapped session are now scope-validated
        """
        original_request = session.request

        @wraps(original_request)
        def wrapped_request(method: str, url: str, *args: Any, **kwargs: Any) -> Any:
            self.intercept(method, url, **kwargs)
            return original_request(method, url, *args, **kwargs)

        session.request = wrapped_request
        self._logger.info("Wrapped session: %s", type(session).__name__)
        return session

    def __call__(self, method: str, url: str, **kwargs: Any) -> tuple[str, str]:
        """Make the interceptor callable as a function.

        Allows the interceptor to be used directly as a validation
        function or as a pre-request hook.

        Args:
            method: The HTTP method.
            url: The target URL.
            **kwargs: Additional request parameters.

        Returns:
            A tuple of (method, url) if allowed.

        Raises:
            ScopeViolationError: If the URL is out of scope.
        """
        return self.intercept(method, url, **kwargs)


def validate_url_scope(url: str, scope_hosts: set[str]) -> ScopeCheckResult:
    """Validate a URL against a set of allowed scope hosts.

    This is a convenience function that creates a temporary ScopeValidator,
    checks the URL, and returns the result. For repeated validations,
    create a persistent ScopeValidator instance instead.

    Args:
        url: The URL to validate.
        scope_hosts: A set of allowed hosts (hostnames, wildcards, IPs, CIDRs).

    Returns:
        A ScopeCheckResult indicating whether the URL is within scope.

    Example:
        >>> result = validate_url_scope(
        ...     "https://api.example.com/v1",
        ...     {"example.com", "*.example.com"}
        ... )
        >>> result.allowed
        True
    """
    validator = ScopeValidator(scope_hosts)
    return validator.check(url)


def create_scope_guard(
    scope_hosts: set[str],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Create a decorator that guards HTTP request functions against out-of-scope targets.

    The returned decorator can be applied to any function that accepts
    `method` and `url` as its first two positional arguments (such as
    `requests.Session.request`).

    Args:
        scope_hosts: A set of allowed hosts for the guard.

    Returns:
        A decorator function that wraps request functions with scope validation.

    Example:
        >>> import requests
        >>> guard = create_scope_guard({"example.com"})
        >>>
        >>> @guard
        ... def safe_request(method, url, **kwargs):
        ...     session = requests.Session()
        ...     return session.request(method, url, **kwargs)
        >>>
        >>> # This will raise ScopeViolationError:
        >>> # safe_request("GET", "https://evil.com")
    """
    validator = ScopeValidator(scope_hosts)
    interceptor = OutboundRequestInterceptor(validator)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(method: str, url: str, *args: Any, **kwargs: Any) -> Any:
            interceptor.intercept(method, url, **kwargs)
            return func(method, url, *args, **kwargs)

        return wrapper

    return decorator
