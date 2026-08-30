"""Scope-Derived Network Egress Enforcement and Cloud Metadata Blocker.

Enforces Invariant I29:
- Outbound network destinations are strictly derived from ScopeToken
- Unconditionally denies cloud metadata IPs and domains (169.254.169.254, metadata.google.internal, fd00:ec2::254)
- Allows RFC1918 internal IP ranges only if explicitly listed in the scope token
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Sequence
from dataclasses import dataclass

from src.decision.models import ScopeToken

logger = logging.getLogger(__name__)

# Hardcoded compile-time floor: Cloud metadata and link-local destinations unconditionally denied (I29)
# Cannot be bypassed or re-enabled by any ScopeToken, wildcards, or custom CIDR allowances.
HARDCODED_METADATA_DENY_LIST: frozenset[str] = frozenset(
    [
        "169.254.169.254",  # AWS/GCP/Azure/OpenStack IMDSv1/v2 IPv4
        "metadata.google.internal",  # GCP internal metadata hostname
        "fd00:ec2::254",  # AWS IMDS IPv6
        "100.100.100.200",  # Alibaba Cloud metadata
        "instance-data",  # Legacy EC2 metadata hostname
        "169.254.169.250",  # Azure IMDS alias
        "169.254.169.251",
        "169.254.169.252",
        "169.254.169.253",
    ]
)

CLOUD_METADATA_DESTINATIONS = HARDCODED_METADATA_DENY_LIST


class EgressViolationError(PermissionError):
    """Raised when sandboxed execution attempts outbound network connection outside authorized scope."""


@dataclass(frozen=True, slots=True)
class NetworkEgressFilter:
    """Evaluates outbound network destinations against scope authorization (Invariant I29)."""

    allowed_domains: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]
    blocked_endpoints: tuple[str, ...] = tuple(sorted(HARDCODED_METADATA_DENY_LIST))
    strict: bool = True

    @classmethod
    def from_scope_token(cls, token: ScopeToken) -> NetworkEgressFilter:
        """Derive network egress filter directly from ScopeToken."""
        domains = tuple(d.lower().strip() for d in token.allowed_domains)
        cidrs = tuple(str(c).strip() for c in token.allowed_cidrs)
        return cls(allowed_domains=domains, allowed_cidrs=cidrs, strict=True)

    @classmethod
    def metadata_guard(cls) -> NetworkEgressFilter:
        """Fail-closed cloud-metadata deny list used when no ScopeToken is available."""
        return cls(allowed_domains=(), allowed_cidrs=(), strict=False)

    @classmethod
    def from_scope_entries(cls, entries: Sequence[str] | None) -> NetworkEgressFilter:
        """Build a filter from pipeline scope host strings."""
        hosts: list[str] = []
        for entry in entries or ():
            raw = str(entry or "").strip().lower()
            if not raw or "*" in raw:
                continue
            if "://" in raw:
                raw = raw.split("://", 1)[1]
            raw = raw.split("/", 1)[0].split(":", 1)[0]
            if raw:
                hosts.append(raw)
        if not hosts:
            return cls.metadata_guard()
        return cls(allowed_domains=tuple(hosts), allowed_cidrs=(), strict=True)

    def is_destination_allowed(self, host: str, port: int | None = None) -> bool:
        """Validate destination against cloud metadata blocker and scope allowlist."""
        norm_host = host.lower().strip()
        if "@" in norm_host:
            norm_host = norm_host.split("@")[-1]
        if ":" in norm_host and not norm_host.startswith("["):
            norm_host = norm_host.split(":")[0]
        norm_host = norm_host.rstrip(".")

        # 1. Unconditional Hard-Coded Cloud Metadata & Link-Local Pre-Filter (I29 Floor)
        if norm_host in HARDCODED_METADATA_DENY_LIST or norm_host in self.blocked_endpoints:
            logger.warning("Egress blocked: cloud metadata endpoint %s accessed", norm_host)
            return False

        try:
            ip = ipaddress.ip_address(norm_host)
            # Check Link-Local Metadata range (169.254.0.0/16 or fe80::/10)
            if ip.is_link_local:
                logger.warning("Egress blocked: link-local IP %s accessed", ip)
                return False

            # Check if IP is explicitly allowed in authorized CIDRs
            if self.allowed_cidrs:
                # Even if allowed_cidrs contains 0.0.0.0/0 or 169.254.0.0/16, metadata is never permitted
                return any(
                    ip in ipaddress.ip_network(cidr, strict=False) for cidr in self.allowed_cidrs
                )
            return not self.strict
        except ValueError:
            pass

        if not self.strict:
            return True

        # 2. Check Allowed Domain Matching
        if self.allowed_domains:
            for domain in self.allowed_domains:
                d = domain.lower().strip().rstrip(".")
                if d.startswith("*."):
                    suffix = d[2:]
                    if norm_host == suffix or norm_host.endswith("." + suffix):
                        return True
                elif norm_host == d:
                    return True

        return False

    def validate_destination_or_raise(self, host: str, port: int | None = None) -> None:
        """Raise EgressViolationError if destination is not authorized."""
        if not self.is_destination_allowed(host, port):
            raise EgressViolationError(
                f"Destination '{host}' is outside authorized scope or targets prohibited metadata (I29)"
            )


def validate_url_resolved(url: str, filt: NetworkEgressFilter) -> list[str]:
    """Resolve *url* and validate every A/AAAA against *filt* (SSRF hardening).

    Returns the list of resolved IP strings that passed. Raises
    :class:`EgressViolationError` if the host/URL is blocked or any address
    fails the scope/metadata checks. Callers that follow redirects must invoke
    this again on each hop.
    """
    import socket
    from urllib.parse import urlparse

    raw = str(url or "").strip()
    if not raw:
        raise EgressViolationError("I29: empty URL")
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    scheme = (parsed.scheme or "https").lower()
    if scheme not in {"http", "https"}:
        raise EgressViolationError(f"I29: scheme not allowed: {scheme}")
    host = parsed.hostname or ""
    if not host:
        raise EgressViolationError(f"I29: URL has no host: {url!r}")
    filt.validate_destination_or_raise(host, parsed.port)
    # If host is already an IP, single-address check is enough.
    try:
        import ipaddress

        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    addrs: list[str] = []
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise EgressViolationError(f"I29: DNS resolution failed for {host}: {exc}") from exc
    for info in infos:
        sockaddr = info[4]
        ip = str(sockaddr[0])
        filt.validate_destination_or_raise(ip, parsed.port)
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:
        raise EgressViolationError(f"I29: no resolved addresses for {host}")
    return addrs
