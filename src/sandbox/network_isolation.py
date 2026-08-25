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
from dataclasses import dataclass, field
from typing import Any

from src.decision.models import ScopeToken

logger = logging.getLogger(__name__)

# Cloud metadata endpoints unconditionally blocked across all cloud providers
CLOUD_METADATA_DESTINATIONS = frozenset([
    "169.254.169.254",
    "metadata.google.internal",
    "fd00:ec2::254",
    "100.100.100.200",  # Alibaba Cloud metadata
    "instance-data",
])


class EgressViolationError(PermissionError):
    """Raised when sandboxed execution attempts outbound network connection outside authorized scope."""


@dataclass(frozen=True, slots=True)
class NetworkEgressFilter:
    """Evaluates outbound network destinations against scope authorization (Invariant I29)."""

    allowed_domains: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]
    blocked_endpoints: tuple[str, ...] = tuple(sorted(CLOUD_METADATA_DESTINATIONS))

    @classmethod
    def from_scope_token(cls, token: ScopeToken) -> NetworkEgressFilter:
        """Derive network egress filter directly from ScopeToken."""
        domains = tuple(d.lower().strip() for d in token.allowed_domains)
        cidrs = tuple(str(c).strip() for c in token.allowed_cidrs)
        return cls(allowed_domains=domains, allowed_cidrs=cidrs)

    def is_destination_allowed(self, host: str, port: int | None = None) -> bool:
        """Validate destination against cloud metadata blocker and scope allowlist."""
        norm_host = host.lower().strip()
        if "@" in norm_host:
            norm_host = norm_host.split("@")[-1]
        if ":" in norm_host and not norm_host.startswith("["):
            norm_host = norm_host.split(":")[0]
        norm_host = norm_host.rstrip(".")

        # 1. Unconditional Cloud Metadata Denial (I29)
        if norm_host in self.blocked_endpoints:
            logger.warning("Egress blocked: cloud metadata endpoint %s accessed", norm_host)
            return False

        try:
            ip = ipaddress.ip_address(norm_host)
            # Check Link-Local Metadata range (169.254.0.0/16)
            if ip.is_link_local:
                logger.warning("Egress blocked: link-local IP %s accessed", ip)
                return False

            # Check if IP is explicitly allowed in authorized CIDRs
            if self.allowed_cidrs:
                return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in self.allowed_cidrs)
            return False
        except ValueError:
            pass

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
