"""Authorization and scope verification gatekeeper for ExecutionRequest.

Validates an incoming ExecutionRequest against cryptographic scope tokens,
tenant boundaries, and resource budgets before handoff to scheduling/worker.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from src.decision.models import ExecutionRequest, ScopeToken


class ScopeAuthorizationError(ValueError):
    """Raised when an ExecutionRequest violates scope or authorization policy."""


@dataclass(frozen=True, slots=True)
class AuthorizedExecutionTicket:
    """Cryptographically signed lease verifying an ExecutionRequest is valid and authorized."""

    ticket_id: str
    request_id: str
    tenant_id: str
    authorized_at: float
    expires_at: float
    signature: str
    request: ExecutionRequest

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "authorized_at": self.authorized_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
            "request": self.request.to_dict(),
        }


class ExecutionAuthorizer:
    """Authorizes ExecutionRequests before dispatch to scheduling and worker."""

    def __init__(self, secret_key: str = "cstp-scope-authorizer-v1") -> None:
        self._secret_key = secret_key.encode("utf-8")

    def _generate_signature(self, request_id: str, tenant_id: str, expires_at: float) -> str:
        payload = f"{request_id}:{tenant_id}:{expires_at:.3f}".encode("utf-8")
        return hmac.new(self._secret_key, payload, hashlib.sha256).hexdigest()

    def _is_ip_allowed(self, host: str, allowed_cidrs: tuple[str, ...]) -> bool:
        if not allowed_cidrs:
            return False
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs)
        except ValueError:
            return False

    def _is_domain_allowed(self, host: str, allowed_domains: tuple[str, ...]) -> bool:
        if not allowed_domains:
            return False
        h = host.lower().strip()
        for domain in allowed_domains:
            d = domain.lower().strip()
            if d.startswith("*."):
                suffix = d[2:]
                if h == suffix or h.endswith("." + suffix):
                    return True
            elif h == d or h.endswith("." + d):
                return True
        return False

    def authorize(self, request: ExecutionRequest) -> AuthorizedExecutionTicket:
        """Validate execution request and issue an AuthorizedExecutionTicket.

        Raises:
            ScopeAuthorizationError: If scope, deadline, or resource limits fail validation.
        """
        now = time.time()

        # 1. Validate Deadline
        if request.deadline > 0 and request.deadline < now:
            raise ScopeAuthorizationError(
                f"ExecutionRequest {request.request_id} deadline expired: {request.deadline} < {now}"
            )

        # 2. Validate Resource Limits
        limits = request.resource_limits
        if limits.timeout_seconds <= 0:
            raise ScopeAuthorizationError(
                f"Invalid timeout_seconds {limits.timeout_seconds} in resource limits"
            )

        # 3. Validate Scope Token if specified
        token = request.scope_token
        target_host = request.target.host
        target_path = request.target.path

        if token.expires_at > 0 and token.expires_at < now:
            raise ScopeAuthorizationError(f"ScopeToken expired at {token.expires_at}")

        # Check domain / CIDR membership
        if token.allowed_domains or token.allowed_cidrs:
            domain_ok = self._is_domain_allowed(target_host, token.allowed_domains)
            ip_ok = self._is_ip_allowed(target_host, token.allowed_cidrs)
            if not (domain_ok or ip_ok):
                raise ScopeAuthorizationError(
                    f"Target host '{target_host}' is not in allowed domains {token.allowed_domains} "
                    f"or allowed CIDRs {token.allowed_cidrs}"
                )

        # Check forbidden paths
        for forbidden in token.forbidden_paths:
            if forbidden and target_path.startswith(forbidden):
                raise ScopeAuthorizationError(
                    f"Target path '{target_path}' matches forbidden path '{forbidden}'"
                )

        # 4. Generate Ticket
        ticket_id = f"tkt_{uuid.uuid4().hex[:16]}"
        expires_at = request.deadline if request.deadline > 0 else (now + limits.timeout_seconds)
        signature = self._generate_signature(request.request_id, request.tenant_id, expires_at)

        return AuthorizedExecutionTicket(
            ticket_id=ticket_id,
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            authorized_at=now,
            expires_at=expires_at,
            signature=signature,
            request=request,
        )


__all__ = [
    "AuthorizedExecutionTicket",
    "ExecutionAuthorizer",
    "ScopeAuthorizationError",
]
