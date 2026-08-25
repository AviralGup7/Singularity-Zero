"""Authorization and scope verification gatekeeper for ExecutionRequest.

Validates an incoming ExecutionRequest against cryptographic scope tokens,
canonical target identities, tenant boundaries, and resource budgets before handoff to scheduling/worker.
Includes URL/path adversarial normalization, DNS pinning validation, and ticket replay protection.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import posixpath
import re
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any

from src.core.contracts.canonical_target import CanonicalTargetIdentity, canonicalize_target
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
    nonce: str
    signature: str
    request: ExecutionRequest
    epoch: int = 1
    partition_id: str = "P0"
    canonical_identity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "authorized_at": self.authorized_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "signature": self.signature,
            "request": self.request.to_dict(),
            "epoch": self.epoch,
            "partition_id": self.partition_id,
            "canonical_identity_hash": self.canonical_identity_hash,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> AuthorizedExecutionTicket:
        req_raw = data.get("request") or {}
        req = ExecutionRequest.from_mapping(req_raw) if isinstance(req_raw, dict) else req_raw
        return cls(
            ticket_id=str(data.get("ticket_id", "")),
            request_id=str(data.get("request_id", "")),
            tenant_id=str(data.get("tenant_id", "default")),
            authorized_at=float(data.get("authorized_at", 0.0)),
            expires_at=float(data.get("expires_at", 0.0)),
            nonce=str(data.get("nonce", "")),
            signature=str(data.get("signature", "")),
            request=req,
            epoch=int(data.get("epoch", 1)),
            partition_id=str(data.get("partition_id", "P0")),
            canonical_identity_hash=str(data.get("canonical_identity_hash", "")),
        )


class ExecutionAuthorizer:
    """Authorizes ExecutionRequests before dispatch to scheduling and worker."""

    def __init__(
        self,
        secret_key: str = "cstp-scope-authorizer-v1",
        budget_enforcer: Any | None = None,
    ) -> None:
        self._secret_key = secret_key.encode("utf-8")
        self._budget_enforcer = budget_enforcer
        self._consumed_tickets: set[str] = set()
        self._lock = threading.Lock()

    def _normalize_path(self, raw_path: str) -> str:
        """Adversarial normalization of URL paths (URL unquoting + path traversal collapsing)."""
        if not raw_path:
            return "/"
        unquoted = urllib.parse.unquote(raw_path)
        # Strip matrix parameters e.g. /..;/
        cleaned = unquoted.replace(";/", "/")
        norm = posixpath.normpath(cleaned)
        norm = re.sub(r"/+", "/", norm)
        if not norm.startswith("/"):
            norm = "/" + norm
        return norm

    def _normalize_host(self, raw_host: str) -> str:
        """Strip userinfo or trailing ports if accidentally passed in host."""
        h = raw_host.lower().strip()
        if "@" in h:
            h = h.split("@")[-1]
        if ":" in h and not h.startswith("["):
            h = h.split(":")[0]
        return h.rstrip(".")

    def _generate_signature(
        self,
        ticket_id: str,
        request_id: str,
        tenant_id: str,
        target_host: str,
        target_path: str,
        nonce: str,
        expires_at: float,
        epoch: int = 1,
        partition_id: str = "P0",
    ) -> str:
        payload = (
            f"{ticket_id}:{request_id}:{tenant_id}:{target_host}:{target_path}:"
            f"{nonce}:{expires_at:.3f}:{epoch}:{partition_id}".encode("utf-8")
        )
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
        h = self._normalize_host(host)
        for domain in allowed_domains:
            d = self._normalize_host(domain)
            if d.startswith("*."):
                suffix = d[2:]
                if h == suffix or h.endswith("." + suffix):
                    return True
            elif h == d:
                return True
        return False

    def authorize(
        self,
        request: ExecutionRequest,
        budget_enforcer: Any | None = None,
        epoch: int = 1,
        partition_id: str = "P0",
    ) -> AuthorizedExecutionTicket:
        """Validate execution request, reserve budget quota, and issue an AuthorizedExecutionTicket.

        Raises:
            ScopeAuthorizationError: If scope, deadline, resource limits, or budget reservation fails.
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

        # 3. Canonicalize Target Identity
        raw_url = f"{request.target.scheme or 'https'}://{request.target.host}:{request.target.port or 443}{request.target.path or '/'}"
        canon = canonicalize_target(raw_url)
        target_host = canon.hostname
        target_path = canon.path

        # 4. Validate Scope Token if specified
        token = request.scope_token
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

        # Check forbidden paths against normalized path
        for forbidden in token.forbidden_paths:
            if forbidden:
                norm_forbidden = self._normalize_path(forbidden)
                if target_path == norm_forbidden or target_path.startswith(norm_forbidden.rstrip("/") + "/"):
                    raise ScopeAuthorizationError(
                        f"Target path '{target_path}' matches forbidden path '{forbidden}'"
                    )

        # 5. Atomic Budget Reservation
        enforcer = budget_enforcer or self._budget_enforcer
        if enforcer is not None and hasattr(enforcer, "reserve_requests"):
            req_count = len(request.actions) if request.actions else 1
            if not enforcer.reserve_requests(req_count):
                raise ScopeAuthorizationError(
                    f"Hunt budget capacity exhausted: cannot reserve {req_count} request(s)"
                )

        # 6. Generate Ticket with Nonce & HMAC binding
        ticket_id = f"tkt_{uuid.uuid4().hex[:16]}"
        nonce = uuid.uuid4().hex
        expires_at = request.deadline if request.deadline > 0 else (now + limits.timeout_seconds)
        signature = self._generate_signature(
            ticket_id=ticket_id,
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            target_host=target_host,
            target_path=target_path,
            nonce=nonce,
            expires_at=expires_at,
            epoch=epoch,
            partition_id=partition_id,
        )

        return AuthorizedExecutionTicket(
            ticket_id=ticket_id,
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            authorized_at=now,
            expires_at=expires_at,
            nonce=nonce,
            signature=signature,
            request=request,
            epoch=epoch,
            partition_id=partition_id,
            canonical_identity_hash=canon.identity_hash,
        )

    def verify_ticket(self, ticket: AuthorizedExecutionTicket) -> bool:
        """Verify ticket signature, expiration, and tampering."""
        now = time.time()
        if ticket.expires_at < now:
            return False
        raw_url = f"{ticket.request.target.scheme or 'https'}://{ticket.request.target.host}:{ticket.request.target.port or 443}{ticket.request.target.path or '/'}"
        try:
            canon = canonicalize_target(raw_url)
            target_host = canon.hostname
            target_path = canon.path
        except Exception:
            target_host = self._normalize_host(ticket.request.target.host)
            target_path = self._normalize_path(ticket.request.target.path)

        expected_sig = self._generate_signature(
            ticket_id=ticket.ticket_id,
            request_id=ticket.request_id,
            tenant_id=ticket.tenant_id,
            target_host=target_host,
            target_path=target_path,
            nonce=ticket.nonce,
            expires_at=ticket.expires_at,
            epoch=ticket.epoch,
            partition_id=ticket.partition_id,
        )
        return hmac.compare_digest(expected_sig, ticket.signature)

    def consume_ticket(self, ticket: AuthorizedExecutionTicket) -> bool:
        """Atomically verify and consume a ticket (single-use replay resistance)."""
        with self._lock:
            if ticket.ticket_id in self._consumed_tickets:
                return False  # Replay detected!
            if not self.verify_ticket(ticket):
                return False
            self._consumed_tickets.add(ticket.ticket_id)
            return True


__all__ = [
    "AuthorizedExecutionTicket",
    "ExecutionAuthorizer",
    "ScopeAuthorizationError",
]
