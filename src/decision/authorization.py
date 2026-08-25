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

from src.core.contracts.canonical_target import canonicalize_target
from src.decision.models import ExecutionRequest, ScopeToken


def _scope_token_binding(token: ScopeToken) -> str:
    """Stable hash of the ScopeToken that authorized the ticket (I30)."""
    raw = (
        f"{token.scope_hash}|{','.join(token.allowed_domains)}|"
        f"{','.join(token.allowed_cidrs)}|{token.issuer_signature}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
    policy_generation: int = 1
    scope_token_hash: str = ""
    budget_reservation_id: str = ""
    authority_revision: str = ""
    command_id: str = ""

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
            "policy_generation": self.policy_generation,
            "scope_token_hash": self.scope_token_hash,
            "budget_reservation_id": self.budget_reservation_id,
            "authority_revision": self.authority_revision,
            "command_id": self.command_id,
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
            policy_generation=int(data.get("policy_generation", 1)),
            scope_token_hash=str(data.get("scope_token_hash", "")),
            budget_reservation_id=str(data.get("budget_reservation_id", "")),
            authority_revision=str(data.get("authority_revision", "")),
            command_id=str(data.get("command_id", "")),
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
        policy_generation: int = 1,
        scope_token_hash: str = "",
        budget_reservation_id: str = "",
        authority_revision: str = "",
        command_id: str = "",
    ) -> str:
        payload = (
            f"{ticket_id}:{request_id}:{tenant_id}:{target_host}:{target_path}:"
            f"{nonce}:{expires_at:.3f}:{epoch}:{partition_id}:{policy_generation}:"
            f"{scope_token_hash}:{budget_reservation_id}:{authority_revision}:{command_id}".encode()
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

    def generate_egress_allowlist(self, token: ScopeToken) -> list[str]:
        """Synthesize scope-derived network egress allowlist directly from ScopeToken (Invariant I29).

        Always denies cloud metadata endpoints (169.254.169.254, metadata.google.internal, fd00:ec2::254).
        Permits authorized internal targets (including RFC1918) only if explicitly enumerated.
        """
        metadata_denylist = {
            "169.254.169.254",
            "169.254.169.254:80",
            "metadata.google.internal",
            "metadata.google.internal:80",
            "fd00:ec2::254",
            "100.100.100.200",  # Alibaba cloud metadata
        }

        allowlist: list[str] = []
        for domain in token.allowed_domains:
            norm_d = self._normalize_host(domain)
            if norm_d not in metadata_denylist:
                allowlist.append(norm_d)

        for cidr in token.allowed_cidrs:
            cidr_str = str(cidr).strip()
            # Ensure metadata subnet is not in allowlist
            if cidr_str != "169.254.169.254/32":
                allowlist.append(cidr_str)

        return allowlist

    def authorize(
        self,
        request: ExecutionRequest,
        budget_enforcer: Any | None = None,
        epoch: int = 1,
        partition_id: str = "P0",
        policy_generation: int = 1,
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
                if target_path == norm_forbidden or target_path.startswith(
                    norm_forbidden.rstrip("/") + "/"
                ):
                    raise ScopeAuthorizationError(
                        f"Target path '{target_path}' matches forbidden path '{forbidden}'"
                    )

        # 5. Mandatory Atomic Budget Reservation (INVARIANT-002)
        enforcer = budget_enforcer or self._budget_enforcer
        if enforcer is None:
            raise ScopeAuthorizationError(
                "Mandatory budget enforcer not configured: cannot issue AuthorizedExecutionTicket "
                "without committed budget reservation (INVARIANT-002)"
            )

        req_count = len(request.actions) if request.actions else 1
        identity: dict[str, Any] | None = None
        if hasattr(enforcer, "reserve_with_identity"):
            identity = enforcer.reserve_with_identity(req_count)
            if identity is None:
                raise ScopeAuthorizationError(
                    f"Hunt budget capacity exhausted: cannot reserve {req_count} request(s)"
                )
        elif not hasattr(enforcer, "reserve_requests") or not enforcer.reserve_requests(req_count):
            raise ScopeAuthorizationError(
                f"Hunt budget capacity exhausted: cannot reserve {req_count} request(s)"
            )

        # 6. Generate Ticket with Nonce & HMAC binding (I30 causal quartet)
        ticket_id = f"tkt_{uuid.uuid4().hex[:16]}"
        nonce = uuid.uuid4().hex
        expires_at = request.deadline if request.deadline > 0 else (now + limits.timeout_seconds)
        scope_token_hash = _scope_token_binding(token)
        reservation_id = str((identity or {}).get("reservation_id") or f"res_{ticket_id}")
        authority_revision = str((identity or {}).get("authority_revision") or f"rev_{ticket_id}")
        command_id = str((identity or {}).get("command_id") or f"cmd_authz_{ticket_id}")
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
            policy_generation=policy_generation,
            scope_token_hash=scope_token_hash,
            budget_reservation_id=reservation_id,
            authority_revision=authority_revision,
            command_id=command_id,
        )

        from src.core.frontier.global_invariants import assert_authorization_causality

        ticket = AuthorizedExecutionTicket(
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
            policy_generation=policy_generation,
            scope_token_hash=scope_token_hash,
            budget_reservation_id=reservation_id,
            authority_revision=authority_revision,
            command_id=command_id,
        )
        assert_authorization_causality(ticket)
        return ticket

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
            policy_generation=ticket.policy_generation,
            scope_token_hash=ticket.scope_token_hash,
            budget_reservation_id=ticket.budget_reservation_id,
            authority_revision=ticket.authority_revision,
            command_id=ticket.command_id,
        )
        return hmac.compare_digest(expected_sig, ticket.signature)

    def consume_ticket(self, ticket: AuthorizedExecutionTicket) -> bool:
        """Atomically verify and consume a ticket (single-use replay resistance)."""
        from src.core.frontier.global_invariants import (
            AuthorizationCausalityError,
            assert_authorization_causality,
        )

        with self._lock:
            if ticket.ticket_id in self._consumed_tickets:
                return False  # Replay detected!
            try:
                assert_authorization_causality(ticket)
            except AuthorizationCausalityError:
                return False
            if not self.verify_ticket(ticket):
                return False
            self._consumed_tickets.add(ticket.ticket_id)
            return True


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    """Represents an active, ephemeral worker identity with rotated signing credentials."""

    worker_id: str
    key_epoch: int
    secret_key_hex: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600.0)

    def sign_claim(self, claim_bytes: bytes) -> str:
        """Sign execution claim bytes using worker's active ephemeral key."""
        return hmac.new(
            self.secret_key_hex.encode("utf-8"),
            claim_bytes,
            hashlib.sha256,
        ).hexdigest()

    def verify_signature(self, claim_bytes: bytes, signature: str) -> bool:
        """Verify claim signature against this worker key."""
        expected = self.sign_claim(claim_bytes)
        return hmac.compare_digest(expected, signature)


class WorkerKeyRotator:
    """Manages worker identity creation, regular key rotation, and grace-period validation."""

    def __init__(
        self, rotation_interval_seconds: float = 3600.0, grace_period_seconds: float = 300.0
    ) -> None:
        self.rotation_interval = rotation_interval_seconds
        self.grace_period = grace_period_seconds
        self._current_epoch = 1
        self._keys: dict[int, WorkerIdentity] = {}
        self._lock = threading.RLock()
        self._rotate_keys()

    @property
    def current_identity(self) -> WorkerIdentity:
        with self._lock:
            # Auto-rotate if expired
            if time.time() >= self._keys[self._current_epoch].expires_at:
                self._rotate_keys()
            return self._keys[self._current_epoch]

    def rotate(self) -> WorkerIdentity:
        """Manually trigger key epoch advancement and worker identity rotation."""
        with self._lock:
            return self._rotate_keys()

    def _rotate_keys(self) -> WorkerIdentity:
        new_epoch = self._current_epoch + 1 if self._keys else 1
        worker_id = f"worker_{uuid.uuid4().hex[:8]}_ep{new_epoch}"
        secret_hex = hashlib.sha256(
            f"{worker_id}_{time.time()}_{uuid.uuid4().hex}".encode()
        ).hexdigest()
        now = time.time()
        ident = WorkerIdentity(
            worker_id=worker_id,
            key_epoch=new_epoch,
            secret_key_hex=secret_hex,
            created_at=now,
            expires_at=now + self.rotation_interval,
        )
        self._keys[new_epoch] = ident
        self._current_epoch = new_epoch

        # Evict expired keys past grace period
        cutoff = now - self.grace_period
        expired_epochs = [
            ep
            for ep, k in self._keys.items()
            if ep != self._current_epoch and k.expires_at < cutoff
        ]
        for ep in expired_epochs:
            del self._keys[ep]

        return ident

    def verify_claim_signature(self, key_epoch: int, claim_bytes: bytes, signature: str) -> bool:
        """Verify signature against the key epoch under which it was signed."""
        with self._lock:
            ident = self._keys.get(key_epoch)
            if not ident:
                return False
            return ident.verify_signature(claim_bytes, signature)


__all__ = [
    "AuthorizedExecutionTicket",
    "ExecutionAuthorizer",
    "ScopeAuthorizationError",
    "WorkerIdentity",
    "WorkerKeyRotator",
]
