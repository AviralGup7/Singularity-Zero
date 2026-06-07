"""Validation context and base validator class."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.core.contracts.pipeline import VALIDATION_RESULT_SCHEMA_VERSION
from src.execution.validators.engine_helpers import scope_check
from src.execution.validators.shared_utils import (
    apply_probe_result,
    build_base_finding,
    mark_out_of_scope,
)

from ._http_client import ValidationHttpClient


@dataclass
class ValidationContext:
    analysis_results: dict[str, list[dict[str, Any]]]
    ranked_priority_urls: list[dict[str, Any]]
    callback_context: dict[str, Any]
    token_replay: dict[str, Any]
    runtime_inputs: dict[str, Any]
    scope_hosts: set[str]
    http_client: ValidationHttpClient
    active_probe_enabled: bool
    per_validator_limit: int
    selector_config: dict[str, Any]
    # R1/R2/R7 extensions. All default to safe no-op values so the
    # dataclass remains backwards compatible with existing callers.
    validation_config: Any = None
    scope_policy: Any = None
    replay_safety: Any = None
    cors_probe_origin: str = ""
    jwt_candidates: list[dict[str, Any]] = field(default_factory=list)
    jwt_test_secrets: tuple[str, ...] = ()
    cache_poisoning_unkeyed_headers: tuple[str, ...] = (
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Host",
    )
    graphql_endpoints: list[str] = field(default_factory=list)
    race_concurrency: int = 5
    graphql_introspection_query: str = ""

    def in_scope_for(self, url: str) -> bool:
        """Return whether ``url`` is in scope for active probing.

        Honours the engagement-wide ``ScopePolicy`` (R2): if no scope
        hosts are configured, returns False and emits a warning.
        """
        in_scope, reason = scope_check(url, self.scope_hosts or set())
        if not self.scope_hosts and getattr(self.scope_policy, "block_active_when_unscoped", True):
            return False
        return in_scope


class BaseValidator:
    name: str = "base"
    result_key: str = "base_validation"
    category: str = "generic"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        raise NotImplementedError

    def _base_finding(
        self,
        *,
        url: str,
        context: ValidationContext,
        confidence: float,
        validation_state: str,
        signals: list[str],
        score: int = 0,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        in_scope, scope_reason = scope_check(url, context.scope_hosts)
        # R2: when no scope is configured, treat the finding as out of scope
        # instead of reporting scope_unavailable.
        policy = getattr(context, "scope_policy", None)
        if (
            not context.scope_hosts
            and policy is not None
            and getattr(policy, "treat_unscoped_as_out_of_scope", True)
        ):
            in_scope = False
            scope_reason = "scope_unavailable"
        return build_base_finding(
            schema_version=str(VALIDATION_RESULT_SCHEMA_VERSION),
            validator_name=self.name,
            category=self.category,
            url=url,
            in_scope=in_scope,
            scope_reason=scope_reason,
            confidence=confidence,
            validation_state=validation_state,
            signals=signals,
            score=score,
            timeout_seconds=context.http_client.config.timeout_seconds,
            scope_hosts=context.scope_hosts,
            selector_config=context.selector_config,
            evidence=evidence,
        )

    def _error_entry(
        self,
        url: str,
        exc: BaseException,
        context: ValidationContext,
    ) -> dict[str, Any]:
        return {
            "url": url,
            "validator": self.name,
            "category": self.category,
            "error": {
                "type": exc.__class__.__name__,
                "message": str(exc),
            },
            "timeout_seconds": context.http_client.config.timeout_seconds,
        }

    def _run_passive_validation(
        self,
        context: ValidationContext,
        items: list[dict[str, Any]],
        evidence_fn: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Shared template for passive-only validators."""
        findings: list[dict[str, Any]] = []
        for item in items[: context.per_validator_limit]:
            findings.append(
                self._base_finding(
                    url=str(item.get("url", "")),
                    context=context,
                    confidence=float(item.get("confidence", 0.0)),
                    validation_state=str(item.get("validation_state", "passive_only")),
                    signals=list(item.get("signals", [])),
                    score=int(item.get("score", 0)),
                    evidence=evidence_fn(item),
                )
            )
        return findings, []

    def _run_active_validation(
        self,
        context: ValidationContext,
        items: list[dict[str, Any]],
        evidence_fn: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        active_ready_check: bool = False,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Shared template for validators with active probing.

        R2: when scope is empty, mark findings as out_of_scope and skip
        the active probe (the engagement must explicitly opt in).
        """
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        policy = getattr(context, "scope_policy", None)
        block_when_unscoped = bool(
            policy is not None and getattr(policy, "block_active_when_unscoped", True)
        )
        for item in items[: context.per_validator_limit]:
            finding = self._base_finding(
                url=str(item.get("url", "")),
                context=context,
                confidence=float(item.get("confidence", 0.0)),
                validation_state=str(item.get("validation_state", "passive_only")),
                signals=list(item.get("signals", [])),
                score=int(item.get("score", 0)),
                evidence=evidence_fn(item),
            )
            if not finding["in_scope"]:
                mark_out_of_scope(finding)
                findings.append(finding)
                continue
            should_probe = context.active_probe_enabled
            if should_probe and active_ready_check:
                should_probe = finding["validation_state"] == "active_ready"
            if not context.scope_hosts and block_when_unscoped:
                should_probe = False
            if should_probe:
                probe = context.http_client.request(finding["url"])
                error = apply_probe_result(finding=finding, probe=probe)
                if error:
                    errors.append(error)
            findings.append(finding)
        return findings, errors
