"""Validation context and base validator class."""

from collections.abc import Callable
from dataclasses import dataclass
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
        score: int,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        in_scope, scope_reason = scope_check(url, context.scope_hosts)
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
        """Shared template for validators with active probing."""
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
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
            if should_probe:
                probe = context.http_client.request(finding["url"])
                error = apply_probe_result(finding=finding, probe=probe)
                if error:
                    errors.append(error)
            findings.append(finding)
        return findings, errors
