"""Engine-level validator plugins for the new R7 categories.

These classes are thin wrappers that delegate to the pure logic in
``src.execution.validators.validators.*`` so the legacy facade
(``validate_target``) and the engine entry point
(``run_blackbox_validation_engine``) can both call them.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from src.core.plugins import register_plugin
from src.execution.validators.config.scoring_config import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
)
from src.execution.validators.engine._base import BaseValidator, ValidationContext
from src.execution.validators.validators.cache_poison import (
    evaluate_cache_poison,
)
from src.execution.validators.validators.cors import evaluate_cors
from src.execution.validators.validators.graphql import evaluate_graphql
from src.execution.validators.validators.jwt import evaluate_jwt
from src.execution.validators.validators.race import evaluate_race_condition

logger = logging.getLogger(__name__)

VALIDATOR = "validator"


def _resolve_scoring(context: ValidationContext, validator_name: str) -> ScoringConfig:
    """Resolve a ScoringConfig from a ValidationContext.

    Falls back to the global ``DEFAULT_SCORING_CONFIG`` table when the
    context has no attached ``ValidationConfig``.
    """
    config = getattr(context, "validation_config", None)
    if config is not None and hasattr(config, "resolve_scoring"):
        return cast(ScoringConfig, config.resolve_scoring(validator_name))
    return DEFAULT_SCORING_CONFIG.get(validator_name, ScoringConfig())


@register_plugin(VALIDATOR, "cors")
class CorsValidator(BaseValidator):
    name = "cors"
    result_key = "cors_validation"
    category = "cors_misconfiguration"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        scoring = _resolve_scoring(context, "cors")
        urls = list(context.ranked_priority_urls or [])
        for entry in urls[: context.per_validator_limit]:
            url = str(entry.get("url", "") if isinstance(entry, dict) else entry)
            try:
                response = context.http_client.request(url, method="GET")
            except Exception as exc:  # noqa: BLE001
                errors.append(self._error_entry(url, exc, context))
                continue
            evaluation = evaluate_cors(
                request_origin=str(context.cors_probe_origin or ""),
                response_headers=dict(response.get("headers", {}) or {}),
                scoring=scoring,
                in_scope=bool(context.in_scope_for(url)),
            )
            finding = self._base_finding(
                url=url,
                context=context,
                confidence=evaluation["confidence"],
                validation_state=str(evaluation["status"]),
                signals=evaluation["signals"],
            )
            finding["evidence"] = evaluation["evidence"]
            findings.append(finding)
        return findings, errors


@register_plugin(VALIDATOR, "jwt_weakness")
class JwtValidator(BaseValidator):
    name = "jwt_weakness"
    result_key = "jwt_validation"
    category = "jwt_weakness"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        scoring = _resolve_scoring(context, "jwt_weakness")
        candidates = list(context.jwt_candidates or [])
        if not candidates:
            return findings, errors
        _priority_urls: list[str] = [
            str(item.get("url", "") if isinstance(item, dict) else item)
            for item in context.ranked_priority_urls or []
        ]
        in_scope_urls = {url for url in _priority_urls if context.in_scope_for(url)}
        candidate_secrets = list(context.jwt_test_secrets or ())
        for candidate in candidates[: context.per_validator_limit]:
            token = str(candidate.get("token", "") or "")
            target_url = str(candidate.get("target_url", "") or "")
            if not token:
                continue
            in_scope = (not target_url) or (target_url in in_scope_urls)
            try:
                evaluation = evaluate_jwt(
                    token=token,
                    scoring=scoring,
                    candidate_secrets=candidate_secrets,
                    jwt_evaluate=(
                        (lambda ctoken: context.http_client.jwt_probe(ctoken, target_url))
                        if target_url and hasattr(context.http_client, "jwt_probe")
                        else None
                    ),
                    kid_evaluate=(
                        (lambda ctoken, kid: context.http_client.jwt_probe(ctoken, target_url))
                        if target_url and hasattr(context.http_client, "jwt_probe")
                        else None
                    ),
                    in_scope=in_scope,
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(self._error_entry(target_url or "<jwt>", exc, context))
                continue
            finding = self._base_finding(
                url=target_url or "<jwt>",
                context=context,
                confidence=evaluation["confidence"],
                validation_state=str(evaluation["status"]),
                signals=evaluation["signals"],
            )
            finding["evidence"] = evaluation["evidence"]
            findings.append(finding)
        return findings, errors


@register_plugin(VALIDATOR, "cache_poisoning")
class CachePoisoningValidator(BaseValidator):
    name = "cache_poisoning"
    result_key = "cache_poisoning_validation"
    category = "cache_poisoning"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        scoring = _resolve_scoring(context, "cache_poisoning")
        unkeyed_headers = list(
            context.cache_poisoning_unkeyed_headers
            or ("X-Forwarded-Host", "X-Original-URL", "X-Host")
        )
        _priority_urls: list[str] = [
            str(item.get("url", "") if isinstance(item, dict) else item)
            for item in context.ranked_priority_urls or []
        ]
        urls = list(_priority_urls)
        for url in urls[: context.per_validator_limit]:
            for header in unkeyed_headers:
                try:
                    probe = context.http_client.cache_poison_probe(url, header)
                except Exception as exc:  # noqa: BLE001
                    errors.append(self._error_entry(url, exc, context))
                    continue
                evaluation = evaluate_cache_poison(
                    target_url=url,
                    unkeyed_header=header,
                    probe_response=(
                        cast(dict[str, Any], probe).get("probe_response") if probe else None
                    ),
                    followup_response=(
                        cast(dict[str, Any], probe).get("followup_response") if probe else None
                    ),
                    scoring=scoring,
                    in_scope=bool(context.in_scope_for(url)),
                )
                finding = self._base_finding(
                    url=url,
                    context=context,
                    confidence=evaluation["confidence"],
                    validation_state=str(evaluation["status"]),
                    signals=evaluation["signals"],
                )
                finding["evidence"] = evaluation["evidence"]
                findings.append(finding)
        return findings, errors


@register_plugin(VALIDATOR, "graphql_abuse")
class GraphqlValidator(BaseValidator):
    name = "graphql_abuse"
    result_key = "graphql_validation"
    category = "graphql_abuse"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        scoring = _resolve_scoring(context, "graphql_abuse")
        endpoints = list(context.graphql_endpoints or [])
        if not endpoints:
            return findings, errors
        for endpoint in endpoints[: context.per_validator_limit]:
            in_scope = bool(context.in_scope_for(endpoint))
            try:
                evaluation = evaluate_graphql(
                    endpoint=endpoint,
                    scoring=scoring,
                    graphql_request=(
                        (lambda ep, q: context.http_client.graphql_probe(ep, q))
                        if hasattr(context.http_client, "graphql_probe")
                        else None
                    ),
                    in_scope=in_scope,
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(self._error_entry(endpoint, exc, context))
                continue
            finding = self._base_finding(
                url=endpoint,
                context=context,
                confidence=evaluation["confidence"],
                validation_state=str(evaluation["status"]),
                signals=evaluation["signals"],
            )
            finding["evidence"] = evaluation["evidence"]
            findings.append(finding)
        return findings, errors


@register_plugin(VALIDATOR, "race_condition")
class RaceConditionValidator(BaseValidator):
    name = "race_condition"
    result_key = "race_condition_validation"
    category = "race_condition"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        scoring = _resolve_scoring(context, "race_condition")
        _priority_urls: list[str] = [
            str(item.get("url", "") if isinstance(item, dict) else item)
            for item in context.ranked_priority_urls or []
        ]
        urls = list(_priority_urls)
        concurrency = int(context.race_concurrency or 5)
        for url in urls[: context.per_validator_limit]:
            try:
                responses = context.http_client.race_probe(url, concurrency=concurrency)
            except Exception as exc:  # noqa: BLE001
                errors.append(self._error_entry(url, exc, context))
                continue
            evaluation = evaluate_race_condition(
                target_url=url,
                responses=responses,
                scoring=scoring,
                expected_concurrency=concurrency,
                in_scope=bool(context.in_scope_for(url)),
            )
            finding = self._base_finding(
                url=url,
                context=context,
                confidence=evaluation["confidence"],
                validation_state=str(evaluation["status"]),
                signals=evaluation["signals"],
            )
            finding["evidence"] = evaluation["evidence"]
            findings.append(finding)
        return findings, errors
