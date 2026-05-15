"""Individual validator implementations."""

from typing import Any

from src.core.plugins import register_plugin
from src.execution.validators.engine_helpers import compare_response_shapes, mutate_identifier
from src.execution.validators.shared_utils import apply_probe_result, mark_out_of_scope
from src.execution.validators.validators.csrf import validate_csrf_candidates
from src.execution.validators.validators.file_upload import validate_file_upload_candidates
from src.execution.validators.validators.idor import validate_idor_candidates
from src.execution.validators.validators.redirect import validate_redirect_candidates
from src.execution.validators.validators.ssrf import validate_ssrf_candidates
from src.execution.validators.validators.ssti import validate_ssti_candidates
from src.execution.validators.validators.xss import validate_xss_candidates

from ._base import BaseValidator, ValidationContext

VALIDATOR = "validator"


@register_plugin(VALIDATOR, "redirect")
class RedirectValidator(BaseValidator):
    name = "redirect"
    result_key = "open_redirect_validation"
    category = "open_redirect"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        items = validate_redirect_candidates(context.ranked_priority_urls, context.callback_context)
        return self._run_active_validation(
            context,
            items,
            evidence_fn=lambda item: {
                "matched_parameters": item.get("matched_parameters", []),
                "callback_provider": item.get("callback_provider", "none"),
                "hint_message": item.get("hint_message", ""),
            },
        )


@register_plugin(VALIDATOR, "ssrf")
class SsrfValidator(BaseValidator):
    name = "ssrf"
    category = "ssrf"
    result_key = "ssrf_validation"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        items = validate_ssrf_candidates(context.analysis_results, context.callback_context)
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
                evidence={
                    "parameters": item.get("parameters", []),
                    "hint_message": item.get("hint_message", ""),
                },
            )
            if not finding["in_scope"]:
                mark_out_of_scope(finding)
                findings.append(finding)
                continue
            if context.active_probe_enabled and finding["validation_state"] == "active_ready":
                probe = context.http_client.request(finding["url"])
                error = apply_probe_result(finding=finding, probe=probe)
                if error:
                    errors.append(error)
            findings.append(finding)
        return findings, errors


@register_plugin(VALIDATOR, "token_reuse")
class TokenReuseValidator(BaseValidator):
    name = "token_reuse"
    result_key = "token_reuse_validation"
    category = "token_reuse"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        grouped = list(context.token_replay.get("grouped_by_endpoint", []))
        findings: list[dict[str, Any]] = []
        for item in grouped[: context.per_validator_limit]:
            findings.append(
                self._base_finding(
                    url=str(item.get("url", "")),
                    context=context,
                    confidence=float(item.get("replay_likelihood", 0.0)),
                    validation_state="passive_only",
                    signals=list(item.get("signals", [])),
                    score=int(item.get("leak_count", 0)),
                    evidence={
                        "location": item.get("location", "unknown"),
                        "repeat_count": item.get("repeat_count", 0),
                        "token_shapes": item.get("token_shapes", []),
                        "recommended_action": context.token_replay.get("recommended_action", ""),
                    },
                )
            )
        return findings, []


@register_plugin(VALIDATOR, "idor")
class IdorValidator(BaseValidator):
    name = "idor"
    result_key = "idor_validation"
    category = "idor"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        items = validate_idor_candidates(context.analysis_results, context.token_replay)
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for item in items[: context.per_validator_limit]:
            finding = self._base_finding(
                url=str(item.get("url", "")),
                context=context,
                confidence=float(item.get("confidence", 0.0)),
                validation_state=str(item.get("validation_state", "heuristic_candidate")),
                signals=list(item.get("signals", [])),
                score=int(item.get("score", 0)),
                evidence={
                    "query_keys": item.get("query_keys", []),
                    "identifier_hints": item.get("identifier_hints", []),
                    "object_family": item.get("object_family", "generic_object"),
                    "comparison": item.get("comparison", {}),
                    "hint_message": item.get("hint_message", ""),
                },
            )
            if not finding["in_scope"]:
                mark_out_of_scope(finding)
                findings.append(finding)
                continue
            if (
                context.active_probe_enabled
                and finding["validation_state"] != "response_similarity_match"
            ):
                mutated = mutate_identifier(finding["url"])
                if mutated:
                    original = context.http_client.request(finding["url"])
                    variant = context.http_client.request(mutated)
                    if original.get("ok") and variant.get("ok"):
                        similarity_state = compare_response_shapes(original, variant)
                        finding["validation_state"] = similarity_state
                        finding["http"] = variant
                        finding["evidence"]["mutated_url"] = mutated
                        orig_len = original.get("body_length", 0)
                        var_len = variant.get("body_length", 0)
                        if similarity_state == "potential_idor":
                            finding["evidence"]["explanation"] = (
                                f"Response bodies differ significantly (original: {orig_len}B, mutated: {var_len}B) "
                                f"when identifier was changed, suggesting possible IDOR vulnerability."
                            )
                        elif similarity_state == "response_similarity_match":
                            finding["evidence"]["explanation"] = (
                                f"Responses are highly similar (original: {orig_len}B, mutated: {var_len}B), "
                                f"suggesting the endpoint may not properly validate resource ownership."
                            )
                        else:
                            finding["evidence"]["explanation"] = (
                                f"IDOR probe completed with state: {similarity_state} "
                                f"(original: {orig_len}B, mutated: {var_len}B)."
                            )
                    else:
                        finding["status"] = "error"
                        finding["http"] = variant if not variant.get("ok") else original
                        finding["error"] = {
                            "code": "idor_probe_failed",
                            "message": str(finding["http"].get("error") or "request failed"),
                        }
                        errors.append(
                            {
                                "validator": self.name,
                                "url": finding["url"],
                                "error": finding["error"],
                            }
                        )
            findings.append(finding)
        return findings, errors


@register_plugin(VALIDATOR, "csrf")
class CsrfValidator(BaseValidator):
    name = "csrf"
    result_key = "csrf_validation"
    category = "csrf"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        items = validate_csrf_candidates(context.analysis_results, context.callback_context)
        return self._run_passive_validation(
            context,
            items,
            evidence_fn=lambda item: {
                "missing_protections": item.get("missing_protections", []),
                "hint_message": item.get("hint_message", ""),
            },
        )


@register_plugin(VALIDATOR, "xss")
class XssValidator(BaseValidator):
    name = "xss"
    result_key = "xss_validation"
    category = "xss"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        items = validate_xss_candidates(context.analysis_results, context.callback_context)
        return self._run_passive_validation(
            context,
            items,
            evidence_fn=lambda item: {
                "xss_signals": item.get("xss_signals", []),
                "context_danger_score": item.get("context_danger_score", 0),
                "hint_message": item.get("hint_message", ""),
            },
        )


@register_plugin(VALIDATOR, "ssti")
class SstiValidator(BaseValidator):
    name = "ssti"
    result_key = "ssti_validation"
    category = "ssti"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        items = validate_ssti_candidates(context.analysis_results, context.callback_context)
        return self._run_passive_validation(
            context,
            items,
            evidence_fn=lambda item: {
                "detected_engines": item.get("detected_engines", []),
                "template_parameters": item.get("template_parameters", []),
                "hint_message": item.get("hint_message", ""),
            },
        )


@register_plugin(VALIDATOR, "file_upload")
class FileUploadValidator(BaseValidator):
    name = "file_upload"
    result_key = "file_upload_validation"
    category = "file_upload"

    def run(self, context: ValidationContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        items = validate_file_upload_candidates(context.analysis_results, context.callback_context)
        return self._run_passive_validation(
            context,
            items,
            evidence_fn=lambda item: {
                "upload_parameters": item.get("upload_parameters", []),
                "dangerous_extensions": item.get("dangerous_extensions", []),
                "hint_message": item.get("hint_message", ""),
            },
        )
