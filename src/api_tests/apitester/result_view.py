from typing import Any

from .context import build_context
from .results.formatting import clean_bool, clean_number, clean_text


def _shared_key_fields(item: dict[str, Any]) -> str:
    evidence = item.get("evidence", {}) or {}
    fields = evidence.get("shared_key_fields") or []
    if not fields:
        return "none"
    return ", ".join(str(field) for field in fields[:8])


def _body_similarity(item: dict[str, Any]) -> object:
    evidence = item.get("evidence", {}) or {}
    diff_summary = evidence.get("diff_summary", {}) or {}
    return (
        diff_summary.get("body_similarity")
        if "body_similarity" in diff_summary
        else evidence.get("body_similarity")
    )


def _length_delta(item: dict[str, Any]) -> object:
    evidence = item.get("evidence", {}) or {}
    diff_summary = evidence.get("diff_summary", {}) or {}
    return diff_summary.get("length_delta")


def _mutated_url(item: dict[str, Any]) -> str:
    context = item.get("request_context", {}) or {}
    evidence = item.get("evidence", {}) or {}
    return clean_text(
        context.get("mutated_url") or item.get("mutated_request_url") or evidence.get("mutated_url")
    )


def _baseline_url(item: dict[str, Any]) -> str:
    context = item.get("request_context", {}) or {}
    return clean_text(context.get("baseline_url") or item.get("url"))


def _request_method(item: dict[str, Any]) -> str:
    context = item.get("request_context", {}) or {}
    return clean_text(context.get("method"), "GET").upper()


def _parameter(item: dict[str, Any]) -> str:
    context = item.get("request_context", {}) or {}
    return clean_text(context.get("parameter") or item.get("parameter"), "n/a")


def _variant(item: dict[str, Any]) -> str:
    context = item.get("request_context", {}) or {}
    return clean_text(context.get("variant") or item.get("variant"), "n/a")


def _replay_id(item: dict[str, Any]) -> str:
    return clean_text(
        item.get("replay_id")
        or (item.get("replay", {}) or {}).get("id")
        or (item.get("evidence", {}).get("replay", {}) or {}).get("id"),
        "n/a",
    )


def build_result_view(item: dict[str, Any]) -> dict[str, object]:
    context = build_context(item)
    evidence = item.get("evidence", {}) or {}
    diff_summary = evidence.get("diff_summary", {}) or {}

    baseline_url = _baseline_url(item) or context.baseline_url or "n/a"
    variant_url = _mutated_url(item) or context.url or "n/a"
    parameter = _parameter(item)
    variant = _variant(item)

    return {
        "title": context.title,
        "baseline_url": baseline_url,
        "variant_url": variant_url,
        "parameter": parameter,
        "variant": variant,
        "request_method": _request_method(item),
        "status_changed": clean_bool(diff_summary.get("status_changed")),
        "redirect_changed": clean_bool(diff_summary.get("redirect_changed")),
        "content_changed": clean_bool(diff_summary.get("content_changed")),
        "trust_boundary_shift": clean_bool(
            item.get("trust_boundary_shift") or evidence.get("trust_boundary_shift")
        ),
        "body_similarity": clean_number(_body_similarity(item)),
        "length_delta": clean_number(_length_delta(item), digits=0),
        "shared_key_fields": _shared_key_fields(item),
        "replay_id": _replay_id(item),
    }
