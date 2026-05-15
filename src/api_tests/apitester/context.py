from typing import Any
from urllib.parse import parse_qsl, urlparse

from .constants import DEFAULT_METHOD, DEFAULT_NEXT_STEP, DEFAULT_TITLE
from .models import ApiTestContext


def clean(value: object) -> str:
    return str(value or "").strip()


def request_context(item: dict[str, Any]) -> dict[str, Any]:
    return item.get("request_context", {}) or {}


def request_url(item: dict[str, Any], context: dict[str, Any]) -> str:
    return (
        clean(context.get("mutated_url"))
        or clean(item.get("mutated_request_url"))
        or clean(item.get("url"))
    )


def baseline_url(context: dict[str, Any]) -> str:
    return clean(context.get("baseline_url"))


def parameter_details(item: dict[str, Any], context: dict[str, Any]) -> tuple[str, str]:
    parameter = clean(context.get("parameter")) or clean(item.get("parameter"))
    variant = clean(context.get("variant")) or clean(item.get("variant"))
    return parameter, variant


def request_method(context: dict[str, Any]) -> str:
    return (clean(context.get("method")) or DEFAULT_METHOD).upper()


def path_and_query(url: str) -> tuple[str, str]:
    if not url:
        return "", ""
    parsed = urlparse(url)
    query = "&".join(
        f"{key}={value}" for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    )
    return parsed.path or "/", query


def next_step(item: dict[str, Any]) -> str:
    return clean(item.get("next_step")) or DEFAULT_NEXT_STEP


def replay_id(item: dict[str, Any]) -> str:
    return clean(item.get("replay_id") or (item.get("replay", {}) or {}).get("id"))


def combined_signal(item: dict[str, Any]) -> str:
    signals = ", ".join(str(signal) for signal in item.get("signals", []) if signal)
    return clean(item.get("combined_signal")) or signals or "none"


def build_context(item: dict[str, Any]) -> ApiTestContext:
    context = request_context(item)
    title = clean(item.get("title")) or DEFAULT_TITLE
    method = request_method(context)
    url = request_url(item, context)
    base_url = baseline_url(context)
    parameter, variant = parameter_details(item, context)
    path, query = path_and_query(url)
    base_path, base_query = path_and_query(base_url)
    return ApiTestContext(
        title=title,
        severity=clean(item.get("severity")).upper() or "INFO",
        confidence=clean(item.get("confidence")),
        method=method,
        url=url,
        baseline_url=base_url,
        path=path,
        query=query,
        baseline_path=base_path,
        baseline_query=base_query,
        parameter=parameter,
        variant=variant,
        replay_id=replay_id(item),
        combined_signal=combined_signal(item),
        next_step=next_step(item),
    )
