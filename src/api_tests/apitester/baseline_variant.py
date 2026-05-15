from typing import Any, Protocol

from .constants import DEFAULT_TIMEOUT
from .context import build_context
from .http import (
    build_comparison_summary,
    build_request_summary,
    cookie_jar,
    request_headers,
    send_request,
    serialize_comparison,
    serialize_request_summary,
)


class _RequestsLike(Protocol):
    def Session(self) -> Any: ...


def _baseline_target(context: Any) -> str:
    return str(context.baseline_url or context.url)


def _variant_target(context: Any) -> str:
    return str(context.url)


def _run_request_pair(
    context: Any,
    *,
    session: Any,
    headers: dict[str, str],
    cookies: dict[str, str],
    timeout: int,
) -> tuple[Any, Any]:
    baseline_response, baseline_error = send_request(
        session,
        context.method,
        _baseline_target(context),
        headers=headers,
        cookies=cookies,
        timeout=timeout,
    )
    variant_response, variant_error = send_request(
        session,
        context.method,
        _variant_target(context),
        headers=headers,
        cookies=cookies,
        timeout=timeout,
    )
    return (
        build_request_summary(baseline_response, baseline_error),
        build_request_summary(variant_response, variant_error),
    )


def test_api_baseline_vs_variant(
    item: dict[str, Any],
    *,
    requests_module: _RequestsLike | None = None,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    if requests_module is None:
        import requests  # type: ignore[import-untyped]

        requests_module = requests

    context = build_context(item)
    session = requests_module.Session()
    headers = request_headers(auth_headers)
    cookie_map = cookie_jar(cookies)
    baseline_summary, variant_summary = _run_request_pair(
        context,
        session=session,
        headers=headers,
        cookies=cookie_map,
        timeout=timeout,
    )
    comparison = build_comparison_summary(baseline_summary, variant_summary)
    return {
        "title": context.title,
        "method": context.method,
        "parameter": context.parameter or "N/A",
        "variant": context.variant or "N/A",
        "baseline_url": _baseline_target(context),
        "variant_url": _variant_target(context),
        "baseline": serialize_request_summary(baseline_summary),
        "variant_response": serialize_request_summary(variant_summary),
        "comparison": serialize_comparison(comparison),
    }
