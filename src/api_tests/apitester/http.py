from typing import Any

from .client import merge_headers, safe_request
from .constants import DEFAULT_HEADERS
from .models import ComparisonSummary, RequestSummary


def request_headers(auth_headers: dict[str, str] | None) -> dict[str, str]:
    return merge_headers(DEFAULT_HEADERS, auth_headers)


def cookie_jar(cookies: dict[str, str] | None) -> dict[str, str]:
    return cookies or {}


def send_request(
    session: Any,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    timeout: int,
) -> tuple[Any | None, str | None]:
    return safe_request(
        session,
        method,
        url,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
    )


def build_request_summary(response: Any | None, error: str | None) -> RequestSummary:
    if response is None:
        return RequestSummary(
            ok=False,
            error=error or "request failed",
            status_code=None,
            content_type="",
            body_length=0,
        )
    return RequestSummary(
        ok=True,
        error="",
        status_code=response.status_code,
        content_type=response.headers.get("content-type", ""),
        body_length=len(response.text),
    )


def build_comparison_summary(
    baseline: RequestSummary, variant_response: RequestSummary
) -> ComparisonSummary:
    if not baseline.ok or not variant_response.ok:
        return ComparisonSummary(False, False, False)
    status_changed = baseline.status_code != variant_response.status_code
    length_changed = abs(baseline.body_length - variant_response.body_length) > 50
    return ComparisonSummary(
        status_changed=bool(status_changed),
        length_changed=bool(length_changed),
        interesting_difference=bool(status_changed or length_changed),
    )


def serialize_request_summary(summary: RequestSummary) -> dict[str, object]:
    return {
        "ok": summary.ok,
        "error": summary.error,
        "status_code": summary.status_code,
        "content_type": summary.content_type,
        "body_length": summary.body_length,
    }


def serialize_comparison(summary: ComparisonSummary) -> dict[str, bool]:
    return {
        "status_changed": summary.status_changed,
        "length_changed": summary.length_changed,
        "interesting_difference": summary.interesting_difference,
    }
