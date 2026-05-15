from typing import Any, Protocol

from .client import materialize_key_location, normalize_base_url, safe_request, summarize_response
from .constants import (
    DEFAULT_HEADERS,
    DEFAULT_KEY_LOCATIONS,
    DEFAULT_SENSITIVE_ENDPOINTS,
    DEFAULT_TIMEOUT,
)
from .http import cookie_jar


class _RequestsLike(Protocol):
    def Session(self) -> Any: ...


def _format_key_location(template: dict[str, Any], api_key: str) -> dict[str, Any]:
    return materialize_key_location(template, api_key)


def _probe_endpoint(
    session: Any,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str],
    cookies: dict[str, str],
    timeout: int,
) -> dict[str, object]:
    response, error = safe_request(
        session,
        "GET",
        url,
        headers=headers,
        params=params,
        cookies=cookies,
        timeout=timeout,
    )
    summary = summarize_response(response, error, fallback_url=url)
    return {
        "ok": summary["ok"],
        "error": summary["error"],
        "status_code": summary["status_code"],
        "body_length": summary["body_length"],
    }


def test_api_key_security(
    base_url: str,
    api_key: str,
    *,
    requests_module: _RequestsLike | None = None,
    cookies: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    endpoints: list[str] | None = None,
) -> dict[str, object]:
    if requests_module is None:
        import requests  # type: ignore[import-untyped]

        requests_module = requests

    session = requests_module.Session()
    try:
        normalized_base_url = normalize_base_url(base_url)
        cookie_map = cookie_jar(cookies)
        endpoint_list = endpoints or DEFAULT_SENSITIVE_ENDPOINTS
        results: list[dict[str, object]] = []

        for template in DEFAULT_KEY_LOCATIONS:
            location = _format_key_location(template, api_key)
            location_headers = {
                **DEFAULT_HEADERS,
                **dict(location.get("headers", {})),
            }
            location_params: dict[str, Any] = dict(location.get("params", {}))
            endpoint_results: list[dict[str, object]] = []
            for endpoint in endpoint_list:
                endpoint_results.append(
                    {
                        "endpoint": endpoint,
                        **_probe_endpoint(
                            session,
                            f"{normalized_base_url}{endpoint}",
                            headers=location_headers,
                            params=location_params,
                            cookies=cookie_map,
                            timeout=timeout,
                        ),
                    }
                )
            results.append(
                {
                    "location": location["name"],
                    "headers": location_headers,
                    "params": location_params,
                    "results": endpoint_results,
                }
            )

        return {
            "base_url": normalized_base_url,
            "tested_locations": len(results),
            "results": results,
        }
    finally:
        session.close()
