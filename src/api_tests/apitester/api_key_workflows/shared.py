from typing import Any

from ..client import (
    build_base_headers,
    display_secret,
    materialize_key_locations,
    normalize_base_url,
    perform_request,
)

JsonMap = dict[str, object]
StrMap = dict[str, str]

KEY_LOCATION_TEMPLATES: list[dict[str, object]] = [
    {"name": "X-API-Key Header", "headers": {"X-API-Key": "{api_key}"}, "params": {}},
    {
        "name": "Authorization: Bearer",
        "headers": {"Authorization": "Bearer {api_key}"},
        "params": {},
    },
    {"name": "Authorization: Token", "headers": {"Authorization": "Token {api_key}"}, "params": {}},
    {"name": "Query Parameter (apikey)", "headers": {}, "params": {"apikey": "{api_key}"}},
    {"name": "Query Parameter (key)", "headers": {}, "params": {"key": "{api_key}"}},
    {"name": "Query Parameter (token)", "headers": {}, "params": {"token": "{api_key}"}},
]


def base_headers(user_agent: str) -> StrMap:
    return build_base_headers(user_agent)


def key_locations(api_key: str) -> list[dict[str, object]]:
    return materialize_key_locations(KEY_LOCATION_TEMPLATES, api_key)


def placement_request_parts(base: StrMap, placement: dict[str, object]) -> tuple[StrMap, StrMap]:
    headers_val = placement.get("headers", {})
    params_val = placement.get("params", {})
    hdrs: StrMap = {**base}
    if isinstance(headers_val, dict):
        hdrs.update({k: str(v) for k, v in headers_val.items()})
    prms: StrMap = {}
    if isinstance(params_val, dict):
        prms.update({k: str(v) for k, v in params_val.items()})
    return hdrs, prms


def safe_json_keys(response: Any) -> list[str]:
    try:
        data = response.json()
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, dict):
        return [str(key) for key in list(data.keys())[:8]]
    return []


def request(
    session: Any,
    method: str,
    url: str,
    *,
    headers: StrMap,
    params: StrMap | None = None,
    cookies: dict[str, str] | None = None,
    timeout: int = 10,
    proxies: dict[str, str] | None = None,
    json_body: JsonMap | None = None,
    allow_redirects: bool = True,
) -> Any:
    return perform_request(
        session,
        method,
        url,
        headers=headers,
        params=params,
        cookies=cookies,
        timeout=timeout,
        proxies=proxies,
        json_body=json_body,
        allow_redirects=allow_redirects,
    )


def print_banner(title: str, detail_lines: list[str], *, divider_width: int) -> None:
    print(title)
    for line in detail_lines:
        print(line)
    print("=" * divider_width)


def print_section_header(title: str, *, divider_width: int) -> None:
    print(f"\n{title}")
    print("-" * divider_width)


def print_summary_header(title: str, *, divider_width: int) -> None:
    print("\n" + "=" * divider_width)
    print(title)
    print("=" * divider_width)


__all__ = [
    "base_headers",
    "display_secret",
    "key_locations",
    "normalize_base_url",
    "placement_request_parts",
    "print_banner",
    "print_section_header",
    "print_summary_header",
    "request",
    "safe_json_keys",
]
