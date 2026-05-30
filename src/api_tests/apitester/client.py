from typing import Any

JsonMap = dict[str, object]
StrMap = dict[str, str]


def normalize_base_url(base_url: str) -> str:
    return base_url if base_url.endswith("/") else f"{base_url}/"


def display_secret(secret: str) -> str:
    if len(secret) <= 12:
        return secret
    return f"{secret[:8]}...{secret[-4:]}"


def build_base_headers(
    user_agent: str,
    *,
    accept: str = "application/json",
    content_type: str = "application/json",
) -> StrMap:
    return {
        "User-Agent": user_agent,
        "Accept": accept,
        "Content-Type": content_type,
    }


def merge_headers(*parts: dict[str, str] | None) -> StrMap:
    merged: StrMap = {}
    for part in parts:
        if part:
            merged.update(part)
    return merged


def materialize_key_location(template: dict[str, object], api_key: str) -> dict[str, object]:
    headers_template = template.get("headers", {})
    params_template = template.get("params", {})
    headers = {
        key: str(value).format(api_key=api_key)
        for key, value in (
            dict(headers_template) if isinstance(headers_template, dict) else {}
        ).items()
    }
    params = {
        key: str(value).format(api_key=api_key)
        for key, value in (
            dict(params_template) if isinstance(params_template, dict) else {}
        ).items()
    }
    return {
        "name": str(template.get("name", "unknown")),
        "headers": headers,
        "params": params,
    }


def materialize_key_locations(
    templates: list[dict[str, object]], api_key: str
) -> list[dict[str, object]]:
    return [materialize_key_location(template, api_key) for template in templates]


def perform_request(
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
    return session.request(
        method.upper(),
        url,
        headers=headers,
        params=params or {},
        cookies=cookies,
        timeout=timeout,
        proxies=proxies,
        json=json_body,
        allow_redirects=allow_redirects,
    )


def safe_request(
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
) -> tuple[Any | None, str | None]:
    if not url:
        return None, "missing url"
    try:
        response = perform_request(
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
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)
    return response, None


def summarize_response(
    response: Any | None, error: str | None, *, fallback_url: str = ""
) -> dict[str, object]:
    if response is None:
        return {
            "ok": False,
            "error": error or "request failed",
            "status_code": None,
            "body_length": 0,
            "final_url": fallback_url,
            "content_type": "",
        }
    return {
        "ok": True,
        "error": "",
        "status_code": response.status_code,
        "body_length": len(response.text),
        "final_url": getattr(response, "url", fallback_url),
        "content_type": response.headers.get("content-type", ""),
    }
