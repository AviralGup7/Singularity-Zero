import time
from typing import Any
from urllib.parse import urlparse

from .api_key_candidates import discover_api_key_candidates
from .client import build_base_headers, normalize_base_url, safe_request, summarize_response


def _request(
    session: Any,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
    timeout: int = 10,
    json_body: dict[str, Any] | None = None,
) -> dict[str, object]:
    response, error = safe_request(
        session,
        method,
        url,
        headers=headers,
        params=params,
        timeout=timeout,
        json_body=json_body,
        allow_redirects=True,
    )
    return summarize_response(response, error, fallback_url=url)


def _base_headers(user_agent: str) -> dict[str, str]:
    return build_base_headers(
        user_agent,
        accept="application/json, text/plain, */*",
        content_type="application/json",
    )


def _placements(candidate: dict[str, str]) -> list[dict[str, Any]]:
    key_value = candidate["key_value"]
    placements: list[dict[str, Any]] = [
        {"name": "header:x-api-key", "headers": {"X-API-Key": key_value}, "params": {}},
        {
            "name": "header:authorization-bearer",
            "headers": {"Authorization": f"Bearer {key_value}"},
            "params": {},
        },
        {
            "name": "header:authorization-token",
            "headers": {"Authorization": f"Token {key_value}"},
            "params": {},
        },
        {"name": "query:apikey", "headers": {}, "params": {"apikey": key_value}},
        {"name": "query:key", "headers": {}, "params": {"key": key_value}},
        {"name": "query:token", "headers": {}, "params": {"token": key_value}},
    ]
    preferred = candidate.get("placement", "")
    placements.sort(key=lambda item: item["name"] != preferred)
    return placements


def _compare(result_with_key: dict[str, object], result_without_key: dict[str, object]) -> str:
    if not result_with_key.get("ok") or not result_without_key.get("ok"):
        return "inconclusive"
    if result_with_key.get("status_code") != result_without_key.get("status_code"):
        return "status_changed"
    if result_with_key.get("body_length") != result_without_key.get("body_length"):
        return "size_changed"
    return "same_shape"


def _record(
    check_id: str, title: str, outcome: str, summary: str, **details: Any
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "outcome": outcome,
        "summary": summary,
        "details": details,
    }


def _different_host_urls(base_url: str) -> list[str]:
    parsed = urlparse(base_url)
    host = parsed.netloc
    labels = host.split(".")
    if len(labels) < 2:
        return []
    base_domain = ".".join(labels[-2:])
    return [
        f"{parsed.scheme}://{sub}.{base_domain}/"
        for sub in ("api", "app", "admin", "staging", "dev", "console")
    ]


def _run_candidate(session: Any, candidate: dict[str, str], timeout: int) -> dict[str, Any]:
    base_url = normalize_base_url(candidate.get("base_url", ""))
    base_headers = _base_headers("Mozilla/5.0 (Codex API Key Validation)")
    placement = _placements(candidate)[0]
    auth_headers: dict[str, str] = {**base_headers, **placement.get("headers", {})}
    auth_params: dict[str, str] = placement.get("params", {})
    no_auth_headers = dict(base_headers)
    no_auth_params: dict[str, str] = {}
    checks: list[dict[str, Any]] = []

    direct_with_key = _request(
        session,
        "GET",
        f"{base_url}users/me",
        headers=auth_headers,
        params=auth_params,
        timeout=timeout,
    )
    direct_without_key = _request(
        session,
        "GET",
        f"{base_url}users/me",
        headers=no_auth_headers,
        params=no_auth_params,
        timeout=timeout,
    )
    direct_compare = _compare(direct_with_key, direct_without_key)
    checks.append(
        _record(
            "direct_no_login",
            "Direct API request without login",
            "risk" if direct_with_key.get("status_code") == 200 else "ok",
            f"with key {direct_with_key.get('status_code')} vs no key {direct_without_key.get('status_code')}",
            compare=direct_compare,
        )
    )

    sensitive_hits: list[dict[str, Any]] = []
    for endpoint in ("users", "orders", "admin", "admin/users", "admin/dashboard"):
        result = _request(
            session,
            "GET",
            f"{base_url}{endpoint}",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
        )
        sensitive_hits.append(
            {
                "endpoint": endpoint,
                "status_code": result.get("status_code"),
                "body_length": result.get("body_length"),
            }
        )
    risky_sensitive = [item for item in sensitive_hits if item.get("status_code") == 200]
    checks.append(
        _record(
            "sensitive_endpoints",
            "Sensitive endpoints with key",
            "risk" if risky_sensitive else "ok",
            f"{len(risky_sensitive)} of {len(sensitive_hits)} sensitive endpoints returned 200",
            hits=risky_sensitive[:6],
        )
    )

    checks.append(
        _record(
            "key_alone",
            "Key works without cookies/session",
            "risk" if direct_with_key.get("status_code") == 200 else "ok",
            f"key-only request returned {direct_with_key.get('status_code')}",
            status_code=direct_with_key.get("status_code"),
        )
    )

    device_results: list[dict[str, Any]] = []
    for user_agent, forwarded_for in (
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "198.51.100.10"),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "198.51.100.25"),
        ("curl/7.88.1", "203.0.113.44"),
    ):
        result = _request(
            session,
            "GET",
            f"{base_url}users/me",
            headers={**auth_headers, "User-Agent": user_agent, "X-Forwarded-For": forwarded_for},
            params=auth_params,
            timeout=timeout,
        )
        device_results.append(
            {"user_agent": user_agent[:32], "status_code": result.get("status_code")}
        )
    checks.append(
        _record(
            "different_device",
            "Different IP/device restriction bypass",
            "info",
            "Executed simulated device and source-IP variations",
            simulations=device_results,
        )
    )

    id_results: list[dict[str, Any]] = []
    for test_id in ("1", "123", "456", "999999", "admin"):
        result = _request(
            session,
            "GET",
            f"{base_url}users/{test_id}",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
        )
        id_results.append(
            {
                "id": test_id,
                "status_code": result.get("status_code"),
                "body_length": result.get("body_length"),
            }
        )
    risky_ids = [item for item in id_results if item.get("status_code") == 200]
    checks.append(
        _record(
            "id_tampering",
            "Modified IDs expose other users' data",
            "risk" if risky_ids else "ok",
            f"{len(risky_ids)} tampered IDs returned 200",
            hits=risky_ids[:6],
        )
    )

    success_count = 0
    rate_limited = 0
    for _ in range(8):
        result = _request(
            session,
            "GET",
            f"{base_url}users/me",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
        )
        if result.get("status_code") == 200:
            success_count += 1
        if result.get("status_code") in {403, 429}:
            rate_limited += 1
            break
        time.sleep(0.1)
    checks.append(
        _record(
            "rate_limit_replay",
            "Replay multiple requests for rate-limit abuse",
            "risk" if success_count >= 8 and rate_limited == 0 else "ok",
            f"{success_count} successful rapid requests before block",
            success_count=success_count,
            rate_limited=rate_limited,
        )
    )

    subdomain_hits: list[dict[str, Any]] = []
    for url in _different_host_urls(base_url):
        result = _request(
            session,
            "GET",
            f"{url}users/me",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
        )
        if result.get("status_code") == 200:
            subdomain_hits.append({"url": url, "status_code": 200})
    checks.append(
        _record(
            "subdomain_scope",
            "Use key on different subdomains/services",
            "risk" if subdomain_hits else "ok",
            f"{len(subdomain_hits)} alternate subdomains accepted the key",
            hits=subdomain_hits[:6],
        )
    )

    privilege_hits: list[dict[str, Any]] = []
    for endpoint in ("admin", "admin/roles", "admin/promote", "account/upgrade"):
        result = _request(
            session,
            "GET",
            f"{base_url}{endpoint}",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
        )
        if result.get("status_code") == 200:
            privilege_hits.append({"endpoint": endpoint, "status_code": 200})
    checks.append(
        _record(
            "privilege_escalation",
            "Privilege escalation endpoints with key",
            "risk" if privilege_hits else "ok",
            f"{len(privilege_hits)} privilege endpoints returned 200",
            hits=privilege_hits[:6],
        )
    )

    method_hits: list[dict[str, Any]] = []
    for method in ("GET", "POST", "PUT"):
        result = _request(
            session,
            method,
            f"{base_url}orders",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
            json_body={"test": True},
        )
        method_hits.append({"method": method, "status_code": result.get("status_code")})
    risky_methods = [
        item
        for item in method_hits
        if item.get("status_code") in {200, 201, 204} and item.get("method") in {"POST", "PUT"}
    ]
    checks.append(
        _record(
            "http_methods",
            "Different HTTP methods with key",
            "risk" if risky_methods else "ok",
            f"{len(risky_methods)} write-capable methods succeeded",
            hits=risky_methods,
        )
    )

    comparisons: list[dict[str, Any]] = []
    for endpoint in ("users/me", "orders", "admin"):
        with_key = _request(
            session,
            "GET",
            f"{base_url}{endpoint}",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
        )
        no_key = _request(
            session, "GET", f"{base_url}{endpoint}", headers=no_auth_headers, timeout=timeout
        )
        comparisons.append(
            {
                "endpoint": endpoint,
                "with_key": with_key.get("status_code"),
                "without_key": no_key.get("status_code"),
                "difference": _compare(with_key, no_key),
            }
        )
    checks.append(
        _record(
            "present_vs_absent",
            "Response differences with key present vs absent",
            "info",
            "Compared status and size for representative endpoints",
            comparisons=comparisons,
        )
    )

    invalid_variants: dict[str, str] = {
        "invalid_literal": "invalid",
        "truncated": candidate["key_value"][: max(4, len(candidate["key_value"]) // 2)],
        "extended": f"{candidate['key_value']}expired",
    }
    invalid_hits: list[dict[str, Any]] = []
    for name, value in invalid_variants.items():
        invalid_placement = _placements({**candidate, "key_value": value})[0]
        invalid_headers: dict[str, str] = {**base_headers, **invalid_placement.get("headers", {})}
        invalid_params: dict[str, str] = invalid_placement.get("params", {})
        result = _request(
            session,
            "GET",
            f"{base_url}users/me",
            headers=invalid_headers,
            params=invalid_params,
            timeout=timeout,
        )
        invalid_hits.append({"variant": name, "status_code": result.get("status_code")})
    checks.append(
        _record(
            "invalid_key",
            "Expired/invalid key validation behavior",
            "info",
            "Executed invalid and malformed key variants",
            variants=invalid_hits,
        )
    )

    browser_result = _request(
        session,
        "GET",
        f"{base_url}users/me",
        headers={**auth_headers, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        params=auth_params,
        timeout=timeout,
    )
    curl_result = _request(
        session,
        "GET",
        f"{base_url}users/me",
        headers={**auth_headers, "User-Agent": "curl/7.88.1"},
        params=auth_params,
        timeout=timeout,
    )
    checks.append(
        _record(
            "browser_vs_curl",
            "Browser vs curl behavior",
            "info",
            f"browser {browser_result.get('status_code')} vs curl {curl_result.get('status_code')}",
            browser_status=browser_result.get("status_code"),
            curl_status=curl_result.get("status_code"),
        )
    )

    write_hits: list[dict[str, Any]] = []
    for method, endpoint, body in (
        ("POST", "orders", {"product": "test"}),
        ("PUT", "profile", {"bio": "test"}),
        ("DELETE", "orders/999", None),
    ):
        result = _request(
            session,
            method,
            f"{base_url}{endpoint}",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
            json_body=body,
        )
        if result.get("status_code") in {200, 201, 204}:
            write_hits.append(
                {"method": method, "endpoint": endpoint, "status_code": result.get("status_code")}
            )
    checks.append(
        _record(
            "write_actions",
            "Write actions with key",
            "risk" if write_hits else "ok",
            f"{len(write_hits)} write actions succeeded",
            hits=write_hits,
        )
    )

    placement_results: list[dict[str, Any]] = []
    for placement_option in _placements(candidate):
        current_headers: dict[str, str] = {**base_headers, **placement_option.get("headers", {})}
        current_params: dict[str, str] = placement_option.get("params", {})
        result = _request(
            session,
            "GET",
            f"{base_url}users/me",
            headers=current_headers,
            params=current_params,
            timeout=timeout,
        )
        placement_results.append(
            {"placement": placement_option["name"], "status_code": result.get("status_code")}
        )
    checks.append(
        _record(
            "placement_flexibility",
            "Header vs query parameter acceptance",
            "info",
            "Checked multiple header and query-key placements",
            placements=placement_results,
        )
    )

    chaining_results: list[dict[str, Any]] = []
    for extra_params in (
        {"user_id": "123"},
        {"user_id": "123", "token": candidate["key_value"]},
        {"user_id": "admin", "role": "admin"},
    ):
        result = _request(
            session,
            "GET",
            f"{base_url}users/me",
            headers=auth_headers,
            params={**auth_params, **extra_params},
            timeout=timeout,
        )
        chaining_results.append(
            {"params": ",".join(sorted(extra_params)), "status_code": result.get("status_code")}
        )
    checks.append(
        _record(
            "parameter_chaining",
            "Chaining with other params",
            "info",
            "Executed extra parameter combinations",
            results=chaining_results,
        )
    )

    risk_count = sum(1 for item in checks if item["outcome"] == "risk")
    totals: dict[str, Any] = {
        "checks_run": len(checks),
        "risk_count": risk_count,
        "ok_count": sum(1 for item in checks if item["outcome"] == "ok"),
        "info_count": sum(1 for item in checks if item["outcome"] == "info"),
    }
    return {
        "candidate": {
            "masked_key": candidate["masked_key"],
            "source_url": candidate["source_url"],
            "base_url": base_url,
            "source_type": candidate["source_type"],
            "provider": candidate["provider"],
            "placement": candidate["placement"],
        },
        "checks": checks,
        "totals": totals,
    }


def run_api_key_checklist(
    urls: list[str] | set[str],
    responses: list[dict[str, Any]],
    *,
    requests_module: Any = None,
    timeout: int = 10,
    candidate_limit: int = 6,
) -> dict[str, Any]:
    import requests as requests  # type: ignore[import-untyped]

    if requests_module is None:
        requests_module = requests

    candidates = discover_api_key_candidates(urls, responses, limit=candidate_limit)
    if not candidates:
        return {
            "status": "none",
            "candidates_tested": 0,
            "results": [],
        }

    session = requests_module.Session()
    try:
        results = [_run_candidate(session, candidate, timeout) for candidate in candidates]
        total_risk = sum(item["totals"]["risk_count"] for item in results)
        return {
            "status": "completed",
            "candidates_tested": len(results),
            "results": results,
            "risk_count": total_risk,
        }
    finally:
        session.close()
