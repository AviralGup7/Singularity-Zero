import logging
import time
from contextvars import ContextVar
from typing import Any
from urllib.parse import urlparse

from src.infrastructure.execution_engine.shared_pool import get_shared_executor

from .api_key_candidates import discover_api_key_candidates
from .api_key_workflows.scope import extract_registrable_domain
from .client import build_base_headers, normalize_base_url, safe_request, summarize_response

logger = logging.getLogger(__name__)

_probe_allowed_host: ContextVar[str] = ContextVar("api_key_probe_allowed_host", default="")
_probe_allow_write: ContextVar[bool] = ContextVar("api_key_probe_allow_write", default=False)


_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _host_of(url: str) -> str:
    return (urlparse(str(url or "")).netloc or "").lower()


def _without_secret(payload: Any, secret: str, masked: str) -> Any:
    """Replace raw secret material in structured checklist output."""
    if not secret:
        return payload
    if isinstance(payload, str):
        return payload.replace(secret, masked)
    if isinstance(payload, dict):
        return {
            key: _without_secret(value, secret, masked)
            for key, value in payload.items()
            if key != "key_value"
        }
    if isinstance(payload, list):
        return [_without_secret(item, secret, masked) for item in payload]
    return payload


def _bound_request_kwargs() -> dict[str, Any]:
    return {
        "allowed_host": _probe_allowed_host.get(),
        "allow_write": _probe_allow_write.get(),
    }


def _request(
    session: Any,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
    timeout: int = 10,
    json_body: dict[str, Any] | None = None,
    allowed_host: str = "",
    allow_write: bool = False,
) -> dict[str, object]:
    verb = str(method or "GET").upper()
    host_allow = allowed_host or _probe_allowed_host.get()
    write_ok = allow_write or _probe_allow_write.get()
    if verb in _WRITE_METHODS and not write_ok:
        return summarize_response(None, "write_probes_disabled", fallback_url=url)
    if host_allow and _host_of(url) != host_allow.lower():
        return summarize_response(None, "host_not_allowed", fallback_url=url)
    response, error = safe_request(
        session,
        verb,
        url,
        headers=headers,
        params=params,
        timeout=timeout,
        json_body=json_body,
        allow_redirects=True,
    )
    return summarize_response(response, error, fallback_url=url)


def _auth_differential(with_key: dict[str, object], without_key: dict[str, object]) -> bool:
    """True only when the key changes an unauthorized response into 200."""
    if not with_key.get("ok") or not without_key.get("ok"):
        return False
    return with_key.get("status_code") == 200 and without_key.get("status_code") in {401, 403}


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
    base_domain = extract_registrable_domain(base_url)
    if not base_domain or "." not in base_domain:
        return []
    return [
        f"{parsed.scheme}://{sub}.{base_domain}/"
        for sub in ("api", "app", "admin", "staging", "dev", "console")
    ]


def _check_direct_access(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    no_auth_headers: dict[str, str],
    no_auth_params: dict[str, str],
    timeout: int,
) -> tuple[dict[str, object], dict[str, object], dict[str, Any]]:
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
    record = _record(
        "direct_no_login",
        "Direct API request without login",
        "risk" if _auth_differential(direct_with_key, direct_without_key) else "ok",
        f"with key {direct_with_key.get('status_code')} vs no key {direct_without_key.get('status_code')}",
        compare=direct_compare,
    )
    return direct_with_key, direct_without_key, record


def _check_sensitive_endpoints(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    endpoints = ("users", "orders", "admin", "admin/users", "admin/dashboard")
    executor = get_shared_executor()
    bound = _bound_request_kwargs()
    futures = {
        executor.submit(
            _request,
            session,
            "GET",
            f"{base_url}{ep}",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
            **bound,
        ): ep
        for ep in endpoints
    }
    sensitive_hits = []
    for future in futures:
        ep = futures[future]
        try:
            result = future.result()
            sensitive_hits.append(
                {
                    "endpoint": ep,
                    "status_code": result.get("status_code"),
                    "body_length": result.get("body_length"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            sensitive_hits.append(
                {
                    "endpoint": ep,
                    "status_code": "error",
                    "body_length": 0,
                    "error": str(exc),
                }
            )
    return _record(
        "sensitive_endpoints",
        "Sensitive endpoints with key",
        "info",
        f"{len(sensitive_hits)} GET probes recorded; 200 alone is not treated as a finding",
        hits=sensitive_hits[:6],
    )


def _check_different_device(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    device_configs = (
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "198.51.100.10"),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "198.51.100.25"),
        ("curl/7.88.1", "203.0.113.44"),
    )
    device_results = []
    for user_agent, forwarded_for in device_configs:
        try:
            result = _request(
                session,
                "GET",
                f"{base_url}users/me",
                headers={
                    **auth_headers,
                    "User-Agent": user_agent,
                    "X-Forwarded-For": forwarded_for,
                },
                params=auth_params,
                timeout=timeout,
            )
            device_results.append(
                {"user_agent": user_agent[:32], "status_code": result.get("status_code")}
            )
        except Exception as exc:  # noqa: BLE001
            device_results.append(
                {"user_agent": user_agent[:32], "status_code": "error", "error": str(exc)}
            )
    return _record(
        "different_device",
        "Different IP/device restriction bypass",
        "info",
        "Executed simulated device and source-IP variations",
        simulations=device_results,
    )


def _check_id_tampering(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    test_ids = ("1", "123", "456", "999999", "admin")
    executor = get_shared_executor()
    bound = _bound_request_kwargs()
    futures = {
        executor.submit(
            _request,
            session,
            "GET",
            f"{base_url}users/{t_id}",
            headers=auth_headers,
            params=auth_params,
            timeout=timeout,
            **bound,
        ): t_id
        for t_id in test_ids
    }
    id_results = []
    for future in futures:
        t_id = futures[future]
        try:
            result = future.result()
            id_results.append(
                {
                    "id": t_id,
                    "status_code": result.get("status_code"),
                    "body_length": result.get("body_length"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            id_results.append(
                {
                    "id": t_id,
                    "status_code": "error",
                    "body_length": 0,
                    "error": str(exc),
                }
            )
    return _record(
        "id_tampering",
        "Modified IDs expose other users' data",
        "info",
        "GET probes of alternate IDs recorded; 200 alone is not treated as a finding",
        hits=id_results[:6],
    )


def _check_rate_limit_replay(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    success_count = 0
    rate_limited = 0
    for _ in range(8):
        try:
            result = _request(
                session,
                "GET",
                f"{base_url}users/me",
                headers=auth_headers,
                params=auth_params,
                timeout=timeout,
            )
            status = result.get("status_code")
            if status == 200:
                success_count += 1
            if status in {403, 429}:
                rate_limited += 1
                break
        except Exception:
            logger.warning("Suppressed exception", exc_info=True)
        time.sleep(0.1)
    return _record(
        "rate_limit_replay",
        "Replay multiple requests for rate-limit abuse",
        "info",
        f"{success_count} successful rapid requests before block",
        success_count=success_count,
        rate_limited=rate_limited,
    )


def _check_subdomain_scope(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    urls = _different_host_urls(base_url)
    subdomain_hits = []
    if urls:
        executor = get_shared_executor()
        bound = _bound_request_kwargs()
        futures = {
            executor.submit(
                _request,
                session,
                "GET",
                f"{u}users/me",
                headers=auth_headers,
                params=auth_params,
                timeout=timeout,
                **bound,
            ): u
            for u in urls
        }
        for future in futures:
            u = futures[future]
            try:
                result = future.result()
                if result.get("status_code") == 200:
                    subdomain_hits.append({"url": u, "status_code": 200})
            except Exception:
                logger.warning("Suppressed exception", exc_info=True)
    return _record(
        "subdomain_scope",
        "Use key on different subdomains/services",
        "info",
        f"{len(subdomain_hits)} alternate subdomains accepted the key",
        hits=subdomain_hits[:6],
    )


def _check_privilege_escalation(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    privilege_endpoints = ("admin", "admin/roles", "admin/promote", "account/upgrade")
    privilege_hits = []
    for endpoint in privilege_endpoints:
        try:
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
        except Exception:
            logger.warning("Suppressed exception", exc_info=True)
    return _record(
        "privilege_escalation",
        "Privilege escalation endpoints with key",
        "info",
        f"{len(privilege_hits)} privilege endpoints returned 200",
        hits=privilege_hits[:6],
    )


def _check_http_methods(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    method_hits = []
    for method in ("GET",):
        try:
            result = _request(
                session,
                method,
                f"{base_url}orders",
                headers=auth_headers,
                params=auth_params,
                timeout=timeout,
            )
            method_hits.append({"method": method, "status_code": result.get("status_code")})
        except Exception as exc:  # noqa: BLE001
            method_hits.append({"method": method, "status_code": "error", "error": str(exc)})
    return _record(
        "http_methods",
        "Read-only HTTP methods with key",
        "info",
        "GET-only method probe; write methods are opt-in",
        hits=method_hits,
    )


def _check_present_vs_absent(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    no_auth_headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    comparisons = []
    for endpoint in ("users/me", "orders", "admin"):
        try:
            with_key = _request(
                session,
                "GET",
                f"{base_url}{endpoint}",
                headers=auth_headers,
                params=auth_params,
                timeout=timeout,
            )
            no_key = _request(
                session,
                "GET",
                f"{base_url}{endpoint}",
                headers=no_auth_headers,
                timeout=timeout,
            )
            comparisons.append(
                {
                    "endpoint": endpoint,
                    "with_key": with_key.get("status_code"),
                    "without_key": no_key.get("status_code"),
                    "difference": _compare(with_key, no_key),
                }
            )
        except Exception as exc:  # noqa: BLE001
            comparisons.append(
                {
                    "endpoint": endpoint,
                    "with_key": "error",
                    "without_key": "error",
                    "difference": "error",
                    "error": str(exc),
                }
            )
    return _record(
        "present_vs_absent",
        "Response differences with key present vs absent",
        "info",
        "Compared status and size for representative endpoints",
        comparisons=comparisons,
    )


def _check_invalid_key(
    session: Any,
    base_url: str,
    candidate: dict[str, str],
    base_headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    key_val = candidate["key_value"]
    invalid_variants = {
        "invalid_literal": "invalid",
        "truncated": key_val[: max(4, len(key_val) // 2)],
        "extended": f"{key_val}expired",
    }
    invalid_hits = []
    for name, value in invalid_variants.items():
        try:
            candidate_var = dict(candidate)
            candidate_var["key_value"] = value
            invalid_placement = _placements(candidate_var)[0]
            invalid_headers = {**base_headers, **invalid_placement.get("headers", {})}
            invalid_params = invalid_placement.get("params", {})
            result = _request(
                session,
                "GET",
                f"{base_url}users/me",
                headers=invalid_headers,
                params=invalid_params,
                timeout=timeout,
            )
            invalid_hits.append({"variant": name, "status_code": result.get("status_code")})
        except Exception as exc:  # noqa: BLE001
            invalid_hits.append({"variant": name, "status_code": "error", "error": str(exc)})
    return _record(
        "invalid_key",
        "Expired/invalid key validation behavior",
        "info",
        "Executed invalid and malformed key variants",
        variants=invalid_hits,
    )


def _check_browser_vs_curl(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    try:
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
        return _record(
            "browser_vs_curl",
            "Browser vs curl behavior",
            "info",
            f"browser {browser_result.get('status_code')} vs curl {curl_result.get('status_code')}",
            browser_status=browser_result.get("status_code"),
            curl_status=curl_result.get("status_code"),
        )
    except Exception as exc:  # noqa: BLE001
        return _record(
            "browser_vs_curl",
            "Browser vs curl behavior",
            "info",
            "error",
            error=str(exc),
        )


def _check_write_actions(
    session: Any,
    base_url: str,
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    write_hits = []
    write_configs = (
        ("POST", "orders", {"product": "test"}),
        ("PUT", "profile", {"bio": "test"}),
        ("DELETE", "orders/999", None),
    )
    for method, endpoint, body in write_configs:
        try:
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
                    {
                        "method": method,
                        "endpoint": endpoint,
                        "status_code": result.get("status_code"),
                    }
                )
        except Exception:
            logger.warning("Suppressed exception", exc_info=True)
    return _record(
        "write_actions",
        "Write actions with key",
        "risk" if write_hits else "ok",
        f"{len(write_hits)} write actions succeeded",
        hits=write_hits,
    )


def _check_placement_flexibility(
    session: Any,
    base_url: str,
    candidate: dict[str, str],
    base_headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    placement_results = []
    for placement_option in _placements(candidate):
        try:
            current_headers = {**base_headers, **placement_option.get("headers", {})}
            current_params = placement_option.get("params", {})
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
        except Exception as exc:  # noqa: BLE001
            placement_results.append(
                {"placement": placement_option["name"], "status_code": "error", "error": str(exc)}
            )
    return _record(
        "placement_flexibility",
        "Header vs query parameter acceptance",
        "info",
        "Checked multiple header and query-key placements",
        placements=placement_results,
    )


def _check_parameter_chaining(
    session: Any,
    base_url: str,
    candidate: dict[str, str],
    auth_headers: dict[str, str],
    auth_params: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    chaining_results = []
    chaining_configs = (
        {"user_id": "123"},
        {"user_id": "123", "token": candidate["key_value"]},
        {"user_id": "admin", "role": "admin"},
    )
    for extra_params in chaining_configs:
        try:
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
        except Exception as exc:  # noqa: BLE001
            chaining_results.append(
                {
                    "params": ",".join(sorted(extra_params)),
                    "status_code": "error",
                    "error": str(exc),
                }
            )
    return _record(
        "parameter_chaining",
        "Chaining with other params",
        "info",
        "Executed extra parameter combinations",
        results=chaining_results,
    )


def _run_candidate(
    session: Any,
    candidate: dict[str, str],
    timeout: int,
    *,
    allow_write_probes: bool = False,
) -> dict[str, Any]:
    candidate_copy = dict(candidate)
    base_url = normalize_base_url(candidate_copy.get("base_url", ""))
    allowed_host = _host_of(base_url)
    host_token = _probe_allowed_host.set(allowed_host)
    write_token = _probe_allow_write.set(bool(allow_write_probes))
    try:
        return _run_candidate_checks(
            session,
            candidate_copy,
            base_url,
            timeout,
            allow_write_probes=allow_write_probes,
        )
    finally:
        _probe_allowed_host.reset(host_token)
        _probe_allow_write.reset(write_token)


def _run_candidate_checks(
    session: Any,
    candidate_copy: dict[str, str],
    base_url: str,
    timeout: int,
    *,
    allow_write_probes: bool,
) -> dict[str, Any]:
    base_hdrs = _base_headers("Mozilla/5.0 (Codex API Key Validation)")
    placement = _placements(candidate_copy)[0]
    auth_headers: dict[str, str] = {**base_hdrs, **placement.get("headers", {})}
    auth_params: dict[str, str] = placement.get("params", {})
    no_auth_headers = dict(base_hdrs)
    no_auth_params: dict[str, str] = {}
    checks: list[dict[str, Any]] = []

    # 1. Direct Access Check
    direct_with_key, direct_without_key, direct_record = _check_direct_access(
        session, base_url, auth_headers, auth_params, no_auth_headers, no_auth_params, timeout
    )
    checks.append(direct_record)

    # 2. Sensitive Endpoints Check
    checks.append(_check_sensitive_endpoints(session, base_url, auth_headers, auth_params, timeout))

    # 3. Key Alone Check — same evidence bar as direct access
    checks.append(
        _record(
            "key_alone",
            "Key works without cookies/session",
            "risk" if _auth_differential(direct_with_key, direct_without_key) else "ok",
            f"key-only request returned {direct_with_key.get('status_code')}",
            status_code=direct_with_key.get("status_code"),
        )
    )

    # 4. Different Device Check
    checks.append(_check_different_device(session, base_url, auth_headers, auth_params, timeout))

    # 5. ID Tampering Check
    checks.append(_check_id_tampering(session, base_url, auth_headers, auth_params, timeout))

    # 6. Rate Limit Replay Check
    checks.append(_check_rate_limit_replay(session, base_url, auth_headers, auth_params, timeout))

    # 7. Subdomain Scope Check — quarantined: other hosts are out of default scope
    checks.append(
        _record(
            "subdomain_scope",
            "Use key on different subdomains/services",
            "info",
            "Skipped: default checklist stays on the candidate source host",
            hits=[],
        )
    )

    # 8. Privilege Escalation Check
    checks.append(
        _check_privilege_escalation(session, base_url, auth_headers, auth_params, timeout)
    )

    # 9. HTTP Methods Check
    checks.append(_check_http_methods(session, base_url, auth_headers, auth_params, timeout))

    # 10. Present vs Absent Check
    checks.append(
        _check_present_vs_absent(
            session, base_url, auth_headers, auth_params, no_auth_headers, timeout
        )
    )

    # 11. Invalid Key Check
    checks.append(_check_invalid_key(session, base_url, candidate_copy, base_hdrs, timeout))

    # 12. Browser vs Curl Check
    checks.append(_check_browser_vs_curl(session, base_url, auth_headers, auth_params, timeout))

    # 13. Write Actions Check — opt-in only
    if allow_write_probes:
        checks.append(_check_write_actions(session, base_url, auth_headers, auth_params, timeout))
    else:
        checks.append(
            _record(
                "write_actions",
                "Write actions with key",
                "info",
                "Skipped: write probes require api_key_allow_write_probes=true",
                hits=[],
            )
        )

    # 14. Placement Flexibility Check
    checks.append(
        _check_placement_flexibility(session, base_url, candidate_copy, base_hdrs, timeout)
    )

    # 15. Parameter Chaining Check
    checks.append(
        _check_parameter_chaining(
            session, base_url, candidate_copy, auth_headers, auth_params, timeout
        )
    )

    risk_count = sum(1 for item in checks if item["outcome"] == "risk")
    totals: dict[str, Any] = {
        "checks_run": len(checks),
        "risk_count": risk_count,
        "ok_count": sum(1 for item in checks if item["outcome"] == "ok"),
        "info_count": sum(1 for item in checks if item["outcome"] == "info"),
    }
    payload = {
        "candidate": {
            "masked_key": candidate_copy["masked_key"],
            "source_url": candidate_copy["source_url"],
            "base_url": base_url,
            "source_type": candidate_copy["source_type"],
            "provider": candidate_copy["provider"],
            "placement": candidate_copy["placement"],
        },
        "checks": checks,
        "totals": totals,
    }
    return _without_secret(
        payload,
        candidate_copy.get("key_value", ""),
        candidate_copy.get("masked_key", "***"),
    )


def run_api_key_checklist(
    urls: list[str] | set[str],
    responses: list[dict[str, Any]],
    *,
    requests_module: Any = None,
    timeout: int = 10,
    candidate_limit: int = 6,
    allow_write_probes: bool = False,
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
        results = [
            _run_candidate(
                session,
                candidate,
                timeout,
                allow_write_probes=allow_write_probes,
            )
            for candidate in candidates
        ]
        total_risk = sum(item["totals"]["risk_count"] for item in results)
        return {
            "status": "completed",
            "candidates_tested": len(results),
            "results": results,
            "risk_count": total_risk,
        }
    finally:
        session.close()
