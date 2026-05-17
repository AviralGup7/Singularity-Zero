"""Helper functions for cache deception probing."""

import json
from typing import Any
from urllib.parse import urlparse

import requests

from src.analysis.helpers import (
    build_endpoint_meta,
    is_auth_flow_endpoint,
    normalize_headers,
)
from src.core.utils.url_validation import is_safe_url

from ._constants import (
    AUTH_HEADER_KEYS,
    NO_CACHE_INDICATORS,
    PATH_TRAVERSAL_VARIANTS,
    PUBLIC_CACHE_INDICATORS,
    SENSITIVE_PATH_HINTS,
    STATIC_EXTENSIONS,
    USER_AGENT,
)


def is_sensitive_endpoint(url: str, response: dict[str, Any] | None = None) -> bool:
    """Check if a URL is likely to return user-specific or sensitive content."""
    path = urlparse(url).path.lower()
    if any(hint in path for hint in SENSITIVE_PATH_HINTS):
        return True
    if is_auth_flow_endpoint(url):
        return True
    if response:
        headers = normalize_headers(response)
        if any(k in headers for k in AUTH_HEADER_KEYS):
            return True
        body = response.get("body_text") or response.get("body") or ""
        if body:
            sensitive_tokens = {
                "email",
                "username",
                "user_id",
                "userid",
                "account_id",
                "accountid",
                "phone",
                "address",
                "password",
                "token",
                "session",
                "balance",
                "order",
                "subscription",
                "profile",
                "name",
                "avatar",
            }
            if body.strip().startswith(("{", "[")):
                try:
                    data = json.loads(body[:50000])
                    if isinstance(data, dict):
                        keys = {k.lower() for k in data.keys()}
                        if keys & sensitive_tokens:
                            return True
                    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                        keys = {k.lower() for k in data[0].keys()}
                        if keys & sensitive_tokens:
                            return True
                except json.JSONDecodeError, ValueError:
                    pass
    return False


def safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Make a safe HTTP request and return response info."""
    req_headers = dict(headers or {})
    req_headers.setdefault("User-Agent", USER_AGENT)
    req_headers.setdefault("Accept", "*/*")
    if not is_safe_url(url):
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": "URL failed safety check",
        }
    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": resp_body[:5000],
            "body_length": len(resp_body),
            "success": resp.status_code < 400,
        }
    except requests.RequestException as e:
        resp_body = ""
        resp_obj = getattr(e, "response", None)
        status = 0
        headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                headers = dict(resp_obj.headers)
            except Exception:  # noqa: S110
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:5000],
            "body_length": len(resp_body or ""),
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": str(e),
        }


def build_static_extension_urls(base_url: str) -> list[str]:
    """Generate URL variants with static file extensions appended."""
    urls = []
    parsed = urlparse(base_url)
    path = parsed.path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    base = f"{parsed.scheme}://{parsed.netloc}{path}"
    for ext in STATIC_EXTENSIONS:
        urls.append(f"{base}{ext}{query}{fragment}")
    return urls


def build_path_traversal_urls(base_url: str) -> list[str]:
    """Generate URL variants with path normalization tricks."""
    urls = []
    parsed = urlparse(base_url)
    path = parsed.path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    base = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = path.rstrip("/").split("/")
    if len(path_parts) >= 2:
        resource_path = "/".join(path_parts[:-1])
        resource_name = path_parts[-1]
        for variant in PATH_TRAVERSAL_VARIANTS:
            urls.append(f"{base}{resource_path}{variant}{resource_name}{query}{fragment}")
        for variant in PATH_TRAVERSAL_VARIANTS[:4]:
            urls.append(f"{base}{resource_path}{variant}{query}{fragment}")
    urls.append(f"{base}/static{path}{query}{fragment}")
    urls.append(f"{base}/assets{path}{query}{fragment}")
    urls.append(f"{base}/public{path}{query}{fragment}")
    deeper_path = path.rstrip("/")
    for ext in STATIC_EXTENSIONS[:6]:
        urls.append(f"{base}{deeper_path}{ext}{query}{fragment}")
    return urls


def has_cacheable_response(headers: dict[str, str]) -> tuple[bool, list[str]]:
    """Check if response headers indicate cacheable content."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    cache_signals = []
    is_cacheable = False
    cache_control = headers_lower.get("cache-control", "")
    etag = headers_lower.get("etag", "")
    last_modified = headers_lower.get("last-modified", "")
    expires = headers_lower.get("expires", "")
    cf_cache = headers_lower.get("cf-cache-status", "")
    x_cache = headers_lower.get("x-cache", "")
    via = headers_lower.get("via", "")
    has_proxy_header = bool(via) or bool(cf_cache) or bool(x_cache)
    if has_proxy_header:
        cache_signals.append("proxy_cache_header_detected")
        is_cacheable = True
    if cache_control:
        cc_lower = cache_control.lower()
        has_public = any(token in cc_lower for token in PUBLIC_CACHE_INDICATORS)
        has_no_cache = any(token in cc_lower for token in NO_CACHE_INDICATORS)
        if has_public and not has_no_cache:
            cache_signals.append("cache_control_public")
            is_cacheable = True
        elif has_public and has_no_cache:
            cache_signals.append("cache_control_mixed")
        elif not has_no_cache:
            cache_signals.append("cache_control_no_prevention")
    if etag:
        cache_signals.append("etag_present")
    if last_modified:
        cache_signals.append("last_modified_present")
    if expires:
        cache_signals.append("expires_present")
    if cf_cache and cf_cache.lower() in ("hit", "dynamic", "miss"):
        cache_signals.append(f"cf_cache_status:{cf_cache}")
        if cf_cache.lower() == "hit":
            is_cacheable = True
    if x_cache and x_cache.lower() in ("hit", "from cache"):
        cache_signals.append(f"x_cache:{x_cache}")
        is_cacheable = True
    if not cache_signals:
        cache_signals.append("no_cache_indicators")
    return is_cacheable, cache_signals


def response_contains_sensitive_data(body: str) -> tuple[bool, list[str]]:
    """Check if response body appears to contain user-specific data."""
    if not body:
        return False, []
    signals = []
    body_lower = body[:10000].lower()
    sensitive_patterns = {
        "email": ["@", "email", "e-mail", "mail"],
        "user_id": ["user_id", "userid", "user-id", "uid"],
        "account": ["account", "account_id", "accountid"],
        "token": ["token", "access_token", "jwt", "bearer"],
        "session": ["session", "session_id", "sid", "phpsessid"],
        "profile": ["profile", "avatar", "display_name", "username"],
        "personal": ["first_name", "last_name", "phone", "address", "dob"],
        "financial": ["balance", "credit", "payment", "billing", "order"],
        "auth": ["authenticated", "is_logged_in", "logged_in", "auth"],
    }
    found_categories = []
    for category, tokens in sensitive_patterns.items():
        if any(token in body_lower for token in tokens):
            found_categories.append(category)
            signals.append(f"sensitive_data:{category}")
    if body.strip().startswith(("{", "[")):
        try:
            data = json.loads(body[:50000])
            if isinstance(data, dict):
                keys_lower = {k.lower() for k in data.keys()}
                json_sensitive = keys_lower & {
                    "email",
                    "user_id",
                    "userid",
                    "account_id",
                    "token",
                    "session",
                    "password",
                    "phone",
                    "address",
                    "balance",
                    "authorization",
                    "access_token",
                    "refresh_token",
                }
                if json_sensitive:
                    signals.append(f"json_sensitive_keys:{','.join(sorted(json_sensitive)[:5])}")
            elif isinstance(data, list):
                for item in data[:5]:
                    if isinstance(item, dict):
                        keys_lower = {k.lower() for k in item.keys()}
                        json_sensitive = keys_lower & {
                            "email",
                            "user_id",
                            "userid",
                            "account_id",
                            "token",
                            "session",
                            "password",
                            "phone",
                            "address",
                            "balance",
                        }
                        if json_sensitive:
                            signals.append(
                                f"json_array_sensitive_keys:{','.join(sorted(json_sensitive)[:5])}"
                            )
                            break
        except json.JSONDecodeError, ValueError:
            pass
    has_sensitive = len(found_categories) >= 1 or any("json_sensitive" in s for s in signals)
    return has_sensitive, signals


def build_finding(
    url: str,
    status_code: int | None,
    category: str,
    title: str,
    severity: str,
    confidence: float,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
) -> dict[str, Any]:
    """Build a standardized finding dictionary."""
    meta = build_endpoint_meta(url)
    score_map = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}
    score = score_map.get(severity, 20)
    return {
        "url": url,
        "endpoint_key": meta["endpoint_key"],
        "endpoint_base_key": meta["endpoint_base_key"],
        "endpoint_type": meta["endpoint_type"],
        "status_code": status_code,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": round(confidence, 2),
        "score": score,
        "signals": sorted(set(signals)),
        "evidence": evidence,
        "explanation": explanation,
    }
