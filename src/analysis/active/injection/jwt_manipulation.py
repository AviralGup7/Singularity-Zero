"""JWT manipulation active probe."""

import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Any, cast

import requests

from src.core.utils.url_validation import is_safe_url

logger = logging.getLogger(__name__)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

JWT_AUTH_HEADERS = [
    "Authorization",
    "X-Access-Token",
    "X-Auth-Token",
    "X-JWT-Token",
    "X-Api-Token",
]

JWT_PARAM_NAMES = {
    "token",
    "access_token",
    "jwt",
    "auth_token",
    "bearer",
    "api_token",
    "id_token",
    "refresh_token",
}


def _safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    req_headers = dict(headers or {})
    req_headers.setdefault(
        "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"
    )
    req_headers.setdefault("Accept", "application/json, text/html, */*")
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
        from src.core.utils.shared_sessions import get_shared_sync_session

        resp = get_shared_sync_session().request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": resp_body[:8000],
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
            except Exception:
                logger.warning("Operation failed in jwt_manipulation.py", exc_info=True)
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:8000],
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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _decode_jwt_part(part: str) -> dict | Any | None:
    try:
        decoded = _b64url_decode(part)
        return json.loads(decoded)
    except Exception:
        logger.debug("jwt_manipulation: failed to decode JWT part %r", part[:16])
        return None


def _create_jwt(header: dict, payload: dict, secret: bytes = b"secret") -> str:
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _create_none_alg_jwt(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def _extract_jwts_from_response(response: dict[str, Any]) -> list[str]:
    tokens = []
    body = str(response.get("body_text") or response.get("body") or "")
    for match in JWT_RE.finditer(body):
        token = match.group(0)
        if token not in tokens:
            tokens.append(token)
    headers = response.get("headers", {})
    for key, val in headers.items():
        if isinstance(val, str) and "eyJ" in val:
            for match in JWT_RE.finditer(val):
                token = match.group(0)
                if token not in tokens:
                    tokens.append(token)
    return tokens


def _extract_jwt_from_headers(headers: dict[str, Any]) -> str | None:
    for header_name in JWT_AUTH_HEADERS:
        val = headers.get(header_name) or headers.get(header_name.lower())
        if val and isinstance(val, str):
            if val.startswith("Bearer "):
                val = val[7:]
            if JWT_RE.match(val):
                return cast(str, val)
    return None


def jwt_manipulation_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for JWT manipulation vulnerabilities via canonical analyzer."""
    from src.analysis.checks.active.jwt import jwt_security_analyzer

    return jwt_security_analyzer(priority_urls, response_cache, limit=limit)

