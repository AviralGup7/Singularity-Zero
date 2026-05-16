"""Shared utilities for JWT attack modules."""

import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Any, cast

import requests

logger = logging.getLogger(__name__)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

JWT_AUTH_HEADERS = [
    "Authorization",
    "X-Access-Token",
    "X-Auth-Token",
    "X-JWT-Token",
    "X-Api-Token",
]

WEAK_SECRETS = [
    b"secret",
    b"password",
    b"123456",
    b"key",
    b"jwt_secret",
    b"jwt-secret",
    b"supersecret",
    b"changeme",
    b"test",
    b"admin",
    b"token",
    b"jwt",
    b"mysecret",
    b"my_secret",
    b"private",
    b"access",
    b"auth",
    b"signing",
    b"signing_key",
    b"signing-key",
    b"-----BEGIN PUBLIC KEY-----\n",
]


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
        return None


def _create_jwt(header: dict, payload: dict, secret: bytes = b"secret") -> str:
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


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
    try:
        resp = requests.request(
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
            except Exception:  # noqa: S110
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:8000],
            "body_length": len(resp_body or ""),
            "success": False,
            "error": str(e),
        }
    return {
        "status": 0,
        "headers": {},
        "body": "",
        "body_length": 0,
        "success": False,
        "error": "unknown error",
    }

def _extract_jwt(url: str, session: Any) -> str | None:
    for header_name in JWT_AUTH_HEADERS:
        if hasattr(session, "headers") and header_name in session.headers:
            val = session.headers[header_name]
            if isinstance(val, str) and val.startswith("Bearer "):
                val = val[7:]
            match = JWT_RE.match(val)
            if match:
                return cast(str, val)
    return None


def _get_original_status(url: str, session: Any) -> int:
    try:
        if hasattr(session, "get"):
            resp = session.get(url, timeout=8, verify=True)
            return cast(int, resp.status_code)
        return cast(int, _safe_request(url, timeout=8).get("status", 0))
    except Exception:
        return 0


def _send_with_token(url: str, token: str, auth_header: str, session: Any) -> dict[str, Any]:
    try:
        if hasattr(session, "request"):
            resp = session.request(
                "GET",
                url,
                headers={auth_header: f"Bearer {token}"},
                timeout=10,
                verify=True,
            )
            return {
                "status": resp.status_code,
                "body": resp.text[:8000],
                "headers": dict(resp.headers),
                "success": resp.status_code < 400,
            }
        headers = {auth_header: f"Bearer {token}"}
        return _safe_request(url, headers=headers, timeout=10)
    except Exception as e:
        logger.debug("JWT request failed: %s", e)
        return {"status": 0, "body": "", "headers": {}, "success": False, "error": str(e)}
