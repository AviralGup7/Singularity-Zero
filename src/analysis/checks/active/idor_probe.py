"""IDOR (Insecure Direct Object Reference) active probe."""

import json
import re
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers.scoring import normalized_confidence
from src.analysis.passive.runtime import ResponseCache
from src.core.utils.url_validation import is_safe_url
from src.recon.common import normalize_url

IDOR_NUMERIC_RE = re.compile(r"/(\d+)(?:/|$|\?)")
IDOR_UUID_RE = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE
)
IDOR_PARAM_ID_RE = re.compile(
    r"(?i)(?:^|&|\?)(id|user_id|account_id|org_id|profile_id|item_id|order_id|doc_id|file_id|message_id|post_id|comment_id|group_id|project_id|task_id|ticket_id|invoice_id|payment_id|transaction_id|customer_id|client_id|product_id|resource_id|entity_id|record_id)=([^&]*)"
)

IDOR_PARAM_NAMES = {
    "id",
    "user_id",
    "account_id",
    "org_id",
    "profile_id",
    "item_id",
    "order_id",
    "doc_id",
    "file_id",
    "message_id",
    "post_id",
    "comment_id",
    "group_id",
    "project_id",
    "task_id",
    "ticket_id",
    "invoice_id",
    "payment_id",
    "transaction_id",
    "customer_id",
    "client_id",
    "product_id",
    "resource_id",
    "entity_id",
    "record_id",
    "owner_id",
    "author_id",
    "parent_id",
    "ref_id",
    "target_id",
    "object_id",
}

SENSITIVE_PATH_HINTS = {
    "/user",
    "/profile",
    "/account",
    "/admin",
    "/settings",
    "/order",
    "/invoice",
    "/payment",
    "/billing",
    "/document",
    "/file",
    "/attachment",
    "/download",
    "/message",
    "/notification",
    "/activity",
    "/project",
    "/task",
    "/ticket",
    "/issue",
    "/api/user",
    "/api/profile",
    "/api/account",
    "/api/order",
    "/api/payment",
    "/api/document",
    "/api/message",
    "/api/notification",
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
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": str(e),
        }


def _is_sensitive_endpoint(url: str) -> bool:
    lowered = url.lower()
    return any(hint in lowered for hint in SENSITIVE_PATH_HINTS)


def _extract_json_data(body: str) -> dict[str, Any] | list[Any] | None:
    stripped = body.strip()
    if stripped.startswith(("{", "[")):
        try:
            return cast(dict[str, Any] | list[Any] | None, json.loads(stripped[:50000]))
        except json.JSONDecodeError, ValueError:
            pass
    return None
    return None


def _check_data_exposure(
    original_body: str, mutated_body: str, original_data: Any, mutated_data: Any
) -> list[str]:
    signals: list[str] = []
    if original_body == mutated_body:
        return signals

    original_data = original_data or _extract_json_data(original_body)
    mutated_data = mutated_data or _extract_json_data(mutated_body)

    if isinstance(original_data, dict) and isinstance(mutated_data, dict):
        original_keys = set(original_data.keys())
        mutated_keys = set(mutated_data.keys())
        if original_keys != mutated_keys:
            new_keys = mutated_keys - original_keys
            if new_keys:
                signals.append(f"idor_different_keys:{','.join(sorted(new_keys)[:5])}")
            removed_keys = original_keys - mutated_keys
            if removed_keys:
                signals.append(f"idor_missing_keys:{','.join(sorted(removed_keys)[:5])}")

        for key in original_keys & mutated_keys:
            orig_val = original_data[key]
            mut_val = mutated_data[key]
            if orig_val != mut_val and isinstance(orig_val, str) and isinstance(mut_val, str):
                if "user" in key.lower() or "email" in key.lower() or "name" in key.lower():
                    signals.append(f"idor_field_changed:{key}")

    if len(mutated_body) > 0:
        length_diff = abs(len(mutated_body) - len(original_body))
        if original_body and length_diff / len(original_body) > 0.2:
            signals.append(f"idor_body_length_diff:{length_diff}")

    return signals


def _build_finding(
    url: str,
    severity: str,
    title: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    score_map = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "status_code": status_code,
        "category": "idor",
        "title": title,
        "severity": severity,
        "confidence": 0.75
        if severity in ("critical", "high")
        else 0.6
        if severity == "medium"
        else 0.45,
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": score_map.get(severity, 20),
    }


def idor_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Test endpoints for Insecure Direct Object Reference vulnerabilities.

    Tests numeric ID manipulation, UUID substitution, cross-user resource access,
    nested resource IDOR, and HTTP method-based IDOR.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of IDOR findings.
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
        original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")
        original_headers = original_resp.get("headers", {})
        original_data = _extract_json_data(original_body)

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        {k.lower() for k, _ in query_pairs}

        idor_targets: list[tuple[str, str, str]] = []

        for match in IDOR_NUMERIC_RE.finditer(parsed.path):
            original_id = match.group(1)
            start = match.start(1)
            end = match.end(1)
            idor_targets.append(
                ("path_numeric", original_id, f"{parsed.path[:start]}{{id}}{parsed.path[end:]}")
            )

        for match in IDOR_UUID_RE.finditer(parsed.path):
            original_id = match.group(1)
            start = match.start(1)
            end = match.end(1)
            idor_targets.append(
                ("path_uuid", original_id, f"{parsed.path[:start]}{{id}}{parsed.path[end:]}")
            )

        for param_name, param_value in query_pairs:
            if param_name.lower() in IDOR_PARAM_NAMES:
                idor_targets.append(("param", param_value, param_name))

        if not idor_targets:
            continue

        is_sensitive = _is_sensitive_endpoint(url)
        url_signals: list[str] = []
        url_evidence: list[dict[str, Any]] = []

        for target_type, original_id, target_info in idor_targets:
            if len(url_evidence) >= 5:
                break

            if target_type == "path_numeric":
                try:
                    numeric_id = int(original_id)
                except ValueError:
                    continue
                test_ids = [
                    str(numeric_id + 1),
                    str(numeric_id - 1) if numeric_id > 1 else str(numeric_id + 2),
                    str(numeric_id + 10),
                    "1",
                    "0",
                    "999999",
                    "-1",
                ]
            elif target_type == "path_uuid":
                test_ids = [
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",
                    "12345678-1234-1234-1234-123456789012",
                ]
            else:
                test_ids = [
                    "1",
                    "2",
                    "0",
                    "999999",
                    "-1",
                    "admin",
                    "root",
                    "test",
                    "00000000-0000-0000-0000-000000000001",
                ]

            for test_id in test_ids:
                if target_type == "param":
                    updated_pairs = [
                        (k, test_id if k == target_info else v) for k, v in query_pairs
                    ]
                    test_url = normalize_url(
                        urlunparse(parsed._replace(query=urlencode(updated_pairs, doseq=True)))
                    )
                else:
                    test_path = target_info.replace("{id}", test_id)
                    test_url = normalize_url(urlunparse(parsed._replace(path=test_path)))

                test_headers = {
                    "Cache-Control": "no-cache",
                    "X-IDOR-Probe": "1",
                }
                for k, v in original_headers.items():
                    if k.lower() in ("authorization", "cookie", "x-csrf-token"):
                        test_headers[k] = v

                response = _safe_request(test_url, headers=test_headers, timeout=10)
                if not response:
                    continue

                status = response.get("status", 0)
                body = str(response.get("body") or "")

                if status == 200 and original_status in (200, 201):
                    signals = _check_data_exposure(
                        original_body, body, original_data, _extract_json_data(body)
                    )
                    if signals:
                        url_signals.extend(signals)
                        url_evidence.append(
                            {
                                "target_type": target_type,
                                "target_info": target_info,
                                "original_id": original_id,
                                "test_id": test_id,
                                "status_code": status,
                                "signals": signals,
                            }
                        )
                        break
                elif status == 200 and original_status in (401, 403):
                    url_signals.append("idor_auth_bypass")
                    url_evidence.append(
                        {
                            "target_type": target_type,
                            "target_info": target_info,
                            "original_id": original_id,
                            "test_id": test_id,
                            "status_code": status,
                            "original_status": original_status,
                            "signals": ["idor_auth_bypass"],
                        }
                    )
                    break

        for method in ["PUT", "DELETE", "PATCH"]:
            if len(url_evidence) >= 5:
                break
            if target_type == "path_numeric":
                try:
                    numeric_id = int(original_id)
                except ValueError:
                    continue
                test_id = str(numeric_id + 1)
                test_path = target_info.replace("{id}", test_id)
                test_url = normalize_url(urlunparse(parsed._replace(path=test_path)))
            elif target_type == "param":
                test_id = "999999"
                updated_pairs = [(k, test_id if k == target_info else v) for k, v in query_pairs]
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated_pairs, doseq=True)))
                )
            else:
                continue

            test_headers = {
                "Content-Type": "application/json",
            }
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie"):
                    test_headers[k] = v

            body_bytes = json.dumps({"test": "idor_probe"}).encode()
            response = _safe_request(
                test_url, method=method, headers=test_headers, body=body_bytes, timeout=10
            )
            if response:
                status = response.get("status", 0)
                if status in (200, 204) and original_status in (401, 403):
                    url_signals.append(f"idor_method_{method.lower()}_bypass")
                    url_evidence.append(
                        {
                            "target_type": target_type,
                            "method": method,
                            "test_id": test_id,
                            "status_code": status,
                            "signals": [f"idor_method_{method.lower()}_bypass"],
                        }
                    )

        if url_evidence:
            severity = "high" if is_sensitive else "medium"
            if "idor_auth_bypass" in url_signals:
                severity = "critical" if is_sensitive else "high"

            title = (
                f"IDOR: potential unauthorized access to resource via {target_type} manipulation"
            )
            if is_sensitive:
                title = "IDOR: sensitive resource accessed via ID manipulation"
            if "idor_auth_bypass" in url_signals:
                title = "IDOR: authentication bypass via resource ID manipulation"

            normalized_confidence(
                base=0.70 if severity == "high" else 0.55 if severity == "medium" else 0.85,
                score=8 if severity == "high" else 5,
                signals=url_signals,
            )

            explanation = (
                f"Endpoint '{url}' appears vulnerable to IDOR. "
                f"Tested {len(url_evidence)} ID manipulation(s) with "
                f"signals: {', '.join(sorted(set(url_signals)))}. "
                f"{'This is a sensitive endpoint.' if is_sensitive else ''}"
            )

            findings.append(
                _build_finding(
                    url=url,
                    severity=severity,
                    title=title,
                    signals=sorted(set(url_signals)),
                    evidence={"tests": url_evidence[:10], "total_tests": len(url_evidence)},
                    explanation=explanation,
                    status_code=original_status if original_status else None,
                )
            )

    findings.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5),
            -f["confidence"],
            f["url"],
        )
    )
    return findings[:limit]
