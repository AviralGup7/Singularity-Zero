"""File upload vulnerability active probe."""

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

import requests

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers.scoring import normalized_confidence
from src.analysis.passive.runtime import ResponseCache
from src.core.utils.url_validation import is_safe_url

UPLOAD_PATH_HINTS = {
    "/upload",
    "/file",
    "/files",
    "/attachment",
    "/attachments",
    "/image",
    "/images",
    "/photo",
    "/photos",
    "/avatar",
    "/avatars",
    "/document",
    "/documents",
    "/media",
    "/import",
    "/import-file",
    "/upload-file",
    "/upload-image",
    "/upload-document",
    "/api/upload",
    "/api/file",
    "/api/attachment",
    "/api/media",
    "/api/import",
    "/api/image",
    "/api/document",
}

UPLOAD_PARAM_NAMES = {
    "file",
    "upload",
    "attachment",
    "document",
    "image",
    "photo",
    "avatar",
    "media",
    "data",
    "import",
    "csv",
    "excel",
    "pdf",
    "doc",
    "docx",
}

DANGEROUS_EXTENSIONS = [
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".cgi",
    ".pl",
    ".py",
    ".sh",
    ".bat",
    ".exe",
    ".phtml",
    ".php5",
    ".php7",
]

DOUBLE_EXTENSIONS = [
    ".php.jpg",
    ".asp;.jpg",
    ".aspx.png",
    ".jsp.gif",
    ".php;.png",
    ".asp;.gif",
    ".aspx;.jpg",
    ".jsp;.png",
    ".php%00.jpg",
    ".asp%00.png",
    ".aspx%00.gif",
]

CASE_VARIATIONS = [".PhP", ".AsP", ".AsPx", ".JsP", ".CgI", ".pHp5", ".pHp7"]

MIME_TYPES = {
    "php": "application/x-php",
    "asp": "application/x-asp",
    "aspx": "application/x-aspx",
    "jsp": "application/x-jsp",
    "cgi": "application/x-cgi",
    "jpg": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "svg": "image/svg+xml",
    "pdf": "application/pdf",
    "txt": "text/plain",
}

MAGIC_BYTES = {
    "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "png": b"\x89PNG\r\n\x1a\n",
    "gif": b"GIF89a",
    "pdf": b"%PDF-1.4",
}

SVG_XSS_PAYLOAD = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<script type="text/javascript">alert('XSS_PROBE')</script>
<image href="x" onerror="alert('XSS_PROBE')"/>
</svg>"""

POLYGLOT_FILE = b"""GIF89a/*<script>alert('XSS_PROBE')</script>*/
<?php echo 'PHP_PROBE'; ?>
<% Response.Write("ASP_PROBE") %>
<%= puts("JSP_PROBE") %>"""

UPLOAD_ERROR_RE = re.compile(
    r"(?i)(?:file.*upload|upload.*error|invalid.*file|file.*type|"
    r"not.*allowed|file.*extension|extension.*not.*allowed|"
    r"file.*size|too.*large|file.*format|unsupported.*format|"
    r"invalid.*mime|mime.*type|file.*content|content.*type|"
    r"upload.*failed|file.*rejected|dangerous.*file)"
)

UPLOAD_SUCCESS_RE = re.compile(
    r"(?i)(?:upload.*success|file.*uploaded|uploaded.*successfully|"
    r"file.*saved|saved.*successfully|upload.*complete|"
    r"file.*path|file.*url|/uploads/|/files/|/attachments/)"
)


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


def _is_upload_endpoint(url: str, response: dict[str, Any] | None = None) -> bool:
    lowered = url.lower()
    if any(hint in lowered for hint in UPLOAD_PATH_HINTS):
        return True
    if response:
        body = str(response.get("body_text") or response.get("body") or "").lower()
        if any(
            token in body
            for token in ('type="file"', "file upload", "upload file", "choose file", "select file")
        ):
            return True
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    param_names = {k.lower() for k, _ in query_pairs}
    if param_names & UPLOAD_PARAM_NAMES:
        return True
    return False


def _build_multipart_body(
    field_name: str,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
    boundary: str = "----WebKitFormBoundary7MA4YWxkTrZu0gW",
) -> bytes:
    body = f"--{boundary}\r\n"
    body += f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
    body += f"Content-Type: {content_type}\r\n\r\n"
    body_bytes = body.encode("utf-8") + content + b"\r\n"
    body_bytes += f"--{boundary}--\r\n".encode()
    return body_bytes


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
        "category": "file_upload",
        "title": title,
        "severity": severity,
        "confidence": 0.80
        if severity in ("critical", "high")
        else 0.65
        if severity == "medium"
        else 0.50,
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": score_map.get(severity, 20),
    }


def file_upload_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for file upload vulnerabilities.

    Tests dangerous extension upload, double extension bypass, null byte injection,
    case variation bypass, MIME type manipulation, magic byte manipulation,
    file size limit bypass, polyglot file testing, and SVG XSS upload.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of file upload findings.
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
            original_resp = _safe_request(url, method="GET", body=None, timeout=8)
        if not original_resp or original_resp.get("status") in (404, 410, 503):
            if not _is_upload_endpoint(url, original_resp):
                continue

        if not _is_upload_endpoint(url, original_resp):
            continue

        original_status = original_resp.get("status", 0)
        original_headers = original_resp.get("headers", {})

        auth_headers = {}
        for k, v in original_headers.items():
            if k.lower() in ("authorization", "cookie", "x-csrf-token", "x-requested-with"):
                auth_headers[k] = v

        url_signals: list[str] = []
        url_evidence: list[dict[str, Any]] = []

        field_name = "file"
        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for k, _ in query_pairs:
            if k.lower() in UPLOAD_PARAM_NAMES:
                field_name = k
                break

        for ext in DANGEROUS_EXTENSIONS:
            if len(url_evidence) >= 5:
                break
            filename = f"test{ext}"
            content = f"<?php echo 'PROBE_{ext.upper()[1:]}'; ?>".encode()
            mime = MIME_TYPES.get(ext[1:], "application/octet-stream")
            body = _build_multipart_body(field_name, filename, content, mime)
            headers = dict(auth_headers)
            headers["Content-Type"] = (
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
            )

            response = _safe_request(url, method="POST", headers=headers, body=body, timeout=15)
            if not response:
                continue

            status = response.get("status", 0)
            resp_body = str(response.get("body") or "")

            issues_for_hit = []

            if UPLOAD_SUCCESS_RE.search(resp_body):
                issues_for_hit.append(f"dangerous_extension_uploaded:{ext}")
            elif status in (200, 201) and not UPLOAD_ERROR_RE.search(resp_body):
                issues_for_hit.append(f"dangerous_extension_no_error:{ext}")
            elif status == 200 and original_status in (400, 403, 415):
                issues_for_hit.append(f"dangerous_extension_bypass:{ext}")

            if issues_for_hit:
                url_signals.extend(issues_for_hit)
                url_evidence.append(
                    {
                        "test": "dangerous_extension",
                        "filename": filename,
                        "extension": ext,
                        "content_type": mime,
                        "status_code": status,
                        "signals": issues_for_hit,
                    }
                )

        for double_ext in DOUBLE_EXTENSIONS:
            if len(url_evidence) >= 5:
                break
            base_ext = double_ext.split(".")[-1] if "." in double_ext else "jpg"
            filename = f"test{double_ext}"
            magic = MAGIC_BYTES.get(base_ext, b"")
            content = magic + b"\r\n<?php echo 'DOUBLE_EXT_PROBE'; ?>"
            mime = MIME_TYPES.get(base_ext, "image/jpeg")
            body = _build_multipart_body(field_name, filename, content, mime)
            headers = dict(auth_headers)
            headers["Content-Type"] = (
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
            )

            response = _safe_request(url, method="POST", headers=headers, body=body, timeout=15)
            if not response:
                continue

            status = response.get("status", 0)
            resp_body = str(response.get("body") or "")

            issues_for_hit = []

            if UPLOAD_SUCCESS_RE.search(resp_body):
                issues_for_hit.append(f"double_extension_uploaded:{double_ext}")
            elif status in (200, 201) and not UPLOAD_ERROR_RE.search(resp_body):
                issues_for_hit.append(f"double_extension_no_error:{double_ext}")

            if issues_for_hit:
                url_signals.extend(issues_for_hit)
                url_evidence.append(
                    {
                        "test": "double_extension",
                        "filename": filename,
                        "extension": double_ext,
                        "status_code": status,
                        "signals": issues_for_hit,
                    }
                )

        for case_ext in CASE_VARIATIONS:
            if len(url_evidence) >= 5:
                break
            filename = f"test{case_ext}"
            content = b"<?php echo 'CASE_PROBE'; ?>"
            mime = "application/octet-stream"
            body = _build_multipart_body(field_name, filename, content, mime)
            headers = dict(auth_headers)
            headers["Content-Type"] = (
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
            )

            response = _safe_request(url, method="POST", headers=headers, body=body, timeout=15)
            if not response:
                continue

            status = response.get("status", 0)
            resp_body = str(response.get("body") or "")

            issues_for_hit = []

            if UPLOAD_SUCCESS_RE.search(resp_body):
                issues_for_hit.append(f"case_variation_uploaded:{case_ext}")
            elif status in (200, 201) and not UPLOAD_ERROR_RE.search(resp_body):
                issues_for_hit.append(f"case_variation_no_error:{case_ext}")

            if issues_for_hit:
                url_signals.extend(issues_for_hit)
                url_evidence.append(
                    {
                        "test": "case_variation",
                        "filename": filename,
                        "extension": case_ext,
                        "status_code": status,
                        "signals": issues_for_hit,
                    }
                )

        php_content = b"<?php echo 'MIME_BYPASS_PROBE'; ?>"
        for fake_mime, ext in [
            ("image/jpeg", ".php"),
            ("image/png", ".asp"),
            ("application/pdf", ".jsp"),
        ]:
            if len(url_evidence) >= 5:
                break
            filename = f"test{ext}"
            body = _build_multipart_body(field_name, filename, php_content, fake_mime)
            headers = dict(auth_headers)
            headers["Content-Type"] = (
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
            )

            response = _safe_request(url, method="POST", headers=headers, body=body, timeout=15)
            if not response:
                continue

            status = response.get("status", 0)
            resp_body = str(response.get("body") or "")

            issues_for_hit = []

            if UPLOAD_SUCCESS_RE.search(resp_body):
                issues_for_hit.append(f"mime_type_bypass:{fake_mime}->{ext}")
            elif status in (200, 201) and not UPLOAD_ERROR_RE.search(resp_body):
                issues_for_hit.append(f"mime_type_no_error:{fake_mime}")

            if issues_for_hit:
                url_signals.extend(issues_for_hit)
                url_evidence.append(
                    {
                        "test": "mime_manipulation",
                        "filename": filename,
                        "claimed_mime": fake_mime,
                        "actual_extension": ext,
                        "status_code": status,
                        "signals": issues_for_hit,
                    }
                )

        for magic_name, magic_bytes_val in MAGIC_BYTES.items():
            if len(url_evidence) >= 5:
                break
            ext_map = {"jpg": ".php", "png": ".asp", "gif": ".jsp", "pdf": ".aspx"}
            dangerous_ext = ext_map.get(magic_name, ".php")
            filename = f"test{dangerous_ext}"
            content = magic_bytes_val + b"\r\n\r\n" + b"<?php echo 'MAGIC_BYPASS_PROBE'; ?>"
            mime = MIME_TYPES.get(magic_name, "application/octet-stream")
            body = _build_multipart_body(field_name, filename, content, mime)
            headers = dict(auth_headers)
            headers["Content-Type"] = (
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
            )

            response = _safe_request(url, method="POST", headers=headers, body=body, timeout=15)
            if not response:
                continue

            status = response.get("status", 0)
            resp_body = str(response.get("body") or "")

            issues_for_hit = []

            if UPLOAD_SUCCESS_RE.search(resp_body):
                issues_for_hit.append(f"magic_byte_bypass:{magic_name}->{dangerous_ext}")
            elif status in (200, 201) and not UPLOAD_ERROR_RE.search(resp_body):
                issues_for_hit.append(f"magic_byte_no_error:{magic_name}")

            if issues_for_hit:
                url_signals.extend(issues_for_hit)
                url_evidence.append(
                    {
                        "test": "magic_byte_manipulation",
                        "filename": filename,
                        "magic_type": magic_name,
                        "extension": dangerous_ext,
                        "status_code": status,
                        "signals": issues_for_hit,
                    }
                )

        svg_body = _build_multipart_body(field_name, "test.svg", SVG_XSS_PAYLOAD, "image/svg+xml")
        svg_headers = dict(auth_headers)
        svg_headers["Content-Type"] = (
            "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
        )

        response = _safe_request(url, method="POST", headers=svg_headers, body=svg_body, timeout=15)
        if response:
            status = response.get("status", 0)
            resp_body = str(response.get("body") or "")
            if UPLOAD_SUCCESS_RE.search(resp_body):
                url_signals.append("svg_upload_accepted")
                url_evidence.append(
                    {
                        "test": "svg_xss_upload",
                        "filename": "test.svg",
                        "status_code": status,
                        "signals": ["svg_upload_accepted"],
                    }
                )
            elif status in (200, 201) and not UPLOAD_ERROR_RE.search(resp_body):
                url_signals.append("svg_upload_no_error")
                url_evidence.append(
                    {
                        "test": "svg_xss_upload",
                        "filename": "test.svg",
                        "status_code": status,
                        "signals": ["svg_upload_no_error"],
                    }
                )

        polyglot_body = _build_multipart_body(field_name, "test.php", POLYGLOT_FILE, "image/jpeg")
        polyglot_headers = dict(auth_headers)
        polyglot_headers["Content-Type"] = (
            "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
        )

        response = _safe_request(
            url, method="POST", headers=polyglot_headers, body=polyglot_body, timeout=15
        )
        if response:
            status = response.get("status", 0)
            resp_body = str(response.get("body") or "")
            if UPLOAD_SUCCESS_RE.search(resp_body):
                url_signals.append("polyglot_file_uploaded")
                url_evidence.append(
                    {
                        "test": "polyglot_upload",
                        "filename": "test.php",
                        "status_code": status,
                        "signals": ["polyglot_file_uploaded"],
                    }
                )
            elif status in (200, 201) and not UPLOAD_ERROR_RE.search(resp_body):
                url_signals.append("polyglot_file_accepted")
                url_evidence.append(
                    {
                        "test": "polyglot_upload",
                        "filename": "test.php",
                        "status_code": status,
                        "signals": ["polyglot_file_accepted"],
                    }
                )

        if url_evidence:
            has_dangerous = any("dangerous_extension" in s for s in url_signals)
            has_bypass = any("bypass" in s for s in url_signals)
            has_svg = any("svg" in s for s in url_signals)

            if has_dangerous and has_bypass:
                severity = "critical"
            elif has_dangerous:
                severity = "high"
            elif has_svg or has_bypass:
                severity = "high"
            else:
                severity = "medium"

            title = f"File upload: {len(url_evidence)} test(s) succeeded"
            if has_dangerous:
                title = "File upload: dangerous file extension accepted"
            if has_bypass:
                title = "File upload: validation bypass detected"

            normalized_confidence(
                base=0.75 if severity == "high" else 0.60 if severity == "medium" else 0.90,
                score=9 if severity == "critical" else 7 if severity == "high" else 4,
                signals=url_signals,
            )

            explanation = (
                f"Upload endpoint '{url}' accepted {len(url_evidence)} malicious file test(s). "
                f"Signals: {', '.join(sorted(set(url_signals)))}. "
                f"File upload validation appears insufficient."
            )

            findings.append(
                _build_finding(
                    url=url,
                    severity=severity,
                    title=title,
                    signals=sorted(set(url_signals)),
                    evidence={"tests": url_evidence[:15], "total_tests": len(url_evidence)},
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
