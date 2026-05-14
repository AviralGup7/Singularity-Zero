"""File upload validation for endpoints accepting file uploads.

Validates file upload candidates by analyzing passive detection results,
performing active upload tests with dangerous file types, extension bypass
techniques, MIME type manipulation, and path traversal attempts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.core.models import ValidationResult

import logging

from src.analysis.helpers import (
    endpoint_signature,
    is_auth_flow_endpoint,
    is_low_value_endpoint,
    normalized_confidence,
)
from src.execution.validators.validators.shared import to_validation_result

logger = logging.getLogger(__name__)

# Dangerous file extensions that should be blocked
DANGEROUS_EXTENSIONS = {
    "php",
    "php3",
    "php4",
    "php5",
    "phtml",  # PHP
    "asp",
    "aspx",
    "ashx",
    "asmx",  # ASP.NET
    "jsp",
    "jspx",  # Java
    "cgi",
    "pl",  # Perl/CGI
    "py",
    "rb",  # Python/Ruby
    "exe",
    "bat",
    "cmd",
    "sh",
    "bash",  # Executables
    "html",
    "htm",
    "svg",  # HTML/SVG (XSS)
    "js",  # JavaScript
}

# Upload-related parameter names
UPLOAD_PARAM_NAMES = {
    "file",
    "upload",
    "attachment",
    "document",
    "image",
    "photo",
    "avatar",
    "logo",
    "import",
    "export",
    "csv",
    "excel",
    "media",
    "video",
    "audio",
    "pdf",
    "backup",
}


def validate_file_upload_candidates(
    analysis_results: dict[str, Any],
    callback_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Validate file upload protection on endpoints accepting uploads.

    Analyzes results from passive file upload detectors to identify endpoints
    that may be vulnerable to unrestricted file upload attacks.

    Args:
        analysis_results: Results from passive analysis modules.
        callback_context: Optional callback context with validation state.

    Returns:
        List of file upload validation findings.
    """
    findings: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()

    # Get file upload-related findings from passive analysis
    upload_findings = analysis_results.get("file_upload_surface_detector", [])

    for item in upload_findings:
        url = str(item.get("url", "")).strip()
        if not url or is_low_value_endpoint(url):
            continue
        endpoint_key = str(item.get("endpoint_key") or endpoint_signature(url))
        if endpoint_key in seen_patterns:
            continue
        seen_patterns.add(endpoint_key)

        upload_params = list(item.get("upload_parameters", []))
        signals = list(item.get("signals", []))
        score = int(item.get("score", 0))

        # Check for auth flow endpoints (higher risk for file upload)
        if is_auth_flow_endpoint(url):
            signals.append("auth_flow_endpoint")
            score += 2

        # Score based on upload indicators
        upload_indicators = item.get("upload_indicators", [])
        score += len(upload_indicators) * 2

        # Check for dangerous file extension handling
        dangerous_extensions = item.get("dangerous_extensions", [])
        if dangerous_extensions:
            signals.append("dangerous_extension_handling")
            score += len(dangerous_extensions) * 3

        # Check for MIME type validation
        mime_validation = item.get("mime_validation", False)
        if not mime_validation:
            signals.append("missing_mime_validation")
            score += 3

        # Check for file size limits
        size_limits = item.get("size_limits", {})
        if not size_limits:
            signals.append("missing_size_limits")
            score += 2

        # Determine validation state
        validation_state = "passive_only"
        if upload_params and (dangerous_extensions or not mime_validation):
            validation_state = "active_ready"
            score += 5
        elif upload_params:
            score += 2

        # Calculate confidence
        confidence = normalized_confidence(
            base=0.48,
            score=score,
            signals=signals,
            cap=0.92,
        )

        # Determine severity
        if dangerous_extensions and not mime_validation:
            severity = "high"
        elif upload_params and not mime_validation:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": str(item.get("endpoint_type", "GENERAL")),
                "score": score,
                "severity": severity,
                "signals": sorted(set(signals)),
                "confidence": round(confidence, 2),
                "validation_state": validation_state,
                "upload_parameters": upload_params,
                "dangerous_extensions": sorted(set(dangerous_extensions)),
                "hint_message": f"File upload surface detected on {url}. Parameters: {', '.join(upload_params[:3]) if upload_params else 'review recommended'}. Test for unrestricted upload and MIME bypass.",
            }
        )

    findings.sort(key=lambda x: (-x["score"], -x["confidence"], x["url"]))
    return findings[:50]


DANGEROUS_FILE_CONTENTS = {
    "php": b"<?php echo 'VULNERABLE'; ?>",
    "php3": b"<?php echo 'VULNERABLE'; ?>",
    "phtml": b"<?php echo 'VULNERABLE'; ?>",
    "asp": b'<% Response.Write("VULNERABLE") %>',
    "aspx": b'<%@ Page Language="C#" %>VULNERABLE',
    "jsp": b'<% out.println("VULNERABLE"); %>',
    "cgi": b'#!/usr/bin/perl\nprint "Content-type: text/html\\n\\nVULNERABLE";',
    "html": b"<html><body>VULNERABLE</body></html>",
    "svg": b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("VULNERABLE")</script></svg>',
    "js": b"console.log('VULNERABLE');",
}

EXTENSION_BYPASS_PAYLOADS = [
    ("test.php", "Double extension"),
    ("test.php.jpg", "Double extension with allowed ext"),
    ("test.php;.jpg", "Semicolon injection"),
    ("test.php%00.jpg", "Null byte injection"),
    ("test.php%00.png", "Null byte with PNG"),
    ("test.PHP", "Case variation"),
    ("test.PhP", "Mixed case variation"),
    ("test.php.", "Trailing dot"),
    ("test.php ", "Trailing space"),
    ("test.php::$DATA", "ADS stream (IIS)"),
    ("test..php..", "Double dot bypass"),
    ("test%2ephp", "URL-encoded dot"),
    ("test%00.php", "Null byte before extension"),
]

MIME_TYPE_TESTS = [
    ("test.php", "image/jpeg", "PHP with image/jpeg MIME"),
    ("test.php", "image/png", "PHP with image/png MIME"),
    ("test.php", "application/octet-stream", "PHP with generic MIME"),
    ("test.php", "text/plain", "PHP with text MIME"),
    ("test.jpg", "application/x-php", "JPG with PHP MIME"),
    ("test.php5", "image/gif", "PHP5 with GIF MIME"),
]

PATH_TRAVERSAL_FILENAMES = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "C:\\Windows\\System32\\config\\SAM",
    "..\\..\\..\\..\\..\\boot.ini",
]

SIZE_LIMIT_TESTS = [
    (1024 * 1024 * 50, "50MB oversized file"),
    (1024 * 1024 * 10, "10MB large file"),
    (1, "1-byte minimal file"),
    (0, "0-byte empty file"),
]


def _build_multipart_body(
    filename: str,
    content: bytes,
    content_type: str,
    field_name: str = "file",
) -> tuple[bytes, str]:
    """Build a multipart/form-data body for file upload testing.

    Args:
        filename: The filename to use in the upload.
        content: The file content bytes.
        content_type: The MIME type to declare.
        field_name: The form field name.

    Returns:
        Tuple of (body bytes, content-type header value).
    """
    import uuid

    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode()
    body += content
    body += f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def _active_file_upload_test(target_url: str, http_client: Any) -> dict[str, Any]:
    """Perform active file upload testing against a target endpoint.

    Tests dangerous file types, extension bypass techniques, MIME type
    manipulation, path traversal in filenames, and file size limits.

    Args:
        target_url: The URL to test.
        http_client: HTTP client for making requests.

    Returns:
        Dict with active test results.
    """
    if not http_client:
        return {"status": "skipped", "reason": "no_http_client"}

    test_results: list[dict[str, Any]] = []
    dangerous_accepted: list[str] = []
    extension_bypasses: list[str] = []
    mime_bypasses: list[str] = []
    path_traversal_results: list[str] = []
    size_limit_results: list[str] = []

    for ext, content in DANGEROUS_FILE_CONTENTS.items():
        filename = f"test.{ext}"
        try:
            body, content_type = _build_multipart_body(
                filename, content, "application/octet-stream"
            )
            response = http_client.request(
                target_url,
                method="POST",
                body=body,
                headers={"Content-Type": content_type},
            )
            status_code = int(response.get("status_code") or 0)
            resp_body = str(response.get("body", ""))

            accepted = status_code in (200, 201, 204, 302)
            stored_path = _extract_stored_path(resp_body, filename)

            result = {
                "test": "dangerous_extension",
                "filename": filename,
                "status_code": status_code,
                "accepted": accepted,
                "stored_path": stored_path,
            }
            test_results.append(result)

            if accepted and stored_path:
                dangerous_accepted.append(filename)
                if ext in ("php", "php3", "phtml", "asp", "aspx", "jsp", "cgi"):
                    result["severity"] = "critical"

        except Exception as exc:
            test_results.append(
                {
                    "test": "dangerous_extension",
                    "filename": filename,
                    "status": "error",
                    "error": str(exc),
                }
            )

    for bypass_filename, description in EXTENSION_BYPASS_PAYLOADS:
        content = b"<?php echo 'BYPASS_TEST'; ?>"
        try:
            body, content_type = _build_multipart_body(bypass_filename, content, "image/jpeg")
            response = http_client.request(
                target_url,
                method="POST",
                body=body,
                headers={"Content-Type": content_type},
            )
            status_code = int(response.get("status_code") or 0)
            resp_body = str(response.get("body", ""))

            accepted = status_code in (200, 201, 204, 302)
            stored_path = _extract_stored_path(resp_body, bypass_filename)

            result = {
                "test": "extension_bypass",
                "description": description,
                "filename": bypass_filename,
                "status_code": status_code,
                "accepted": accepted,
                "stored_path": stored_path,
            }
            test_results.append(result)

            if accepted:
                extension_bypasses.append(f"{bypass_filename} ({description})")

        except Exception as exc:
            logger.debug("File upload test failed (extension_bypass=%s): %s", bypass_filename, exc)

    for filename, mime_type, description in MIME_TYPE_TESTS:
        content = b"<?php echo 'MIME_BYPASS'; ?>"
        try:
            body, content_type = _build_multipart_body(filename, content, mime_type)
            response = http_client.request(
                target_url,
                method="POST",
                body=body,
                headers={"Content-Type": content_type},
            )
            status_code = int(response.get("status_code") or 0)
            resp_body = str(response.get("body", ""))

            accepted = status_code in (200, 201, 204, 302)
            stored_path = _extract_stored_path(resp_body, filename)

            result = {
                "test": "mime_bypass",
                "description": description,
                "filename": filename,
                "mime_type": mime_type,
                "status_code": status_code,
                "accepted": accepted,
                "stored_path": stored_path,
            }
            test_results.append(result)

            if accepted:
                mime_bypasses.append(f"{filename} as {mime_type} ({description})")

        except Exception as exc:
            logger.debug("File upload test failed (mime_test=%s): %s", filename, exc)

    for traversal_filename in PATH_TRAVERSAL_FILENAMES:
        content = b"PATH_TRAVERSAL_TEST"
        try:
            body, content_type = _build_multipart_body(traversal_filename, content, "text/plain")
            response = http_client.request(
                target_url,
                method="POST",
                body=body,
                headers={"Content-Type": content_type},
            )
            status_code = int(response.get("status_code") or 0)
            resp_body = str(response.get("body", ""))

            accepted = status_code in (200, 201, 204, 302)
            stored_path = _extract_stored_path(resp_body, traversal_filename)

            result = {
                "test": "path_traversal",
                "filename": traversal_filename,
                "status_code": status_code,
                "accepted": accepted,
                "stored_path": stored_path,
            }
            test_results.append(result)

            if accepted and stored_path and (".." in stored_path or stored_path.startswith("/")):
                path_traversal_results.append(f"{traversal_filename} -> {stored_path}")

        except Exception as exc:
            logger.debug("File upload test failed (traversal=%s): %s", traversal_filename, exc)

    for size, description in SIZE_LIMIT_TESTS:
        content = b"A" * min(size, 1024 * 100)
        try:
            body, content_type = _build_multipart_body("test_large.txt", content, "text/plain")
            response = http_client.request(
                target_url,
                method="POST",
                body=body,
                headers={"Content-Type": content_type},
            )
            status_code = int(response.get("status_code") or 0)

            accepted = status_code in (200, 201, 204, 302)
            result = {
                "test": "size_limit",
                "description": description,
                "size": size,
                "status_code": status_code,
                "accepted": accepted,
            }
            test_results.append(result)

            if accepted:
                size_limit_results.append(f"{description} accepted")
            else:
                size_limit_results.append(f"{description} rejected ({status_code})")

        except Exception as exc:
            logger.debug("File upload test failed (size_test=%s): %s", description, exc)

    if dangerous_accepted:
        final_status = "confirmed"
    elif extension_bypasses or mime_bypasses:
        final_status = "potential"
    elif path_traversal_results:
        final_status = "potential"
    else:
        final_status = "not_vulnerable"

    return {
        "status": final_status,
        "url": target_url,
        "test_results": test_results[:30],
        "dangerous_accepted": dangerous_accepted,
        "extension_bypasses": extension_bypasses,
        "mime_bypasses": mime_bypasses,
        "path_traversal_results": path_traversal_results,
        "size_limit_results": size_limit_results,
        "dangerous_count": len(dangerous_accepted),
        "bypass_count": len(extension_bypasses) + len(mime_bypasses),
        "traversal_count": len(path_traversal_results),
        "payloads_tested": len(test_results),
    }


def _extract_stored_path(response_body: str, filename: str) -> str:
    """Try to extract the stored file path from the response.

    Args:
        response_body: The HTTP response body.
        filename: The uploaded filename to look for.

    Returns:
        Extracted path string or empty string.
    """
    import re

    if not response_body:
        return ""

    patterns = [
        rf'(?:path|file|url|src|href|location)["\s]*[:=]\s*["\']?([^\s"\'>]+{re.escape(filename)}[^\s"\'>]*)',
        rf'["\']?([^\s"\'>]*uploads[^\s"\'>]*{re.escape(filename)}[^\s"\'>]*)["\']?',
        rf'["\']?(/[^"\'>\s]*{re.escape(filename)})["\']?',
    ]

    for pattern in patterns:
        match = re.search(pattern, response_body, re.IGNORECASE)
        if match:
            return match.group(1)

    if filename.lower() in response_body.lower():
        return filename

    return ""


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    """Validate file upload vulnerability with passive analysis and active testing.

    Performs passive analysis of existing responses for file upload surfaces,
    then actively tests upload endpoints with dangerous file types, extension
    bypass techniques, MIME type manipulation, and path traversal attempts.

    Args:
        target: Target dict with url and metadata.
        context: Validation context with analysis_results and http_client.

    Returns:
        ValidationResult with file upload assessment.
    """
    analysis_results = context.get("analysis_results") if isinstance(context, dict) else {}
    analysis_results = analysis_results if isinstance(analysis_results, dict) else {}
    http_client = context.get("http_client") if isinstance(context, dict) else None

    passive_findings = validate_file_upload_candidates(analysis_results)

    if not passive_findings:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "no_upload_signals"},
            validator="file_upload",
            category="file_upload",
        )

    top_finding = passive_findings[0]
    target_url = top_finding.get("url", target.get("url", ""))
    validation_state = top_finding.get("validation_state", "passive_only")

    active_result: dict[str, Any] = {"status": "skipped", "reason": "not_active_ready"}

    if validation_state == "active_ready" and http_client:
        active_result = _active_file_upload_test(target_url, http_client)

    active_status = active_result.get("status", "skipped")
    dangerous_count = active_result.get("dangerous_count", 0)
    bypass_count = active_result.get("bypass_count", 0)
    traversal_count = active_result.get("traversal_count", 0)
    dangerous_accepted = active_result.get("dangerous_accepted", [])
    extension_bypasses = active_result.get("extension_bypasses", [])
    mime_bypasses = active_result.get("mime_bypasses", [])
    path_traversal_results = active_result.get("path_traversal_results", [])
    size_limit_results = active_result.get("size_limit_results", [])

    base_confidence = top_finding.get("confidence", 0.48)
    bonuses: list[float] = []

    if active_status == "confirmed":
        bonuses.append(0.30)
    elif active_status == "potential":
        bonuses.append(0.15)
    elif active_status == "not_vulnerable":
        bonuses.append(-0.10)

    if dangerous_count > 0:
        bonuses.append(0.20)
        if any(ext in str(dangerous_accepted).lower() for ext in ("php", "asp", "jsp")):
            bonuses.append(0.10)

    if bypass_count >= 3:
        bonuses.append(0.12)
    elif bypass_count >= 1:
        bonuses.append(0.06)

    if traversal_count > 0:
        bonuses.append(0.10)

    passive_signals = top_finding.get("signals", [])
    if "missing_mime_validation" in passive_signals:
        bonuses.append(0.05)
    if "missing_size_limits" in passive_signals:
        bonuses.append(0.03)
    if "dangerous_extension_handling" in passive_signals:
        bonuses.append(0.06)

    if validation_state == "active_ready":
        bonuses.append(0.08)

    confidence = round(min(max(base_confidence + sum(bonuses), 0.10), 0.98), 2)

    if active_status == "confirmed":
        final_status = "confirmed"
        severity = "critical" if dangerous_count > 0 else "high"
    elif active_status == "potential":
        final_status = "potential"
        severity = "high" if bypass_count > 0 else "medium"
    elif dangerous_count > 0:
        final_status = "potential"
        severity = "high"
    else:
        final_status = "not_confirmed"
        severity = "low"

    edge_case_notes = []
    if active_status == "skipped":
        edge_case_notes.append(
            "Active testing was skipped — no HTTP client or endpoint not active-ready."
        )
    if dangerous_accepted:
        edge_case_notes.append(
            f"Dangerous file types accepted ({len(dangerous_accepted)}): {', '.join(dangerous_accepted[:5])}."
        )
    if extension_bypasses:
        edge_case_notes.append(
            f"Extension bypass techniques succeeded ({len(extension_bypasses)}): {', '.join(extension_bypasses[:3])}."
        )
    if mime_bypasses:
        edge_case_notes.append(
            f"MIME type bypasses succeeded ({len(mime_bypasses)}): {', '.join(mime_bypasses[:3])}."
        )
    if path_traversal_results:
        edge_case_notes.append(
            f"Path traversal in filename succeeded ({len(path_traversal_results)})."
        )
    if size_limit_results:
        accepted_sizes = [s for s in size_limit_results if "accepted" in s.lower()]
        if accepted_sizes:
            edge_case_notes.append(
                f"No file size limits enforced: {', '.join(accepted_sizes[:3])}."
            )

    evidence = {
        "passive_signals": top_finding.get("signals", []),
        "upload_parameters": top_finding.get("upload_parameters", []),
        "dangerous_extensions_passive": top_finding.get("dangerous_extensions", []),
        "active_status": active_status,
        "dangerous_count": dangerous_count,
        "bypass_count": bypass_count,
        "traversal_count": traversal_count,
        "dangerous_accepted": dangerous_accepted,
        "extension_bypasses": extension_bypasses,
        "mime_bypasses": mime_bypasses,
        "path_traversal_results": path_traversal_results,
        "size_limit_results": size_limit_results,
        "payloads_tested": active_result.get("payloads_tested", 0),
        "test_results": active_result.get("test_results", [])[:15],
    }

    result_item = {
        "url": target_url,
        "status": final_status,
        "confidence": confidence,
        "severity": severity,
        "validation_state": "active_tested" if active_status != "skipped" else validation_state,
        "signals": top_finding.get("signals", []),
        "evidence": evidence,
        "edge_case_notes": edge_case_notes,
        "hint_message": top_finding.get("hint_message", ""),
    }

    return to_validation_result(result_item, validator="file_upload", category="file_upload")
