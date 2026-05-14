"""File upload surface detector for identifying endpoints that accept file uploads.

Analyzes URLs and responses for file upload indicators including multipart forms,
upload-related parameters, file extension handling, and MIME type processing.
Flags endpoints that may be vulnerable to unrestricted file upload, MIME type
bypass, or extension validation bypass attacks.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    endpoint_signature,
    is_noise_url,
    meaningful_query_pairs,
    normalized_confidence,
)
from src.analysis.passive.extended_shared import (
    build_response_index,
    compute_severity,
    record,
)

# File upload-related parameter names
UPLOAD_PARAM_NAMES = {
    "file",
    "upload",
    "attachment",
    "document",
    "doc",
    "image",
    "img",
    "photo",
    "avatar",
    "logo",
    "banner",
    "background",
    "cover",
    "thumbnail",
    "thumb",
    "media",
    "video",
    "audio",
    "import",
    "csv",
    "excel",
    "spreadsheet",
    "backup",
    "export",
    "download",
    "attachment",
    "payload",
    "data",
    "profile_picture",
    "profile_image",
    "user_image",
    "user_file",
}

# File upload-related path patterns
UPLOAD_PATH_PATTERNS = re.compile(
    r"(?i)/(upload|import|attachment|document|file|media|image|photo|avatar|logo|banner|cover|thumbnail|backup|export|csv|excel|spreadsheet)(?:s|er|ing|ed)?(?:/|$)"
)

# Dangerous file extensions that should be flagged
DANGEROUS_EXTENSIONS = {
    "php",
    "php3",
    "php4",
    "php5",
    "php7",
    "phtml",
    "asp",
    "aspx",
    "jsp",
    "jspx",
    "cgi",
    "pl",
    "py",
    "rb",
    "sh",
    "bash",
    "exe",
    "bat",
    "cmd",
    "com",
    "scr",
    "pif",
    "hta",
    "vbs",
    "wsf",
    "msi",
    "dll",
    "so",
    "dylib",
}

# MIME types that indicate upload handling
UPLOAD_MIME_INDICATORS = {
    "multipart/form-data",
    "application/octet-stream",
    "image/",
    "video/",
    "audio/",
    "application/pdf",
    "application/msword",
    "application/vnd.",
    "text/csv",
    "application/zip",
    "application/x-",
}


def _check_upload_indicators_in_body(body: str) -> list[str]:
    """Check response body for file upload indicators.

    Args:
        body: Response body text.

    Returns:
        List of upload indicator signals found in the body.
    """
    signals = []
    body_lower = body.lower()

    # Check for file input fields
    if 'type="file"' in body_lower or "type='file'" in body_lower:
        signals.append("file_input_field")

    # Check for multipart form
    if (
        'enctype="multipart/form-data"' in body_lower
        or "enctype='multipart/form-data'" in body_lower
    ):
        signals.append("multipart_form")

    # Check for upload-related JavaScript
    if any(
        kw in body_lower
        for kw in (
            "fileupload",
            "file_upload",
            "uploadfile",
            "upload_file",
            "dropzone",
            "filepicker",
        )
    ):
        signals.append("upload_js_library")

    # Check for file extension validation
    if any(
        kw in body_lower
        for kw in (
            "allowed_extensions",
            "allowed_file_types",
            "file_type_validation",
            "mime_type_check",
        )
    ):
        signals.append("extension_validation_hint")

    # Check for max file size limits
    if re.search(r"max[_-]?file[_-]?size|max[_-]?upload[_-]?size|maxfilesize", body_lower):
        signals.append("file_size_limit_hint")

    # Check for file storage paths
    if re.search(r"(?:uploads?|attachments?|documents?|media|images?)/[\w.-]+", body_lower):
        signals.append("file_storage_path")

    return signals


def file_upload_surface_detector(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Detect endpoints that may accept file uploads.

    Analyzes URLs and responses for:
    - Upload-related path patterns
    - File-related query parameters
    - Multipart form indicators in responses
    - File input fields in HTML
    - File extension handling hints

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.

    Returns:
        List of file upload surface findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    response_by_url = build_response_index(responses)

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        upload_params: list[str] = []
        path_match = UPLOAD_PATH_PATTERNS.search(urlparse(url).path or "")

        if path_match:
            signals.append(f"upload_path:{path_match.group(1).lower()}")

        # Check for upload-related query parameters
        query_pairs = meaningful_query_pairs(url)
        for name, value in query_pairs:
            if name.lower() in UPLOAD_PARAM_NAMES:
                upload_params.append(name.lower())
                # Check for dangerous file extensions in parameter values
                ext = value.rsplit(".", 1)[-1].lower() if "." in value else ""
                if ext in DANGEROUS_EXTENSIONS:
                    signals.append(f"dangerous_extension_in_param:{ext}")

        if upload_params:
            signals.extend(f"param:{p}" for p in sorted(upload_params))

        # Check response for upload indicators and server-side validation signals
        response = response_by_url.get(url)
        if response:
            body = str(response.get("body_text") or "")[:8000]
            content_type = str(response.get("content_type") or "").lower()
            headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

            # Check content type for upload handling
            if any(content_type.startswith(mime) for mime in UPLOAD_MIME_INDICATORS):
                signals.append("upload_mime_type")

            # Check for server-side validation indicators in headers
            if headers.get("x-content-type-options", "").lower() == "nosniff":
                signals.append("nosniff_header_present")
            if "content-disposition" in headers:
                content_disp = headers["content-disposition"].lower()
                if "attachment" in content_disp:
                    signals.append("content_disposition_attachment")
                elif "inline" in content_disp:
                    signals.append("content_disposition_inline")  # Potential risk

            # Check for double-extension patterns in response (indicates weak validation)
            if body:
                double_ext_patterns = re.findall(
                    r"[\w-]+\.(?:php|jsp|asp)\.(?:jpg|png|gif|pdf)", body, re.IGNORECASE
                )
                if double_ext_patterns:
                    signals.append("double_extension_pattern_detected")

                # Check for file upload response indicators
                if any(
                    kw in body.lower()
                    for kw in (
                        '"upload_url"',
                        '"file_url"',
                        '"download_url"',
                        '"file_path"',
                        '"storage_path"',
                    )
                ):
                    signals.append("file_url_in_response")

                # Check if server reveals file type validation method
                if any(
                    kw in body.lower()
                    for kw in ("mime_type", "content_type", "file_type", "extension_check")
                ):
                    signals.append("server_reveals_validation_method")

            # Check body for upload indicators
            if body:
                body_signals = _check_upload_indicators_in_body(body)
                signals.extend(body_signals)

        # Only report if we have meaningful signals
        if len(signals) < 2:
            continue

        seen.add(endpoint_key)

        # Calculate risk score with server-side validation awareness
        risk_score = 0
        if path_match:
            risk_score += 3
        if upload_params:
            risk_score += 2 * len(upload_params)
        if any("dangerous_extension" in s for s in signals):
            risk_score += 5
        if "multipart_form" in signals:
            risk_score += 3
        if "file_input_field" in signals:
            risk_score += 2
        if "upload_js_library" in signals:
            risk_score += 1

        # Server-side validation signals (reduce risk if present)
        if "nosniff_header_present" in signals:
            risk_score -= 1  # Slightly lower risk with security headers
        if "content_disposition_attachment" in signals:
            risk_score -= 1  # Lower risk if files served as attachments

        # Increased risk indicators
        if "content_disposition_inline" in signals:
            risk_score += 3  # Higher risk if files served inline
        if "double_extension_pattern_detected" in signals:
            risk_score += 6  # High risk for double-extension bypass
        if "file_url_in_response" in signals:
            risk_score += 2  # Indicates files are stored and accessible
        if "server_reveals_validation_method" in signals:
            risk_score += 3  # Information disclosure aids attackers

        severity = compute_severity(risk_score)

        # Calculate confidence based on signal strength and evidence quality
        confidence = normalized_confidence(
            base=0.45,
            score=risk_score,
            signals=signals,
            cap=0.90,
        )

        # Build human-readable explanation
        explanation_parts = []
        if path_match:
            explanation_parts.append(f"Upload-related path detected: {path_match.group(1).lower()}")
        if upload_params:
            explanation_parts.append(f"Upload parameters found: {', '.join(sorted(upload_params))}")
        if any("dangerous_extension" in s for s in signals):
            dangerous_exts = [s.split(":")[1] for s in signals if "dangerous_extension" in s]
            explanation_parts.append(
                f"Dangerous file extensions in parameters: {', '.join(dangerous_exts)}"
            )
        if "multipart_form" in signals:
            explanation_parts.append(
                "Multipart form detected - endpoint likely accepts file uploads"
            )
        if "file_input_field" in signals:
            explanation_parts.append("File input field detected in response body")

        findings.append(
            record(
                url,
                status_code=response.get("status_code") if response else None,
                upload_signals=signals,
                upload_parameters=sorted(upload_params),
                risk_score=risk_score,
                severity=severity,
                confidence=round(confidence, 2),
                explanation="; ".join(explanation_parts)
                if explanation_parts
                else "File upload surface detected",
                content_type=response.get("content_type", "") if response else "",
            )
        )

    findings.sort(key=lambda item: (-item.get("risk_score", 0), item.get("url", "")))
    return findings
