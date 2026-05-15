"""CRLF vulnerability validation logic."""

from .._patterns import CRLF_HEADER_RE


def _check_crlf_vulnerability(
    headers: dict[str, str],
    body: str,
    expected_header: str,
    expected_value: str,
    token: str,
    is_set_cookie: bool = False,
    is_response_split: bool = False,
) -> list[str]:
    """Validate whether a CRLF injection was successful.

    Uses session-cookie-style validation: for Set-Cookie, checks the exact
    cookie value. For headers, checks exact header presence. For response
    splitting, checks body content.

    Args:
        headers: Response headers (lowercased keys).
        body: Response body text.
        expected_header: Header name to check for.
        expected_value: Expected header/cookie value.
        token: The unique probe token.
        is_set_cookie: Whether this is a Set-Cookie probe.
        is_response_split: Whether this is a response splitting probe.

    Returns:
        List of detected issue types.
    """
    issues: list[str] = []

    if is_response_split:
        if f"crlf-body-{token}" in body:
            issues.append("crlf_response_split")
        if "HTTP/1." in body or "HTTP/2" in body:
            if "HTTP/1.1 418" in body.lower() or "HTTP/1.0 418" in body.lower():
                issues.append("crlf_status_manipulation")
        if CRLF_HEADER_RE.search(body):
            issues.append("crlf_response_split")
        if f"crlf-xss-{token}" in body.lower():
            issues.append("crlf_xss_via_split")
        if f"<script>alert('{token}')</script>" in body.lower():
            issues.append("crlf_xss_injected")
        if f"xss-{token}" in body.lower():
            issues.append("crlf_xss_body_injection")
    elif is_set_cookie:
        set_cookie = headers.get("set-cookie", "")
        if expected_value.lower() in set_cookie.lower():
            issues.append("crlf_set_cookie_injection")
        if expected_value.lower() in body.lower():
            if "crlf_set_cookie_injection" not in issues:
                issues.append("crlf_cookie_reflection")
    elif expected_header:
        header_value = headers.get(expected_header.lower(), "")
        if expected_value.lower() in header_value.lower():
            issues.append("crlf_header_injection")
        elif expected_value.lower() in body.lower():
            if f"crlf-header-{token}" in body.lower():
                issues.append("crlf_header_reflection")
            else:
                issues.append("crlf_value_reflection")

    return issues
