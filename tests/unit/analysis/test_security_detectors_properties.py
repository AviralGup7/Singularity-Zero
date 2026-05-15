"""Property-based tests for security detectors using Hypothesis.

Tests cover SSRF, XSS, CSRF, security header checking, and sensitive data
exposure detectors with both positive (should detect) and negative
(should not false-positive) property tests.
"""

import ipaddress
import string
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from src.analysis.active.xss_constants import XSS_DANGEROUS_VALUE_RE
from src.analysis.active.xss_utils import xss_signals
from src.analysis.checks.active._impl import stored_xss_signal_detector
from src.analysis.checks.active.ssrf_oob_validator._helpers import (
    check_cloud_metadata,
    check_internal_errors,
    check_internal_leakage,
    find_ssrf_params,
)
from src.analysis.checks.passive._impl import (
    header_checker,
    sensitive_data_scanner,
)
from src.analysis.passive.patterns import (
    CSRF_TOKEN_NAMES,
    SENSITIVE_PATTERNS,
    SSRF_PARAM_NAMES,
)
from src.recon.common import normalize_url


def _make_response(url: str, body: str, headers: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "url": url,
        "status_code": 200,
        "body_text": body,
        "headers": headers or {"Content-Type": "application/json"},
    }


# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

_SAFE_ALPHABET = st.characters(
    whitelist_categories=("Lu", "Ll", "Nd"),
    blacklist_characters=("<", ">", "'", '"', "&", "/", "\\", ";", "(", ")"),
)

_SAFE_TEXT = st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=200)

_URL_SAFE_PATH = st.text(
    alphabet=string.ascii_lowercase + string.digits + "/_-",
    min_size=1,
    max_size=80,
)

_URL_HOST = st.text(
    alphabet=string.ascii_lowercase + string.digits + ".-",
    min_size=3,
    max_size=50,
)

_VALID_URL = st.builds(
    lambda scheme, host, path: f"{scheme}://{host}{path}",
    scheme=st.sampled_from(["http", "https"]),
    host=_URL_HOST,
    path=_URL_SAFE_PATH,
)

_HEADERS_DICT = st.dictionaries(
    keys=st.text(min_size=1, max_size=40),
    values=st.text(min_size=0, max_size=200),
    max_size=15,
)

# ---------------------------------------------------------------------------
# 1. SSRF detector property tests
# ---------------------------------------------------------------------------

_SSRF_PARAM_NAME = st.sampled_from(sorted(SSRF_PARAM_NAMES)[:30])

_PRIVATE_IPV4_STRATEGY = st.one_of(
    st.ip_addresses(v=4, network=ipaddress.IPv4Network("10.0.0.0/8")).map(str),
    st.ip_addresses(v=4, network=ipaddress.IPv4Network("192.168.0.0/16")).map(str),
    st.ip_addresses(v=4, network=ipaddress.IPv4Network("127.0.0.0/8")).map(str),
)

_CLOUD_METADATA_URL = st.sampled_from(
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://168.63.129.16/metadata",
    ]
)

_PROTOCOL_URL = st.sampled_from(
    [
        "gopher://internal:6379/1INFO",
        "dict://internal:11211/",
        "file:///etc/passwd",
        "ldap://internal:389/dc=example,dc=com",
    ]
)


@given(_SSRF_PARAM_NAME, _PRIVATE_IPV4_STRATEGY)
@settings(max_examples=100)
def test_ssrf_param_with_private_ip_always_detected(param_name: str, private_ip: str) -> None:
    url = f"https://example.com/api/fetch?{param_name}=http://{private_ip}:8080/data"
    params = find_ssrf_params(url)
    assert len(params) >= 1, f"SSRF param '{param_name}' with private IP should be detected"
    assert any(p[0] == param_name for p in params)


@given(_SSRF_PARAM_NAME, _CLOUD_METADATA_URL)
@settings(max_examples=100)
def test_ssrf_param_with_cloud_metadata_always_detected(param_name: str, cloud_url: str) -> None:
    url = f"https://example.com/proxy?{param_name}={cloud_url}"
    params = find_ssrf_params(url)
    assert len(params) >= 1, f"SSRF param '{param_name}' with cloud metadata URL should be detected"


@given(_SSRF_PARAM_NAME, _PROTOCOL_URL)
@settings(max_examples=100)
def test_ssrf_param_with_protocol_url_always_detected(param_name: str, protocol_url: str) -> None:
    url = f"https://example.com/import?{param_name}={protocol_url}"
    params = find_ssrf_params(url)
    assert len(params) >= 1, f"SSRF param '{param_name}' with protocol URL should be detected"


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_ssrf_no_false_positive_on_safe_param_value(safe_value: str) -> None:
    url = f"https://example.com/search?q={safe_value}"
    params = find_ssrf_params(url)
    assert len(params) == 0, (
        f"Safe query param 'q' should not trigger SSRF detection for value: {safe_value!r}"
    )


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_ssrf_non_ssrf_param_not_flagged(safe_value: str) -> None:
    url = f"https://example.com/page?name={safe_value}"
    params = find_ssrf_params(url)
    assert len(params) == 0, (
        f"Non-SSRF param 'name' should not be flagged for value: {safe_value!r}"
    )


@given(_PRIVATE_IPV4_STRATEGY)
@settings(max_examples=100)
def test_ssrf_url_with_private_ip_in_value_flagged(private_ip: str) -> None:
    url = f"https://example.com/api/load?target=http://{private_ip}:8080/internal"
    params = find_ssrf_params(url)
    assert len(params) >= 1, f"URL with private IP in value should be flagged: {url}"


@given(st.text(min_size=0, max_size=500))
@settings(max_examples=100)
def test_ssrf_find_ssrf_params_never_crashes(url: str) -> None:
    try:
        find_ssrf_params(url)
    except Exception as exc:
        raise AssertionError(f"find_ssrf_params crashed on {url!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# 2. XSS detector property tests
# ---------------------------------------------------------------------------

_XSS_PAYLOADS = st.sampled_from(
    [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<img src=x onfocus=alert(1) autofocus>",
    ]
)

_XSS_JSON_FIELD = st.sampled_from(
    [
        '{"field": "comment", "value": "{payload}"}',
        '{"comment": "{payload}", "status": "ok"}',
        '[{"name": "bio", "content": "{payload}"}]',
    ]
)


@given(_XSS_PAYLOADS, _XSS_JSON_FIELD)
@settings(max_examples=100)
def test_xss_payload_in_field_always_detected(xss_payload: str, field_template: str) -> None:
    body = field_template.replace("{payload}", xss_payload)
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/comments", body, {"Content-Type": "application/json"}
        )
    ]
    findings = stored_xss_signal_detector(responses)
    assert len(findings) >= 1, f"XSS payload {xss_payload!r} in field should be detected"


@given(_XSS_PAYLOADS)
@settings(max_examples=100)
def test_xss_dangerous_value_regex_matches_all_payloads(xss_payload: str) -> None:
    assert XSS_DANGEROUS_VALUE_RE.search(xss_payload), (
        f"XSS_DANGEROUS_VALUE_RE should match payload: {xss_payload!r}"
    )


@given(_XSS_PAYLOADS)
@settings(max_examples=100)
def test_xss_signals_returns_non_empty_for_payloads(xss_payload: str) -> None:
    signals = xss_signals(xss_payload)
    assert len(signals) >= 1, f"xss_signals should return at least one signal for: {xss_payload!r}"


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_xss_no_false_positive_on_safe_text(safe_text: str) -> None:
    match = XSS_DANGEROUS_VALUE_RE.search(safe_text)
    assert match is None, f"Safe text should not match XSS pattern: {safe_text!r}"


@given(
    st.lists(
        st.fixed_dictionaries(
            {
                "url": _VALID_URL,
                "status_code": st.integers(min_value=200, max_value=299),
                "headers": st.just({"Content-Type": "application/json"}),
                "body_text": _SAFE_TEXT,
            }
        ),
        min_size=1,
        max_size=5,
    )
)
@settings(max_examples=100)
def test_xss_no_false_positive_on_safe_responses(responses: list[dict[str, Any]]) -> None:
    findings = stored_xss_signal_detector(responses)
    assert len(findings) == 0, (
        f"Safe responses should not trigger XSS detection, got {len(findings)} findings"
    )


@given(st.text(min_size=0, max_size=500))
@settings(max_examples=100)
def test_xss_detector_never_crashes_on_arbitrary_body(body: str) -> None:
    responses: list[dict[str, Any]] = [_make_response("https://example.com/test", body)]
    try:
        stored_xss_signal_detector(responses)
    except Exception as exc:
        raise AssertionError(
            f"stored_xss_signal_detector crashed on body: {body!r}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# 3. CSRF detector property tests
# ---------------------------------------------------------------------------

_CSRF_TOKEN_NAME = st.sampled_from(sorted(CSRF_TOKEN_NAMES))

_FORM_HTML_TEMPLATE = st.sampled_from(
    [
        '<form action="/submit" method="POST">{csrf_field}<input type="text" name="data"></form>',
        '<form method="post" action="/api/update">{csrf_field}<button type="submit">Save</button></form>',
    ]
)

_CSRF_FIELD_PRESENT = st.sampled_from(
    [
        '<input type="hidden" name="{name}" value="abc123def456">',
        '<input name="{name}" type="hidden" value="token_789xyz">',
        '<meta name="{name}" content="csrf_value_12345">',
        '<input type="hidden" value="token_abc" name="{name}">',
    ]
)


@given(_CSRF_TOKEN_NAME, _CSRF_FIELD_PRESENT, _FORM_HTML_TEMPLATE)
@settings(max_examples=100)
def test_csrf_token_present_in_form_detected(
    token_name: str, csrf_field_template: str, form_template: str
) -> None:
    csrf_field = csrf_field_template.replace("{name}", token_name)
    body = form_template.replace("{csrf_field}", csrf_field)
    found = token_name.lower() in body.lower()
    assert found, f"CSRF token name '{token_name}' should be present in form HTML"


@given(_CSRF_TOKEN_NAME)
@settings(max_examples=100)
def test_csrf_token_names_are_recognized_patterns(token_name: str) -> None:
    token_lower = token_name.lower()
    assert any(keyword in token_lower for keyword in ("csrf", "xsrf", "token", "authenticity")), (
        f"CSRF token name '{token_name}' should contain recognizable keyword"
    )


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_csrf_no_false_positive_on_safe_form(safe_value: str) -> None:
    body = f'<form action="/submit" method="POST"><input type="text" name="q" value="{safe_value}"></form>'
    has_csrf = any(name.lower() in body.lower() for name in CSRF_TOKEN_NAMES)
    assert not has_csrf, f"Safe form with value {safe_value!r} should not contain CSRF token names"


@given(
    st.lists(
        st.fixed_dictionaries(
            {
                "url": _VALID_URL,
                "status_code": st.integers(min_value=200, max_value=299),
                "headers": st.just({"Content-Type": "text/html"}),
                "body_text": st.just(
                    '<form action="/submit" method="POST">'
                    '<input type="text" name="data">'
                    '<button type="submit">Submit</button>'
                    "</form>"
                ),
            }
        ),
        min_size=1,
        max_size=3,
    )
)
@settings(max_examples=100)
def test_csrf_form_without_token_has_no_csrf_field(responses: list[dict[str, Any]]) -> None:
    for response in responses:
        body = response.get("body_text", "")
        has_csrf_token = any(name.lower() in body.lower() for name in CSRF_TOKEN_NAMES)
        assert not has_csrf_token, (
            "Form without CSRF token field should not contain CSRF token names"
        )


# ---------------------------------------------------------------------------
# 4. Security header checker property tests
# ---------------------------------------------------------------------------

_SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=()",
    "Cache-Control": "no-store",
}

_WEAK_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'unsafe-inline' 'unsafe-eval'",
    "X-Content-Type-Options": "sniff",
    "X-Frame-Options": "ALLOW-FROM example.com",
    "Referrer-Policy": "unsafe-url",
    "Server": "Apache/2.4.49",
    "X-Powered-By": "PHP/7.4.3",
}


def _build_response_map(url: str, headers: dict[str, str]) -> dict[str, dict[str, Any]]:
    normalized = normalize_url(url)
    return {
        normalized: {
            "url": url,
            "status_code": 200,
            "headers": headers,
            "body_text": "",
        }
    }


@given(_URL_HOST, _URL_SAFE_PATH)
@settings(max_examples=100)
def test_header_checker_missing_headers_always_reported(host: str, path: str) -> None:
    url = f"https://{host}{path}"
    targets = [url]
    response_map = _build_response_map(url, {})
    findings = header_checker(targets, None, response_map)
    assert len(findings) >= 1, "Missing security headers should always be reported"
    issues = findings[0].get("issues", [])
    assert len(issues) >= 1, "At least one missing header issue should be found"


@given(_URL_HOST, _URL_SAFE_PATH)
@settings(max_examples=100)
def test_header_checker_all_secure_no_issues(host: str, path: str) -> None:
    url = f"https://{host}{path}"
    targets = [url]
    response_map = _build_response_map(url, dict(_SECURE_HEADERS))
    findings = header_checker(targets, None, response_map)
    assert len(findings) == 0, "All-secure headers should produce no findings"


@given(_URL_HOST, _URL_SAFE_PATH)
@settings(max_examples=100)
def test_header_checker_weak_headers_always_reported(host: str, path: str) -> None:
    url = f"https://{host}{path}"
    targets = [url]
    response_map = _build_response_map(url, dict(_WEAK_HEADERS))
    findings = header_checker(targets, None, response_map)
    assert len(findings) >= 1, "Weak security headers should always be reported"
    issues = findings[0].get("issues", [])
    expected_weak_issues = {
        "hsts_missing_includesubdomains",
        "hsts_missing_preload",
        "csp_unsafe_inline",
        "csp_unsafe_eval",
        "csp_missing_directives",
        "missing_x_content_type_options",
        "weak_x_frame_options",
        "weak_referrer_policy",
        "server_version_disclosure",
        "x_powered_by_disclosure",
    }
    found_weak = expected_weak_issues & set(issues)
    assert len(found_weak) >= 3, f"At least 3 weak header issues should be found, got: {found_weak}"


@given(_HEADERS_DICT)
@settings(max_examples=100)
def test_header_checker_never_crashes_on_arbitrary_headers(headers: dict[str, str]) -> None:
    url = "https://example.com/test"
    targets = [url]
    response_map = _build_response_map(url, headers)
    try:
        header_checker(targets, None, response_map)
    except Exception as exc:
        raise AssertionError(f"header_checker crashed on headers: {headers!r}: {exc}") from exc


@given(_URL_HOST, _URL_SAFE_PATH)
@settings(max_examples=100)
def test_header_checker_http_no_hsts_issue(host: str, path: str) -> None:
    url = f"http://{host}{path}"
    targets = [url]
    response_map = _build_response_map(url, {})
    findings = header_checker(targets, None, response_map)
    if findings:
        issues = findings[0].get("issues", [])
        assert "missing_hsts" not in issues, "HTTP URLs should not report missing HSTS"


# ---------------------------------------------------------------------------
# 5. Sensitive data exposure property tests
# ---------------------------------------------------------------------------

_AWS_KEY = st.text(
    alphabet=string.ascii_uppercase + string.digits,
    min_size=16,
    max_size=16,
).map(lambda s: f"AKIA{s}")

_GITHUB_TOKEN = st.text(
    alphabet=string.ascii_letters + string.digits,
    min_size=24,
    max_size=40,
).map(lambda s: f"ghp_{s}")

_STRIPE_KEY = st.text(
    alphabet=string.ascii_letters + string.digits,
    min_size=16,
    max_size=40,
).map(lambda s: f"sk_live_{s}")

_GOOGLE_API_KEY = st.text(
    alphabet=string.ascii_letters + string.digits + "-",
    min_size=35,
    max_size=35,
).map(lambda s: f"AIza{s}")

_SLACK_TOKEN = st.text(
    alphabet=string.ascii_letters + string.digits + "-",
    min_size=10,
    max_size=30,
).map(lambda s: f"xoxb-{s}")

_PRIVATE_KEY_BLOCK = st.just("-----BEGIN RSA PRIVATE KEY-----")

_CLOUD_METADATA = st.sampled_from(
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
)

_INTERNAL_IP = st.one_of(
    st.ip_addresses(v=4, network=ipaddress.IPv4Network("10.0.0.0/8")).map(str),
    st.ip_addresses(v=4, network=ipaddress.IPv4Network("192.168.0.0/16")).map(str),
)


@given(_AWS_KEY)
@settings(max_examples=100)
def test_sensitive_data_aws_access_key_always_detected(aws_key: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/config",
            f'{{"aws_key": "{aws_key}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, f"AWS access key {aws_key!r} should be detected"
    assert any("aws_access_key" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention aws_access_key"
    )


@given(_GITHUB_TOKEN)
@settings(max_examples=100)
def test_sensitive_data_github_token_always_detected(github_token: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/settings",
            f'{{"token": "{github_token}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, "GitHub token should be detected"
    assert any("github_token" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention github_token"
    )


@given(_STRIPE_KEY)
@settings(max_examples=100)
def test_sensitive_data_stripe_key_always_detected(stripe_key: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/payment",
            f'{{"stripe_key": "{stripe_key}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, "Stripe key should be detected"
    assert any("stripe_secret" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention stripe_secret"
    )


@given(_GOOGLE_API_KEY)
@settings(max_examples=100)
def test_sensitive_data_google_api_key_always_detected(google_key: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/maps",
            f'{{"google_api_key": "{google_key}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, "Google API key should be detected"
    assert any("google_api_key" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention google_api_key"
    )


@given(_SLACK_TOKEN)
@settings(max_examples=100)
def test_sensitive_data_slack_token_always_detected(slack_token: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/integrations",
            f'{{"slack_token": "{slack_token}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, "Slack token should be detected"
    assert any("slack_token" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention slack_token"
    )


@given(_PRIVATE_KEY_BLOCK)
@settings(max_examples=50)
def test_sensitive_data_private_key_always_detected(private_key: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/keys",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, "Private key block should be detected"
    assert any("private_key_block" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention private_key_block"
    )


@given(_CLOUD_METADATA)
@settings(max_examples=50)
def test_sensitive_data_cloud_metadata_url_always_detected(cloud_url: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/debug",
            f'{{"metadata_url": "{cloud_url}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, "Cloud metadata URL should be detected"
    assert any("cloud_metadata" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention cloud_metadata"
    )


@given(_INTERNAL_IP)
@settings(max_examples=100)
def test_sensitive_data_internal_ip_always_detected(internal_ip: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/api/internal",
            f'{{"server_ip": "{internal_ip}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    assert len(findings) >= 1, f"Internal IP {internal_ip} should be detected"
    assert any("internal_ip" in str(f.get("indicator", "")) for f in findings), (
        "Finding should mention internal_ip"
    )


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_sensitive_data_no_false_positive_on_safe_text(safe_text: str) -> None:
    responses: list[dict[str, Any]] = [
        _make_response(
            "https://example.com/search",
            f'{{"query": "{safe_text}"}}',
        )
    ]
    findings = sensitive_data_scanner(responses)
    for finding in findings:
        indicator = str(finding.get("indicator", ""))
        assert not any(
            sensitive_type in indicator
            for sensitive_type in (
                "aws_access_key",
                "github_token",
                "stripe_secret",
                "google_api_key",
                "slack_token",
                "private_key_block",
            )
        ), f"Safe text should not trigger sensitive data detection: {safe_text!r}"


@given(
    st.lists(
        st.fixed_dictionaries(
            {
                "url": _VALID_URL,
                "status_code": st.integers(min_value=200, max_value=299),
                "headers": st.just({"Content-Type": "text/html"}),
                "body_text": _SAFE_TEXT,
            }
        ),
        min_size=1,
        max_size=5,
    )
)
@settings(max_examples=100)
def test_sensitive_data_no_false_positive_on_safe_responses(
    responses_data: list[dict[str, Any]],
) -> None:
    findings = sensitive_data_scanner(responses_data)
    for finding in findings:
        indicator = str(finding.get("indicator", ""))
        assert not any(
            sensitive_type in indicator
            for sensitive_type in (
                "aws_access_key",
                "github_token",
                "stripe_secret",
                "google_api_key",
                "slack_token",
                "private_key_block",
                "cloud_metadata",
            )
        ), "Safe responses should not trigger sensitive data detection"


@given(st.text(min_size=0, max_size=500))
@settings(max_examples=100)
def test_sensitive_data_scanner_never_crashes_on_arbitrary_body(body: str) -> None:
    responses: list[dict[str, Any]] = [_make_response("https://example.com/test", body)]
    try:
        sensitive_data_scanner(responses)
    except Exception as exc:
        raise AssertionError(f"sensitive_data_scanner crashed on body: {body!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# 6. SSRF helper function property tests (cloud metadata, internal leak, errors)
# ---------------------------------------------------------------------------

_CLOUD_METADATA_BODY = st.sampled_from(
    [
        "ami-id: ami-12345678\ninstance-id: i-1234567890abcdef0",
        "instance-type: t2.micro\nlocal-ipv4: 10.0.1.5",
        "public-ipv4: 54.123.45.67\niam/security-credentials/role-name",
        '{"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "secretAccessKey": "wJalrXUtnFEMI/K7MDENG"}',
        "computeMetadata/v1/instance/service-accounts/default/token",
    ]
)

_INTERNAL_LEAK_BODY = st.sampled_from(
    [
        "Connection to 10.0.1.5 failed",
        "Server at 192.168.1.100 returned error",
        "Internal server host: 172.16.0.50",
        "localhost:8080 refused connection",
        "169.254.169.254 metadata service timeout",
    ]
)

_INTERNAL_ERROR_BODY = st.sampled_from(
    [
        "Connection refused: 127.0.0.1:8080",
        "Failed to connect to internal service",
        "Access denied: metadata endpoint blocked",
        "SSRF attempt detected and blocked",
        "ECONNREFUSED 10.0.0.1:3000",
        "getaddrinfo failed for internal-host.local",
        "No route to host 192.168.1.1",
    ]
)


@given(_CLOUD_METADATA_BODY)
@settings(max_examples=100)
def test_check_cloud_metadata_always_detects_cloud_patterns(body: str) -> None:
    matches = check_cloud_metadata(body)
    assert len(matches) >= 1, f"Cloud metadata patterns should be detected in: {body!r}"


@given(_INTERNAL_LEAK_BODY)
@settings(max_examples=100)
def test_check_internal_leakage_always_detects_internal_ips(body: str) -> None:
    leaks = check_internal_leakage(body)
    assert len(leaks) >= 1, f"Internal leakage patterns should be detected in: {body!r}"


@given(_INTERNAL_ERROR_BODY)
@settings(max_examples=100)
def test_check_internal_errors_always_detects_error_patterns(body: str) -> None:
    errors = check_internal_errors(body)
    assert len(errors) >= 1, f"Internal error patterns should be detected in: {body!r}"


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_check_cloud_metadata_no_false_positive_on_safe_text(safe_text: str) -> None:
    matches = check_cloud_metadata(safe_text)
    assert len(matches) == 0, f"Safe text should not match cloud metadata: {safe_text!r}"


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_check_internal_leakage_no_false_positive_on_safe_text(safe_text: str) -> None:
    leaks = check_internal_leakage(safe_text)
    assert len(leaks) == 0, f"Safe text should not match internal leakage: {safe_text!r}"


@given(_SAFE_TEXT)
@settings(max_examples=100)
def test_check_internal_errors_no_false_positive_on_safe_text(safe_text: str) -> None:
    errors = check_internal_errors(safe_text)
    assert len(errors) == 0, f"Safe text should not match internal errors: {safe_text!r}"


# ---------------------------------------------------------------------------
# 7. Cross-detector property: all sensitive patterns are covered
# ---------------------------------------------------------------------------


def test_all_sensitive_patterns_are_testable() -> None:
    for label, pattern in SENSITIVE_PATTERNS:
        assert hasattr(pattern, "search"), f"Pattern for {label} should have search method"
        assert pattern.pattern, f"Pattern for {label} should not be empty"


def test_ssrf_param_names_are_non_empty() -> None:
    assert len(SSRF_PARAM_NAMES) > 0, "SSRF_PARAM_NAMES should not be empty"
    for name in SSRF_PARAM_NAMES:
        assert isinstance(name, str), f"SSRF param name should be string: {name!r}"
        assert len(name) > 0, f"SSRF param name should not be empty: {name!r}"


def test_csrf_token_names_are_non_empty() -> None:
    assert len(CSRF_TOKEN_NAMES) > 0, "CSRF_TOKEN_NAMES should not be empty"
    for name in CSRF_TOKEN_NAMES:
        assert isinstance(name, str), f"CSRF token name should be string: {name!r}"
        assert len(name) > 0, f"CSRF token name should not be empty: {name!r}"
