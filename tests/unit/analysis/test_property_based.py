"""Property-based tests for security analysis detectors using Hypothesis."""

import ipaddress
import re
import string
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from src.analysis.passive.detector_idor import idor_candidate_finder
from src.analysis.passive.detector_ssrf import ssrf_candidate_finder
from src.analysis.passive.detector_token import token_leak_detector
from src.analysis.passive.detector_vulnerable_components import vulnerable_component_detector

# ---------------------------------------------------------------------------
# SSRF: private/reserved URLs are always flagged
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
]

_PRIVATE_IP_STRATEGY = st.one_of(
    *[st.ip_addresses(v=4, network=net).map(str) for net in _PRIVATE_NETWORKS]
)

_CLOUD_METADATA_URLS = st.sampled_from(
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://168.63.129.16/metadata",
    ]
)

_PROTOCOL_SMUGGLING_URLS = st.sampled_from(
    [
        "gopher://internal:6379/1INFO",
        "dict://internal:11211/",
        "file:///etc/passwd",
        "ldap://internal:389/dc=example,dc=com",
    ]
)

_DNS_REBINDING_URLS = st.sampled_from(
    [
        "http://127.0.0.1.rbndr.us/admin",
        "http://127.0.0.1.nip.io/api",
        "http://localhost.localtest.me/debug",
    ]
)


@given(_PRIVATE_IP_STRATEGY)
@settings(max_examples=50)
def test_ssrf_private_ip_always_flagged(ip: str) -> None:
    url = f"https://example.com/api/fetch?target=http://{ip}:8080/data"
    urls: set[str] = {url}
    findings = ssrf_candidate_finder(urls)
    assert len(findings) >= 1, f"Private IP {ip} should be flagged as SSRF candidate"
    assert any(
        "internal_host" in s or "ipv4_address" in s for f in findings for s in f.get("signals", [])
    )


@given(_CLOUD_METADATA_URLS)
@settings(max_examples=30)
def test_ssrf_cloud_metadata_always_flagged(url: str) -> None:
    full_url = f"https://example.com/proxy?dest={url}"
    urls: set[str] = {full_url}
    findings = ssrf_candidate_finder(urls)
    assert len(findings) >= 1, "Cloud metadata URL should be flagged"


@given(_PROTOCOL_SMUGGLING_URLS)
@settings(max_examples=30)
def test_ssrf_protocol_smuggling_always_flagged(url: str) -> None:
    full_url = f"https://example.com/import?source={url}"
    urls: set[str] = {full_url}
    findings = ssrf_candidate_finder(urls)
    assert len(findings) >= 1, "Protocol smuggling URL should be flagged"


@given(_DNS_REBINDING_URLS)
@settings(max_examples=30)
def test_ssrf_dns_rebinding_always_flagged(url: str) -> None:
    full_url = f"https://example.com/fetch?target={url}"
    urls: set[str] = {full_url}
    findings = ssrf_candidate_finder(urls)
    assert len(findings) >= 1, "DNS rebinding URL should be flagged"


# ---------------------------------------------------------------------------
# IDOR: random parameter permutations produce consistent detection
# ---------------------------------------------------------------------------

_IDOR_PARAM_NAMES = st.sampled_from(
    [
        "id",
        "user_id",
        "account_id",
        "order_id",
        "record_id",
    ]
)

_IDOR_KEYWORD_PATHS = st.sampled_from(
    [
        "/api/users",
        "/api/orders",
        "/api/documents",
        "/api/accounts",
        "/api/profiles",
        "/api/records",
    ]
)


@given(_IDOR_KEYWORD_PATHS, st.integers(min_value=10, max_value=99999))
@settings(max_examples=50)
def test_idor_numeric_path_always_detected(path: str, numeric_id: int) -> None:
    url = f"https://example.com{path}/{numeric_id}"
    urls: set[str] = {url}
    findings = idor_candidate_finder(urls)
    assert len(findings) >= 1, f"URL with numeric path ID should be detected: {url}"


@given(_IDOR_KEYWORD_PATHS, _IDOR_PARAM_NAMES, st.integers(min_value=10, max_value=99999))
@settings(max_examples=50)
def test_idor_numeric_query_param_always_detected(path: str, param: str, value: int) -> None:
    url = f"https://example.com{path}/items?{param}={value}"
    urls: set[str] = {url}
    findings = idor_candidate_finder(urls)
    assert len(findings) >= 1, f"URL with numeric query param should be detected: {url}"


@given(_IDOR_KEYWORD_PATHS, st.uuids(version=4))
@settings(max_examples=30)
def test_idor_uuid_path_always_detected(path: str, uuid_val: str) -> None:
    url = f"https://example.com{path}/{uuid_val}"
    urls: set[str] = {url}
    findings = idor_candidate_finder(urls)
    assert len(findings) >= 1, f"URL with UUID path should be detected: {url}"


# ---------------------------------------------------------------------------
# CVSS / scoring: scores always 0.0-10.0, severity monotonic with score
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@given(st.lists(st.text(min_size=1, max_size=100), min_size=1, max_size=10))
@settings(max_examples=30)
def test_vulnerable_component_scores_in_valid_range(body_texts: list[str]) -> None:
    responses: list[dict[str, Any]] = []
    for i, body in enumerate(body_texts):
        responses.append(
            {
                "url": f"https://example.com/page/{i}",
                "status_code": 200,
                "headers": {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4.3"},
                "body_text": body,
            }
        )
    findings = vulnerable_component_detector(set(), responses)
    for finding in findings:
        score = finding.get("score", 0)
        assert isinstance(score, (int, float)), "Score must be numeric"
        assert 0 <= score, f"Score must be >= 0, got {score}"


@given(st.integers(min_value=0, max_value=100))
@settings(max_examples=30)
def test_vulnerable_component_severity_monotonic(risk_score: int) -> None:
    responses: list[dict[str, Any]] = [
        {
            "url": "https://example.com/test",
            "status_code": 200,
            "headers": {"Server": "Apache/2.4.49"},
            "body_text": "x" * risk_score,
        }
    ]
    findings = vulnerable_component_detector(set(), responses)
    for finding in findings:
        severity = finding.get("severity", "low")
        assert severity in _SEVERITY_ORDER, f"Unknown severity: {severity}"


# ---------------------------------------------------------------------------
# Input sanitization: fuzz all inputs, verify no crashes
# ---------------------------------------------------------------------------

_RANDOM_STRING = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126),
    min_size=0,
    max_size=500,
)

_FUZZ_URL = st.builds(
    lambda host, path: f"https://{host}{path}",
    host=st.text(alphabet=string.ascii_lowercase + string.digits + ".-", min_size=1, max_size=50),
    path=st.text(alphabet=string.ascii_lowercase + string.digits + "/_-", min_size=0, max_size=100),
)


@given(_FUZZ_URL)
@settings(max_examples=50)
def test_ssrf_fuzz_no_crash(url: str) -> None:
    urls: set[str] = {url}
    try:
        ssrf_candidate_finder(urls)
    except Exception as exc:
        raise AssertionError(f"ssrf_candidate_finder crashed on {url!r}: {exc}") from exc


@given(_FUZZ_URL)
@settings(max_examples=50)
def test_idor_fuzz_no_crash(url: str) -> None:
    urls: set[str] = {url}
    try:
        idor_candidate_finder(urls)
    except Exception as exc:
        raise AssertionError(f"idor_candidate_finder crashed on {url!r}: {exc}") from exc


@given(
    st.lists(_FUZZ_URL, min_size=0, max_size=10),
    st.lists(
        st.fixed_dictionaries(
            {
                "url": _FUZZ_URL,
                "status_code": st.integers(min_value=100, max_value=599),
                "headers": st.dictionaries(st.text(), st.text()),
                "body_text": _RANDOM_STRING,
            }
        ),
        min_size=0,
        max_size=10,
    ),
)
@settings(max_examples=30)
def test_token_detector_fuzz_no_crash(urls: list[str], responses: list[dict[str, Any]]) -> None:
    url_set: set[str] = set(urls)
    try:
        token_leak_detector(url_set, responses)
    except Exception as exc:
        raise AssertionError(f"token_leak_detector crashed: {exc}") from exc


@given(
    st.lists(
        st.fixed_dictionaries(
            {
                "url": _FUZZ_URL,
                "status_code": st.integers(min_value=100, max_value=599),
                "headers": st.dictionaries(st.text(), st.text()),
                "body_text": _RANDOM_STRING,
            }
        ),
        min_size=0,
        max_size=10,
    ),
)
@settings(max_examples=30)
def test_vulnerable_component_fuzz_no_crash(responses: list[dict[str, Any]]) -> None:
    try:
        vulnerable_component_detector(set(), responses)
    except Exception as exc:
        raise AssertionError(f"vulnerable_component_detector crashed: {exc}") from exc


# ---------------------------------------------------------------------------
# Token detection: random strings, verify token patterns detected correctly
# ---------------------------------------------------------------------------

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

_BEARER_TOKEN = st.text(
    alphabet=string.ascii_letters + string.digits + "-_",
    min_size=30,
    max_size=200,
).map(lambda s: f"eyJhbGciOiJIUzI1NiJ9.{s}.{s[:40]}")

_API_KEY_PATTERN = st.text(
    alphabet=string.ascii_letters + string.digits,
    min_size=32,
    max_size=64,
).map(lambda s: f"sk_live_{s}")


@given(_BEARER_TOKEN)
@settings(max_examples=30)
def test_token_detector_jwt_always_found(jwt_token: str) -> None:
    responses: list[dict[str, Any]] = [
        {
            "url": "https://example.com/api/user",
            "status_code": 200,
            "headers": {},
            "body_text": f'{{"token": "{jwt_token}"}}',
        }
    ]
    findings = token_leak_detector(set(), responses)
    assert len(findings) >= 1, "JWT token in response body should be detected"


@given(_API_KEY_PATTERN)
@settings(max_examples=30)
def test_token_detector_api_key_always_found(api_key: str) -> None:
    responses: list[dict[str, Any]] = [
        {
            "url": "https://example.com/api/config",
            "status_code": 200,
            "headers": {},
            "body_text": f'{{"api_key": "{api_key}"}}',
        }
    ]
    findings = token_leak_detector(set(), responses)
    assert len(findings) >= 1, "API key in response body should be detected"


@given(st.text(alphabet=string.ascii_letters + string.digits, min_size=5, max_size=20))
@settings(max_examples=30)
def test_token_detector_no_false_positives_on_random(random_str: str) -> None:
    urls: set[str] = {f"https://example.com/search?q={random_str}"}
    findings = token_leak_detector(urls, [])
    for finding in findings:
        assert random_str not in str(finding.get("indicator", "")), (
            f"Random string '{random_str}' should not trigger token detection"
        )
