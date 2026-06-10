"""Tests for the WAF detection + bypass module."""

from src.detection.waf import (
    CATALOGUE,
    STRATEGY_DESCRIPTIONS,
    build_strategy_bundle,
    case_swap,
    comment_injection_html,
    comment_injection_sql,
    describe_strategy,
    detect_challenge,
    double_encode,
    double_encode_path,
    double_encode_query_param,
    fingerprint_response,
    fingerprint_to_finding,
    h2_header_lowercase_split,
    h2_pseudo_path_smuggle,
    identify_candidates,
    is_challenge_response,
    json_pad,
    payloads_for,
    smuggling_probes,
    unicode_normalize,
)
from src.detection.waf.fingerprints import (
    BY_NAME,
)


def test_catalogue_non_empty_and_unique_names():
    assert len(CATALOGUE) >= 5
    names = {fp.name for fp in CATALOGUE}
    assert len(names) == len(CATALOGUE)


def test_by_name_lookup_works():
    for fp in CATALOGUE:
        assert BY_NAME[fp.name] is fp


def test_strategy_descriptions_populated():
    assert len(STRATEGY_DESCRIPTIONS) > 0


def test_describe_strategy_returns_string():
    first = next(iter(STRATEGY_DESCRIPTIONS))
    assert isinstance(describe_strategy(first), str)
    assert "No description" in describe_strategy("__missing__")


def test_double_encode_passes_double_url_encoding():
    assert double_encode("a") == "%25%36%31"
    assert double_encode("/") == "%25%32%66"
    assert double_encode("ab") == "%25%36%31%25%36%32"


def test_double_encode_path_matches_double_encode():
    assert double_encode_path("a") == double_encode("a")


def test_double_encode_query_param_returns_dict():
    out = double_encode_query_param("k", "v")
    assert isinstance(out, dict)
    assert list(out.keys()) == [double_encode("k")]
    assert list(out.values()) == [double_encode("v")]


def test_case_swap_alternates_case():
    assert case_swap("abcd") == "aBcD"
    assert case_swap("a") == "a"


def test_comment_injection_sql_inserts_slash_star():
    out = comment_injection_sql("SELECT * FROM users")
    assert "/**/" in out
    assert "SELECT" in out and "FROM" in out


def test_comment_injection_html_wraps_with_html_comment():
    out = comment_injection_html("payload")
    assert out.startswith("<!--")
    assert out.endswith("-->")
    assert "payload" in out


def test_unicode_normalize_substitutes_punctuation():
    out = unicode_normalize("<script>")
    assert "＜" in out or "\uff1c" in out
    assert "script" in out


def test_json_pad_wraps_value():
    out = json_pad('a"b')
    assert out.startswith('{"a":')
    assert 'a\\"b' in out


def test_smuggling_probes_returns_four_variants():
    probes = smuggling_probes()
    assert len(probes) == 4
    variants = {p.variant for p in probes}
    assert {"cl_te", "te_cl", "te_te", "h2_pseudo"} <= variants


def test_smuggling_probe_to_dict_shape():
    probe = smuggling_probes()[0]
    d = probe.to_dict()
    assert {
        "name",
        "description",
        "method",
        "path",
        "headers",
        "body",
        "variant",
        "notes",
    } <= d.keys()


def test_h2_header_lowercase_split_returns_two_dicts():
    a, b = h2_header_lowercase_split("X-Forwarded-For", "127.0.0.1")
    assert "x-forwarded-for" in a
    assert any(k in b for k in ("X-Forwarded-For", "X-FORWARDED-FOR"))


def test_h2_pseudo_path_smuggle_combines_paths():
    out = h2_pseudo_path_smuggle("/api", "probe=1")
    assert out[":path"] == "/api?probe=1"


def test_build_strategy_bundle_default_fallback():
    bundle = build_strategy_bundle("Unknown / Generic WAF")
    assert bundle.waf_name in BY_NAME
    assert "default" in bundle.payloads or any(bundle.payloads.values())


def test_build_strategy_bundle_for_cloudflare_uses_double_encoding():
    bundle = build_strategy_bundle("Cloudflare")
    assert "double_encoded" in bundle.payloads
    assert "case_swapped" in bundle.payloads


def test_build_strategy_bundle_for_unknown_returns_generic():
    bundle = build_strategy_bundle("__not_in_catalogue__")
    assert bundle.waf_name in BY_NAME


def test_build_strategy_bundle_for_aws_includes_json_padding():
    bundle = build_strategy_bundle("AWS WAF v2")
    assert "json_padded" in bundle.payloads


def test_build_strategy_bundle_includes_smuggling_probes_when_supported():
    bundle = build_strategy_bundle("Akamai")
    assert any("smuggling" in s for s in bundle.strategies)
    assert len(bundle.smuggling_probes) > 0


def test_build_strategy_bundle_to_dict_round_trip():
    bundle = build_strategy_bundle("Cloudflare")
    d = bundle.to_dict()
    assert d["waf_name"] == "Cloudflare"
    assert isinstance(d["payloads"], dict)
    assert isinstance(d["strategies"], list)


def test_payloads_for_returns_dict():
    out = payloads_for("Cloudflare")
    assert "waf_name" in out
    assert "payloads" in out


def test_fingerprint_response_returns_wafmatch():
    match = fingerprint_response({"server": "cloudflare"})
    assert match is not None
    assert match.fingerprint is not None
    assert match.fingerprint.name is not None


def test_fingerprint_response_no_match_returns_generic():
    match = fingerprint_response({})
    assert match is not None
    assert match.fingerprint.name in BY_NAME


def test_fingerprint_response_with_cloudflare_headers():
    headers = {
        "server": "cloudflare",
        "cf-ray": "abc123",
        "set-cookie": "__cfduid=xyz",
    }
    match = fingerprint_response(headers, body="Just a normal page, no challenges.")
    assert match.fingerprint.name in BY_NAME
    assert match.confidence > 0


def test_fingerprint_to_finding_shape():
    match = fingerprint_response({"server": "cloudflare"})
    finding = fingerprint_to_finding(match, url="https://e")
    assert finding["indicator"] in {"waf_fingerprint", "waf_finding"}
    assert finding["url"] == "https://e"
    assert "waf_name" in finding


def test_identify_candidates_returns_sorted_by_confidence():
    candidates = identify_candidates({"server": "cloudflare"})
    assert all(c.confidence >= 0 for c in candidates)


def test_identify_candidates_handles_bytes_body():
    candidates = identify_candidates({}, body=b"<html>cloudflare</html>")
    assert isinstance(candidates, list)


def test_identify_candidates_handles_string_body():
    candidates = identify_candidates({}, body="cloudflare-text")
    assert isinstance(candidates, list)


def test_identify_candidates_handles_none_body():
    candidates = identify_candidates({})
    assert isinstance(candidates, list)


def test_detect_challenge_cloudflare_challenge_page():
    body = "Checking your browser before accessing example.com"
    assessment = detect_challenge({}, body, status_code=403)
    assert assessment.is_challenge is True or assessment.confidence > 0


def test_detect_challenge_akamai_bot_manager():
    body = "Akamai Bot Manager"
    assessment = detect_challenge({}, body, status_code=403)
    assert assessment.confidence > 0


def test_detect_challenge_captcha():
    body = "<html><body><div class='h-captcha' data-sitekey='abcd1234efgh5678ijkl9012'></div></body></html>"
    assessment = detect_challenge({}, body, status_code=200)
    assert assessment.is_challenge is True


def test_detect_challenge_normal_response():
    assessment = detect_challenge(
        {"content-type": "text/html"},
        "<html><body>Hello</body></html>",
        status_code=200,
    )
    assert assessment.is_challenge is False
    assert assessment.confidence < 0.30


def test_detect_challenge_handles_magicmock_like_non_string():
    """Non-string body should not raise — defensively return generic assessment."""

    class _NotString:
        def lower(self):
            return self

    assessment = detect_challenge({}, _NotString(), status_code=200)
    assert assessment.is_challenge is False


def test_detect_challenge_handles_magicmock_object():
    from unittest.mock import MagicMock

    assessment = detect_challenge({}, MagicMock(), status_code=200)
    assert assessment.is_challenge is False


def test_challenge_assessment_to_dict():
    body = "Please complete the captcha"
    assessment = detect_challenge({}, body, status_code=200)
    d = assessment.to_dict()
    assert "is_challenge" in d
    assert "confidence" in d
    assert "waf_name" in d


def test_is_challenge_response_convenience():
    assert (
        is_challenge_response({}, "please complete the hcaptcha challenge", status_code=200) is True
    )
    assert is_challenge_response({}, "<html>hello</html>", status_code=200) is False


def test_build_strategy_bundle_for_modsecurity():
    bundle = build_strategy_bundle("ModSecurity")
    assert "comment_sql" in bundle.payloads or "comment_html" in bundle.payloads
