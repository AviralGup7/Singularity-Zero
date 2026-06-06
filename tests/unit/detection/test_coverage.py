
from src.detection.coverage import (
    EXPLOIT_ENGINE_KEYS,
    _cwe_to_engines,
    _url_hint_engines,
    apply_referral,
    filter_actionable,
    group_by_engine,
    is_actionable,
    recommend_engines,
    referral_reasons,
    referral_summary,
)
from src.detection.finding import DetectionFinding, Exploitability, Severity


def _finding(**kwargs):
    base = dict(
        finding_id="F-test",
        url="https://example.com",
        indicator="xss_candidate",
        summary="Reflected value in body",
        severity=Severity.HIGH,
        confidence=0.7,
        exploitability=Exploitability.PROBABLE,
        analyzer_key="ak",
        phase="analyze",
        recommended_engines=(),
        evidence=(),
    )
    base.update(kwargs)
    return DetectionFinding(**base)


def test_exploit_engine_keys_contains_expected_engines():
    assert "injectionengine" in EXPLOIT_ENGINE_KEYS
    assert "ssrfexploitationengine" in EXPLOIT_ENGINE_KEYS
    assert "authbypassengine" in EXPLOIT_ENGINE_KEYS
    assert "raceconditionengine" in EXPLOIT_ENGINE_KEYS


def test_cwe_to_engines_xss_maps_to_injection():
    assert "injectionengine" in _cwe_to_engines("CWE-79")


def test_cwe_to_engines_ssrf_maps_to_ssrf_engine():
    assert "ssrfexploitationengine" in _cwe_to_engines("CWE-918")


def test_cwe_to_engines_path_traversal():
    assert "pathtraversalexploitationengine" in _cwe_to_engines("CWE-22")


def test_cwe_to_engines_deserialization():
    assert "deserializationexploitationengine" in _cwe_to_engines("CWE-502")


def test_cwe_to_engines_returns_empty_for_unknown():
    assert _cwe_to_engines("CWE-9999") == ()


def test_cwe_to_engines_empty_input():
    assert _cwe_to_engines("") == ()
    assert _cwe_to_engines(None) == ()


def test_url_hint_engines_upload_endpoint():
    assert _url_hint_engines("https://api.example.com/upload/file", "") == (
        "fileuploadexploitationengine",
    )


def test_url_hint_engines_ssrf_endpoint():
    assert _url_hint_engines("https://api.example.com/webhook", "") == (
        "ssrfexploitationengine",
    )


def test_url_hint_engines_template_renderer():
    assert _url_hint_engines("https://example.com/render/template", "") == (
        "sstiexploitationengine",
    )


def test_url_hint_engines_payment_checkout_race():
    assert _url_hint_engines("https://example.com/checkout/pay", "") == (
        "raceconditionengine",
    )


def test_url_hint_engines_deserialization_indicator():
    assert _url_hint_engines("https://example.com/", "deserialization") == (
        "deserializationexploitationengine",
    )


def test_url_hint_engines_unknown_returns_empty():
    assert _url_hint_engines("https://example.com/page", "xss") == ()


def test_recommend_engines_uses_explicit_when_provided():
    finding = _finding(
        indicator="xss",
        recommended_engines=("injectionengine",),
    )
    recs = recommend_engines(finding)
    assert "injectionengine" in recs


def test_recommend_engines_indicator_substring_rules():
    finding = _finding(indicator="stored_xss_candidate", cwe_id=None)
    recs = recommend_engines(finding)
    assert "injectionengine" in recs


def test_recommend_engines_summary_fallback():
    finding = _finding(indicator="unknown", summary="Detected SSRF candidate")
    recs = recommend_engines(finding)
    assert "ssrfexploitationengine" in recs


def test_recommend_engines_uses_cwe_table():
    finding = _finding(indicator="unknown", summary="", cwe_id="CWE-89")
    recs = recommend_engines(finding)
    assert "injectionengine" in recs


def test_recommend_engines_uses_url_lexical_hint():
    finding = _finding(
        indicator="xss",
        summary="",
        url="https://example.com/api/upload/file",
        cwe_id=None,
    )
    recs = recommend_engines(finding)
    assert "fileuploadexploitationengine" in recs


def test_recommend_engines_falls_back_to_http_engine():
    finding = _finding(
        indicator="unrelated",
        summary="unrelated",
        url="https://example.com",
        cwe_id=None,
        recommended_engines=(),
    )
    recs = recommend_engines(finding)
    assert "httpexploitengine" in recs


def test_recommend_engines_deduplicates():
    finding = _finding(
        indicator="xss",
        summary="",
        cwe_id="CWE-79",
        recommended_engines=("injectionengine",),
    )
    recs = recommend_engines(finding)
    assert recs.count("injectionengine") == 1


def test_recommend_engines_filters_unknown_engines():
    finding = _finding(
        indicator="xss",
        recommended_engines=("bogusengine", "injectionengine"),
    )
    recs = recommend_engines(finding)
    assert "bogusengine" not in recs
    assert "injectionengine" in recs


def test_referral_reasons_returns_strings():
    finding = _finding(indicator="xss", cwe_id="CWE-79")
    reasons = referral_reasons(finding)
    assert len(reasons) > 0
    assert all(isinstance(r, str) for r in reasons)


def test_referral_reasons_includes_cwe_reason():
    finding = _finding(indicator="xss", cwe_id="CWE-89")
    reasons = referral_reasons(finding)
    assert any("CWE" in r for r in reasons)


def test_referral_reasons_fallback_includes_default():
    finding = _finding(indicator="unknown", summary="", cwe_id=None, recommended_engines=())
    reasons = referral_reasons(finding)
    assert any("fallback" in r.lower() for r in reasons)


def test_apply_referral_populates_recommended_engines():
    finding = _finding(indicator="xss", recommended_engines=())
    refreshed = apply_referral(finding)
    assert "injectionengine" in refreshed.recommended_engines


def test_apply_referral_keeps_explicit_recommendation():
    finding = _finding(indicator="xss", recommended_engines=("injectionengine",))
    refreshed = apply_referral(finding)
    assert refreshed.recommended_engines == finding.recommended_engines


def test_is_actionable_high_confidence_with_recommendation():
    finding = _finding(confidence=0.8, recommended_engines=("injectionengine",))
    assert is_actionable(finding) is True


def test_is_actionable_low_confidence_rejected():
    finding = _finding(confidence=0.30, recommended_engines=("injectionengine",))
    assert is_actionable(finding) is False


def test_is_actionable_unknown_exploitability_requires_higher_confidence():
    finding = _finding(
        confidence=0.50,
        exploitability=Exploitability.UNKNOWN,
        recommended_engines=("injectionengine",),
    )
    assert is_actionable(finding) is False


def test_is_actionable_unknown_exploitability_above_65():
    finding = _finding(
        confidence=0.70,
        exploitability=Exploitability.UNKNOWN,
        recommended_engines=("injectionengine",),
    )
    assert is_actionable(finding) is True


def test_is_actionable_no_recommendation_rejected():
    finding = _finding(recommended_engines=())
    assert is_actionable(finding) is False


def test_filter_actionable_returns_only_actionable():
    a = _finding(confidence=0.8, recommended_engines=("injectionengine",))
    b = _finding(confidence=0.10, recommended_engines=("injectionengine",))
    c = _finding(confidence=0.6, recommended_engines=())
    out = filter_actionable([a, b, c])
    assert out == [a]


def test_group_by_engine_uses_recommended_or_fallback():
    a = _finding(recommended_engines=("injectionengine",), url="https://a")
    b = _finding(recommended_engines=(), url="https://b")
    grouped = group_by_engine([a, b])
    assert "injectionengine" in grouped
    assert "httpexploitengine" in grouped
    assert grouped["injectionengine"] == [a]
    assert grouped["httpexploitengine"] == [b]


def test_referral_summary_counts_and_buckets():
    findings = [
        _finding(
            confidence=0.9,
            exploitability=Exploitability.CONFIRMED,
            recommended_engines=("injectionengine",),
        ),
        _finding(
            confidence=0.4,
            exploitability=Exploitability.THEORETICAL,
            recommended_engines=("injectionengine",),
        ),
    ]
    summary = referral_summary(findings)
    assert summary["total_findings"] == 2
    assert "injectionengine" in summary["by_engine"]
    engine_summary = summary["by_engine"]["injectionengine"]
    assert engine_summary["count"] == 2
    assert engine_summary["confirmed"] == 1
    assert engine_summary["high_confidence"] == 1
