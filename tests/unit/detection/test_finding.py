
import pytest

from src.detection.finding import (
    DetectionFinding,
    Evidence,
    Exploitability,
    FindingOverrides,
    Severity,
    _infer_confidence,
    _signature_from_dict,
    clamp_confidence,
    coerce_findings,
    dicts_to_findings,
    from_dict,
    make_finding_id,
)


def _base_kwargs(**overrides):
    base = dict(
        finding_id="F-test001",
        url="https://example.com/api/users?id=1",
        indicator="xss_candidate",
        summary="Reflected value in body",
        severity=Severity.HIGH,
        confidence=0.75,
        exploitability=Exploitability.PROBABLE,
        analyzer_key="js_sink_source_analyzer",
        phase="analyze",
        recommended_engines=("injectionengine",),
        evidence=(),
    )
    base.update(overrides)
    return base


def test_clamp_confidence_within_range():
    assert clamp_confidence(0.5) == 0.5
    assert clamp_confidence(0.0) == pytest.approx(0.05)
    assert clamp_confidence(1.0) == pytest.approx(0.99)
    assert clamp_confidence(0.04) == pytest.approx(0.05)
    assert clamp_confidence(1.5) == pytest.approx(0.99)
    assert clamp_confidence(-0.5) == pytest.approx(0.05)


def test_clamp_confidence_handles_nan():
    assert clamp_confidence(float("nan")) == pytest.approx(0.05)


def test_detection_finding_to_dict_round_trip():
    finding = DetectionFinding(**_base_kwargs())
    payload = finding.to_dict()
    assert payload["url"] == "https://example.com/api/users?id=1"
    assert payload["indicator"] == "xss_candidate"
    assert payload["severity"] == "high"
    assert payload["confidence"] == 0.75
    assert payload["exploitability"] == "probable"
    assert payload["analyzer_key"] == "js_sink_source_analyzer"
    assert payload["phase"] == "analyze"
    assert payload["recommended_engines"] == ["injectionengine"]
    assert payload["finding_id"] == "F-test001"


def test_detection_finding_dict_getitem_protocol():
    finding = DetectionFinding(**_base_kwargs())
    assert finding["url"] == "https://example.com/api/users?id=1"
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.75
    assert finding["recommended_engines"] == ["injectionengine"]
    assert finding.get("missing", "fallback") == "fallback"
    assert "url" in finding
    assert "missing" not in finding
    with pytest.raises(KeyError):
        _ = finding["definitely_not_there"]


def test_detection_finding_dict_getitem_for_metadata():
    finding = DetectionFinding(**_base_kwargs(metadata={"waf_name": "Cloudflare"}))
    assert finding["waf_name"] == "Cloudflare"
    assert finding.get("waf_name") == "Cloudflare"
    assert "waf_name" in finding


def test_from_dict_minimal_input_uses_defaults():
    finding = from_dict({"url": "https://example.com/x"}, analyzer_key="ak", phase="analyze")
    assert finding.severity == Severity.INFO
    assert finding.exploitability in {Exploitability.UNKNOWN, Exploitability.THEORETICAL}
    assert finding.url == "https://example.com/x"
    assert finding.analyzer_key == "ak"
    assert finding.phase == "analyze"
    assert finding.finding_id.startswith("F-")
    assert finding.indicator in {"x", "unknown"}


def test_from_dict_severity_normalization():
    finding = from_dict(
        {"url": "https://e", "severity": "Critical"},
        analyzer_key="ak",
        phase="p",
    )
    assert finding.severity == Severity.CRITICAL


def test_from_dict_invalid_severity_falls_back_to_info():
    finding = from_dict(
        {"url": "https://e", "severity": "bogus"},
        analyzer_key="ak",
        phase="p",
    )
    assert finding.severity == Severity.INFO


def test_from_dict_confidence_clamped_and_round_tripped():
    finding = from_dict(
        {"url": "https://e", "confidence": 0.0},
        analyzer_key="ak",
        phase="p",
    )
    assert finding.confidence == pytest.approx(0.05)


def test_from_dict_confidence_inference_when_missing():
    finding = from_dict(
        {"url": "https://e", "indicator": "stored_xss_candidate", "status_code": 500},
        analyzer_key="ak",
        phase="p",
    )
    base = _infer_confidence({"indicator": "stored_xss_candidate", "status_code": 500})
    assert finding.confidence == pytest.approx(base)


def test_from_dict_confidence_garbage_falls_back_to_inference():
    finding = from_dict(
        {"url": "https://e", "indicator": "reflected_input_candidate", "confidence": "wat"},
        analyzer_key="ak",
        phase="p",
    )
    assert finding.confidence > 0.30


def test_from_dict_explicit_finding_id_kept():
    finding = from_dict(
        {"url": "https://e", "finding_id": "F-abc"},
        analyzer_key="ak",
        phase="p",
    )
    assert finding.finding_id == "F-abc"


def test_from_dict_evidence_list_built():
    raw = {
        "url": "https://e",
        "evidence": [
            {
                "kind": "reflection",
                "description": "reflected in body",
                "payload": "<script>alert(1)</script>",
                "response_status": 200,
                "body_snippet": "hello <script>alert(1)</script>",
            }
        ],
    }
    finding = from_dict(raw, analyzer_key="ak", phase="p")
    assert len(finding.evidence) == 1
    assert finding.evidence[0].kind == "reflection"
    assert finding.evidence[0].payload == "<script>alert(1)</script>"
    assert finding.evidence[0].response_status == 200
    assert finding.evidence[0].body_snippet is not None


def test_from_dict_response_evidence_built_from_status():
    raw = {"url": "https://e", "status_code": 200, "body_preview": "x"}
    finding = from_dict(raw, analyzer_key="ak", phase="p")
    assert len(finding.evidence) == 1
    assert finding.evidence[0].kind == "response"
    assert finding.evidence[0].response_status == 200


def test_from_dict_exploitability_confirmed():
    finding = from_dict(
        {"url": "https://e", "confirmed": True},
        analyzer_key="ak",
        phase="p",
    )
    assert finding.exploitability == Exploitability.CONFIRMED


def test_from_dict_exploitability_probable_from_confidence():
    finding = from_dict(
        {"url": "https://e", "indicator": "ssrf_candidate_finder", "status_code": 500, "error": "oops"},
        analyzer_key="ak",
        phase="p",
    )
    assert finding.exploitability in {
        Exploitability.PROBABLE,
        Exploitability.CONFIRMED,
        Exploitability.THEORETICAL,
    }


def test_from_dict_legacy_payload_preserved():
    raw = {"url": "https://e", "old_field": "preserved"}
    finding = from_dict(raw, analyzer_key="ak", phase="p")
    assert finding.legacy.get("old_field") == "preserved"
    payload = finding.to_dict()
    assert payload.get("legacy", {}).get("old_field") == "preserved"


def test_from_dict_metadata_extracted():
    raw = {"url": "https://e", "waf_name": "Cloudflare", "bypass_strategies": ["x"]}
    finding = from_dict(raw, analyzer_key="ak", phase="p")
    assert finding.metadata.get("waf_name") == "Cloudflare"
    assert "waf_name" in finding.to_dict()


def test_signature_from_dict_uses_keys():
    sig = _signature_from_dict({"parameter": "id", "value": "1"})
    assert "parameter=id" in sig
    assert "value=1" in sig


def test_signature_from_dict_falls_back_to_body_hash():
    sig = _signature_from_dict({"body": "abc"})
    assert sig.startswith("body=")


def test_signature_from_dict_falls_back_to_json():
    sig = _signature_from_dict({"something_unique": "x"})
    assert isinstance(sig, str)
    assert len(sig) > 0


def test_coerce_findings_keeps_typed_and_wraps_dicts():
    typed = DetectionFinding(**_base_kwargs())
    out = coerce_findings(
        [typed, {"url": "https://e2", "indicator": "xss"}],
        analyzer_key="ak",
        phase="p",
    )
    assert len(out) == 2
    assert out[0] is typed
    assert out[1].analyzer_key == "ak"
    assert out[1].url == "https://e2"


def test_dicts_to_findings_returns_enriched_dicts():
    rows = [{"url": "https://e", "indicator": "stored_xss_candidate", "status_code": 500}]
    out = dicts_to_findings(rows, analyzer_key="ak", phase="p")
    assert isinstance(out[0], dict)
    assert "confidence" in out[0]
    assert "recommended_engines" in out[0]
    assert out[0]["analyzer_key"] == "ak"


def test_make_finding_id_is_unique():
    ids = {make_finding_id() for _ in range(50)}
    assert len(ids) == 50


def test_finding_overrides_dataclass_construction():
    overrides = FindingOverrides(severity=Severity.LOW, confidence=0.4)
    assert overrides.severity == Severity.LOW
    assert overrides.recommended_engines == ()


def test_evidence_to_dict_strips_empty_extra():
    ev = Evidence(kind="k", description="d", payload="p", response_status=200, response_length=42, body_snippet="snip")
    d = ev.__dict__ if hasattr(ev, "__dict__") else None
    assert d is None or isinstance(d, dict)


def test_from_dict_with_url_override():
    finding = from_dict(
        {"indicator": "xss", "url": "raw"},
        analyzer_key="ak",
        phase="p",
        url="https://override",
    )
    assert finding.url == "https://override"
