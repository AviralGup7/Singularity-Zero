"""Tests for the detection handler adapters."""

from src.detection.handlers import (
    csrf_entropy_analyzer,
    dom_runtime_analyzer,
    get_handler,
    js_sink_source_analyzer,
    list_handler_keys,
    prototype_pollution_walker,
    race_concurrent_mutator,
    rate_limit_adaptive_prober,
    session_fixation_detector,
    waf_challenge_detector,
    waf_fingerprint_analyzer,
    wasm_module_introspector,
)

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


def test_list_handler_keys_includes_api_handlers():
    keys = list_handler_keys()
    assert "js_sink_source_analyzer" in keys
    assert "race_concurrent_mutator" in keys
    api_keys = {
        "api_rest_param_pollution",
        "api_graphql_introspection",
        "api_rate_limit_differential",
        "api_jwt_claim_integrity",
        "api_websocket_message_security",
    }
    assert api_keys.issubset(set(keys))


def test_get_handler_returns_callable_for_each_key():
    for key in list_handler_keys():
        handler = get_handler(key)
        assert callable(handler)


def test_get_handler_returns_none_for_unknown():
    assert get_handler("__unknown__") is None


# ---------------------------------------------------------------------------
# js_sink_source_analyzer
# ---------------------------------------------------------------------------


def test_js_sink_source_analyzer_extracts_sinks():
    responses = [
        {
            "url": "https://e/page",
            "body_text": "<html><script>eval('alert(1)')</script></html>",
            "content_type": "text/html",
        }
    ]
    findings = js_sink_source_analyzer(responses)
    assert any(f.get("pattern") == "eval" for f in findings)
    assert all(f.get("analyzer_key") == "js_sink_source_analyzer" for f in findings)
    assert all(f.get("phase") == "analyze" for f in findings)


def test_js_sink_source_analyzer_skips_empty_url():
    findings = js_sink_source_analyzer([{"url": "", "body_text": "<html></html>"}])
    assert findings == []


def test_js_sink_source_analyzer_handles_no_body():
    findings = js_sink_source_analyzer([{"url": "https://e"}])
    assert findings == []


# ---------------------------------------------------------------------------
# wasm_module_introspector
# ---------------------------------------------------------------------------


def test_wasm_module_introspector_with_bytes():
    body = b"\x00asm\x01\x00\x00\x00"
    findings = wasm_module_introspector([{"url": "https://e/app.wasm", "body": body}])
    assert isinstance(findings, list)


def test_wasm_module_introspector_with_string_body():
    findings = wasm_module_introspector([{"url": "https://e/app.wasm", "body": "not bytes"}])
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# prototype_pollution_walker
# ---------------------------------------------------------------------------


def test_prototype_pollution_walker_html():
    findings = prototype_pollution_walker(
        [
            {
                "url": "https://e/page",
                "body_text": "<html><script>obj.__proto__ = 1</script></html>",
                "content_type": "text/html",
            }
        ]
    )
    assert any(f.get("pattern_type") == "assign" for f in findings)


def test_prototype_pollution_walker_json():
    findings = prototype_pollution_walker(
        [
            {
                "url": "https://e/api",
                "body_text": '{"__proto__": {"x": 1}}',
                "content_type": "application/json",
            }
        ]
    )
    assert any("__proto__" in f.get("pattern", "") for f in findings)


def test_prototype_pollution_walker_skips_empty_body():
    findings = prototype_pollution_walker([{"url": "https://e", "body_text": ""}])
    assert findings == []


# ---------------------------------------------------------------------------
# dom_runtime_analyzer
# ---------------------------------------------------------------------------


def test_dom_runtime_analyzer_html():
    findings = dom_runtime_analyzer(
        [
            {
                "url": "https://e/page",
                "body_text": "<html><script>el.innerHTML = x;</script></html>",
                "content_type": "text/html",
            }
        ]
    )
    assert isinstance(findings, list)
    assert all(f.get("analyzer_key") == "dom_runtime_analyzer" for f in findings)


def test_dom_runtime_analyzer_json_returns_empty():
    findings = dom_runtime_analyzer(
        [
            {
                "url": "https://e/api",
                "body_text": '{"a": 1}',
                "content_type": "application/json",
            }
        ]
    )
    assert findings == []


# ---------------------------------------------------------------------------
# waf_fingerprint_analyzer
# ---------------------------------------------------------------------------


def test_waf_fingerprint_analyzer_with_cloudflare_headers():
    findings = waf_fingerprint_analyzer(
        [
            {
                "url": "https://e",
                "headers": {"server": "cloudflare", "cf-ray": "abc"},
                "body_text": "hello world",
                "content_type": "text/html",
            }
        ]
    )
    assert any(f.get("waf_name") for f in findings)


def test_waf_fingerprint_analyzer_skips_no_url():
    findings = waf_fingerprint_analyzer([{"url": "", "headers": {}}])
    assert findings == []


# ---------------------------------------------------------------------------
# waf_challenge_detector
# ---------------------------------------------------------------------------


def test_waf_challenge_detector_emits_finding_for_challenge():
    findings = waf_challenge_detector(
        [
            {
                "url": "https://e",
                "headers": {},
                "body_text": "please complete the hcaptcha challenge to continue",
                "content_type": "text/html",
                "status_code": 200,
            }
        ]
    )
    assert any(f.get("indicator") == "waf_challenge_page" for f in findings)


def test_waf_challenge_detector_skips_clean_response():
    findings = waf_challenge_detector(
        [
            {
                "url": "https://e",
                "headers": {},
                "body_text": "normal page content",
                "content_type": "text/html",
                "status_code": 200,
            }
        ]
    )
    assert findings == []


# ---------------------------------------------------------------------------
# csrf_entropy_analyzer
# ---------------------------------------------------------------------------


def test_csrf_entropy_analyzer_with_static_tokens():
    findings = csrf_entropy_analyzer(
        [{"url": "https://e/form", "csrf_token_samples": ["abc", "abc", "abc", "abc"]}]
    )
    assert any(f.get("indicator") == "csrf_entropy_weakness" for f in findings)
    assert any(f.get("is_static") is True for f in findings)


def test_csrf_entropy_analyzer_skips_no_tokens():
    findings = csrf_entropy_analyzer([{"url": "https://e", "csrf_token_samples": []}])
    assert findings == []


def test_csrf_entropy_analyzer_supports_alternate_key():
    findings = csrf_entropy_analyzer([{"url": "https://e", "csrf_tokens": ["static"]}])
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# session_fixation_detector
# ---------------------------------------------------------------------------


def test_session_fixation_detector_vulnerable():
    findings = session_fixation_detector(
        [
            {
                "url": "https://e/login",
                "pre_auth_token": "PRE123",
                "post_auth_token": "PRE123",
            }
        ]
    )
    assert any(f.get("rotated_after_auth") is False for f in findings)
    assert any(f.get("severity") == "high" for f in findings)


def test_session_fixation_detector_safe():
    findings = session_fixation_detector(
        [
            {
                "url": "https://e/login",
                "pre_auth_token": "PRE123",
                "post_auth_token": "POST456",
            }
        ]
    )
    assert any(f.get("rotated_after_auth") is True for f in findings)
    assert any(f.get("severity") == "info" for f in findings)


def test_session_fixation_detector_skips_empty_url():
    findings = session_fixation_detector(
        [{"url": "", "pre_auth_token": "x", "post_auth_token": "x"}]
    )
    assert findings == []


# ---------------------------------------------------------------------------
# rate_limit_adaptive_prober
# ---------------------------------------------------------------------------


def test_rate_limit_adaptive_prober_basic():
    samples = [
        {"interval_ms": 100, "status_code": 200},
        {"interval_ms": 500, "status_code": 429},
    ]
    findings = rate_limit_adaptive_prober([{"url": "https://e", "rate_limit_samples": samples}])
    assert any(f.get("indicator") == "rate_limit_adaptive_probe" for f in findings)


def test_rate_limit_adaptive_prober_skips_no_samples():
    findings = rate_limit_adaptive_prober([{"url": "https://e", "rate_limit_samples": []}])
    assert findings == []


# ---------------------------------------------------------------------------
# race_concurrent_mutator
# ---------------------------------------------------------------------------


def test_race_concurrent_mutator_with_drift():
    findings = race_concurrent_mutator(
        [
            {
                "url": "https://e/redeem",
                "race_observation": {
                    "fired_concurrent": 5,
                    "success_count": 4,
                    "failure_count": 1,
                    "drift_observed": True,
                },
            }
        ]
    )
    assert len(findings) == 1
    assert findings[0]["indicator"] == "race_condition_concurrent_probe"
    assert findings[0]["severity"] == "high"
    assert findings[0]["drift_observed"] is True


def test_race_concurrent_mutator_without_drift():
    findings = race_concurrent_mutator(
        [
            {
                "url": "https://e/redeem",
                "race_observation": {
                    "fired_concurrent": 5,
                    "success_count": 5,
                    "failure_count": 0,
                    "drift_observed": False,
                },
            }
        ]
    )
    assert findings[0]["severity"] == "medium"
    assert findings[0]["drift_observed"] is False


def test_race_concurrent_mutator_skips_no_observation():
    findings = race_concurrent_mutator([{"url": "https://e"}])
    assert findings == []


def test_race_concurrent_mutator_skips_invalid_observation():
    findings = race_concurrent_mutator([{"url": "https://e", "race_observation": "not a dict"}])
    assert findings == []
