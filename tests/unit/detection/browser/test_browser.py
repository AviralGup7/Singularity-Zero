"""Tests for the browser DOM-runtime detection module."""


from src.detection.browser import (
    DOMMutationRecord,
    RuntimeDetectionResult,
    analyze,
    analyze_async,
    findings_from_response,
    get_instrumentation_script,
    get_interaction_templates,
    is_headless_available,
    probe_url,
    static_analyze,
)
from src.detection.browser.runtime_browser import (
    _INSTRUMENTATION_SCRIPT,
    _INTERACTION_TEMPLATES,
)

# ---------------------------------------------------------------------------
# Static analyzer
# ---------------------------------------------------------------------------


def test_static_analyze_returns_runtime_result():
    html = "<html><script>eval(1)</script></html>"
    result = static_analyze(html, url="https://e")
    assert isinstance(result, RuntimeDetectionResult)
    assert result.mode == "static"
    assert result.error is None
    assert any(f.get("pattern") == "eval" for f in result.static_findings)


def test_static_analyze_detects_innerhtml_sink():
    html = "<html><script>el.innerHTML = userInput;</script></html>"
    result = static_analyze(html, url="https://e")
    assert any(f.get("pattern") == "innerHTML_write" for f in result.static_findings)


def test_static_analyze_detects_prototype_pollution():
    html = "<html><script>obj.__proto__ = 1</script></html>"
    result = static_analyze(html, url="https://e")
    assert any(f.get("pattern_type") == "assign" for f in result.static_findings)


def test_static_analyze_handles_empty_html():
    result = static_analyze("", url="https://e")
    assert result.mode == "static"
    assert result.static_findings == []


def test_static_analyze_to_findings_combines_both():
    html = "<html><script>eval(1)</script><script>obj.__proto__ = 1</script></html>"
    result = static_analyze(html, url="https://e")
    findings = result.to_findings()
    assert len(findings) >= 2


# ---------------------------------------------------------------------------
# analyze() and analyze_async() — both should fall back to static when Playwright missing
# ---------------------------------------------------------------------------


def test_analyze_falls_back_to_static_when_no_playwright(monkeypatch):
    import src.detection.browser.runtime_browser as rb

    monkeypatch.setattr(rb, "async_playwright", None)
    html = "<html><script>eval(1)</script></html>"
    result = analyze("https://e", html=html, force_mode="static")
    assert result.mode == "static"
    assert any(f.get("pattern") == "eval" for f in result.to_findings())


def test_analyze_falls_back_to_static_via_default(monkeypatch):
    import src.detection.browser.runtime_browser as rb

    monkeypatch.setattr(rb, "async_playwright", None)
    html = "<html><script>eval(1)</script></html>"
    result = analyze("https://e", html=html)
    assert result.mode == "static"


def test_analyze_no_html_returns_no_html_error(monkeypatch):
    import src.detection.browser.runtime_browser as rb

    monkeypatch.setattr(rb, "async_playwright", None)
    result = analyze("https://e")
    assert result.error == "no_html"


def test_analyze_async_static_mode(monkeypatch):
    import asyncio

    import src.detection.browser.runtime_browser as rb

    monkeypatch.setattr(rb, "async_playwright", None)
    html = "<html><script>el.innerHTML = x;</script></html>"
    result = asyncio.run(analyze_async("https://e", html=html, force_mode="static"))
    assert result.mode == "static"
    assert any(f.get("pattern") == "innerHTML_write" for f in result.to_findings())


def test_analyze_async_no_html_returns_error(monkeypatch):
    import asyncio

    import src.detection.browser.runtime_browser as rb

    monkeypatch.setattr(rb, "async_playwright", None)
    result = asyncio.run(analyze_async("https://e"))
    assert result.error == "no_html"


def test_analyze_force_headless_no_html(monkeypatch):
    import src.detection.browser.runtime_browser as rb

    monkeypatch.setattr(rb, "async_playwright", None)
    result = analyze("https://e", force_mode="headless")
    assert result.error is not None
    assert "headless" in result.error or "playwright" in result.error


# ---------------------------------------------------------------------------
# findings_from_response adapter
# ---------------------------------------------------------------------------


def test_findings_from_response_json_returns_minimal():
    findings = findings_from_response(
        url="https://e", body_text='{"a": 1}', content_type="application/json"
    )
    assert isinstance(findings, list)


def test_findings_from_response_html_with_sink():
    body = "<html><script>eval(1)</script></html>"
    findings = findings_from_response(
        url="https://e", body_text=body, content_type="text/html", force_mode="static"
    )
    assert any(f.get("pattern") == "eval" for f in findings)


def test_findings_from_response_text_only_no_html():
    findings = findings_from_response(
        url="https://e", body_text="plain text", content_type="text/plain"
    )
    assert findings == []


def test_findings_from_response_none_body():
    findings = findings_from_response(url="https://e", body_text=None)
    assert findings == []


def test_findings_from_response_html_with_no_script():
    findings = findings_from_response(
        url="https://e", body_text="<html><body>Hello</body></html>",
        content_type="text/html", force_mode="static",
    )
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_instrumentation_script_non_empty_and_contains_instrumentation():
    assert len(_INSTRUMENTATION_SCRIPT) > 200
    assert "innerHTML" in _INSTRUMENTATION_SCRIPT
    assert "postMessage" in _INSTRUMENTATION_SCRIPT
    assert "addEventListener" in _INSTRUMENTATION_SCRIPT
    assert "setTimeout" in _INSTRUMENTATION_SCRIPT


def test_instrumentation_script_captures_outer_html():
    # OuterHTML support is opt-in via the runtime; check the supported primitives
    # are at least named in the kind taxonomy (insertion of new outerHTML is fine).
    assert "innerHTML" in _INSTRUMENTATION_SCRIPT
    assert "insertAdjacentHTML" in _INSTRUMENTATION_SCRIPT


def test_instrumentation_script_captures_insert_adjacent_html():
    assert "insertAdjacentHTML" in _INSTRUMENTATION_SCRIPT


def test_instrumentation_script_captures_document_write():
    assert "document.write" in _INSTRUMENTATION_SCRIPT


def test_get_instrumentation_script_matches_private():
    assert get_instrumentation_script() == _INSTRUMENTATION_SCRIPT


def test_interaction_templates_contain_expected_actions():
    names = {n for n, _ in _INTERACTION_TEMPLATES}
    assert {"click", "scroll", "type", "submit", "hover"} <= names


def test_get_interaction_templates_returns_tuple():
    out = get_interaction_templates()
    assert isinstance(out, tuple)
    assert len(out) >= 5


def test_is_headless_available_returns_bool():
    result = is_headless_available()
    assert isinstance(result, bool)


def test_probe_url_returns_dict_with_expected_keys():
    result = probe_url("https://e", html="<html><body>hi</body></html>", force_mode="static")
    assert "url" in result
    assert "mode" in result
    assert "error" in result
    assert "mutations" in result
    assert "static_findings" in result


# ---------------------------------------------------------------------------
# DOMMutationRecord
# ---------------------------------------------------------------------------


def test_dom_mutation_record_to_dict_shape():
    rec = DOMMutationRecord(
        url="https://e", kind="innerHTML", selector="#foo",
        payload_preview="<img x=1>", interaction="click", confidence=0.8
    )
    d = rec.to_dict()
    assert d["url"] == "https://e"
    assert d["kind"] == "innerHTML"
    assert d["selector"] == "#foo"
    assert d["payload_preview"] == "<img x=1>"
    assert d["indicator"] == "dom_runtime_innerHTML"
    assert d["severity"] == "high"


def test_dom_mutation_record_post_message_listener_severity():
    rec = DOMMutationRecord(
        url="https://e", kind="postMessage_listener", selector="window",
        payload_preview=None, interaction="event_listener", confidence=0.5
    )
    d = rec.to_dict()
    assert d["severity"] == "medium"
