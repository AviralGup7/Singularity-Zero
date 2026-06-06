"""Tests for the AST detection package (JS sinks, Wasm, prototype pollution)."""



from src.detection.ast import (
    analyze_html_for_prototype_pollution,
    analyze_html_for_sinks,
    analyze_object_for_prototype_pollution,
    analyze_response,
    analyze_wasm_candidates,
    extract_next_data,
    extract_source_map_url,
    fetch_inline_scripts,
    is_wasm_bytes,
    is_wasm_url,
)
from src.detection.ast.js_sink_analyzer import (
    analyze_html,
    analyze_script,
    analyze_scripts,
    decode_inline_source_map,
)
from src.detection.ast.prototype_pollution_walker import (
    analyze_json_string,
    analyze_object,
    walk_html,
    walk_script,
)
from src.detection.ast.wasm_introspector import (
    batch_introspect,
    findings_from_introspection,
    introspect_bytes,
)

# ---------------------------------------------------------------------------
# JS sink analyzer
# ---------------------------------------------------------------------------


def test_fetch_inline_scripts_extracts_scripts():
    html = (
        "<html><body>\n"
        "<script>var x = 1;</script>\n"
        "<p>text</p>\n"
        "<script>eval('hi');</script>\n"
        "</body></html>"
    )
    scripts = list(fetch_inline_scripts(html))
    assert len(scripts) == 2
    line1, code1 = scripts[0]
    assert "var x = 1" in code1
    line2, code2 = scripts[1]
    assert "eval" in code2
    assert line1 >= 1
    assert line2 > line1


def test_fetch_inline_scripts_no_scripts():
    html = "<html><body><p>hello</p></body></html>"
    scripts = list(fetch_inline_scripts(html))
    assert scripts == []


def test_analyze_script_detects_eval():
    code = "function f(){ eval('alert(1)'); }"
    findings = analyze_script(code, url="https://e")
    eval_finding = next((f for f in findings if f.pattern == "eval"), None)
    assert eval_finding is not None
    assert eval_finding.severity == "critical"
    assert eval_finding.pattern_type == "sink"


def test_analyze_script_detects_innerhtml():
    code = "el.innerHTML = userInput;"
    findings = analyze_script(code, url="https://e")
    inner = next((f for f in findings if f.pattern == "innerHTML_write"), None)
    assert inner is not None
    assert inner.severity == "high"


def test_analyze_script_detects_location_href_assignment():
    code = "window.location.href = url;"
    findings = analyze_script(code, url="https://e")
    loc = next((f for f in findings if f.pattern == "location_assignment"), None)
    assert loc is not None


def test_analyze_script_detects_sanitizer():
    code = "var clean = DOMPurify.sanitize(input); el.innerHTML = clean;\n"
    findings = analyze_script(code, url="https://e")
    inner = next((f for f in findings if f.pattern == "innerHTML_write"), None)
    assert inner is not None
    assert inner.has_sanitizer is True
    assert inner.sanitizer_name is not None


def test_analyze_script_detects_source_map_reference():
    html = "<script>\nvar x = 1;\nel.innerHTML = userInput;\n//# sourceMappingURL=app.js.map\n</script>"
    findings = analyze_html(html, url="https://e")
    with_map = next((f for f in findings if f.source_map), None)
    assert with_map is not None
    assert "app.js.map" in with_map.source_map


def test_analyze_script_detects_jsonp_callback():
    code = "callback = function(d){return d;}"
    findings = analyze_script(code, url="https://e")
    jsonp = next((f for f in findings if f.pattern_type == "jsonp"), None)
    assert jsonp is not None


def test_analyze_script_detects_wasm_instantiate():
    code = "WebAssembly.instantiate(bytes, imports).then(...)"
    findings = analyze_script(code, url="https://e")
    wasm = next((f for f in findings if f.pattern == "wasm_instantiate"), None)
    assert wasm is not None


def test_analyze_script_detects_proto_mutation():
    code = "obj.__proto__ = {polluted: 1}\n"
    findings = analyze_script(code, url="https://e")
    proto = next((f for f in findings if f.pattern_type == "prototype"), None)
    assert proto is not None


def test_analyze_html_combines_inline_scripts():
    html = "<html><script>eval(1)</script><script>el.innerHTML = x;</script></html>"
    findings = analyze_html(html, url="https://e")
    patterns = {f.pattern for f in findings}
    assert "eval" in patterns
    assert "innerHTML_write" in patterns


def test_analyze_scripts_handles_multiple():
    scripts = [("https://a/1.js", "eval(1)", 0), ("https://a/2.js", "el.innerHTML = x;", 0)]
    findings = analyze_scripts(scripts)
    assert len(findings) >= 2


def test_extract_source_map_url_returns_url():
    code = "var x = 1;\n//# sourceMappingURL=app.js.map\nvar y = 2;"
    assert extract_source_map_url(code) == "app.js.map"


def test_extract_source_map_url_returns_none_for_missing():
    code = "var x = 1;"
    assert extract_source_map_url(code) is None


def test_extract_next_data_returns_json_dict():
    html = '<html><script id="__NEXT_DATA__" type="application/json">{"foo":"bar"}</script></html>'
    data = extract_next_data(html)
    assert data is not None
    assert data.get("foo") == "bar"


def test_extract_next_data_returns_none_for_missing():
    html = "<html><body>no next</body></html>"
    assert extract_next_data(html) is None


def test_decode_inline_source_map_valid_base64():
    import base64
    import json as _json

    payload = _json.dumps({"version": 3, "sources": ["a.js"], "mappings": ""}).encode("utf-8")
    encoded = "data:application/json;base64," + base64.b64encode(payload).decode("ascii")
    decoded = decode_inline_source_map(encoded)
    assert decoded is not None
    assert "a.js" in decoded


def test_decode_inline_source_map_invalid_returns_none():
    assert decode_inline_source_map("not-a-data-url") is None
    assert decode_inline_source_map("") is None


def test_analyze_html_for_sinks_returns_dicts():
    html = "<html><script>eval(1)</script></html>"
    findings = analyze_html_for_sinks(html, url="https://e")
    assert all(isinstance(f, dict) for f in findings)
    assert any(f["pattern"] == "eval" for f in findings)


# ---------------------------------------------------------------------------
# Prototype pollution walker
# ---------------------------------------------------------------------------


def test_walk_script_detects_traversal():
    code = "obj['__proto__'] = 1\n"
    findings = walk_script(code, url="https://e")
    assert any(f.pattern_type == "traversal" for f in findings)


def test_walk_script_detects_assign():
    code = "obj.__proto__ = {}"
    findings = walk_script(code, url="https://e")
    assert any(f.pattern_type == "assign" for f in findings)


def test_walk_script_detects_merge_helpers():
    code = "var x = deepMerge(a, b)"
    findings = walk_script(code, url="https://e")
    assert any(f.pattern_type == "merge" for f in findings)


def test_walk_html_combines_inline_scripts():
    html = "<html><script>obj.__proto__ = 1</script><script>deepMerge(a, b)</script></html>"
    findings = walk_html(html, url="https://e")
    pattern_types = {f.pattern_type for f in findings}
    assert "assign" in pattern_types
    assert "merge" in pattern_types


def test_analyze_object_finds_proto_keys():
    obj = {"a": 1, "__proto__": {"polluted": True}, "constructor": {"prototype": {}}}
    findings = analyze_object(obj, url="https://e")
    assert len(findings) >= 2
    assert any("__proto__" in f.pattern for f in findings)


def test_analyze_object_handles_nested():
    obj = {"a": {"b": {"__proto__": {"x": 1}}}}
    findings = analyze_object(obj, url="https://e")
    assert any("__proto__" in f.pattern for f in findings)


def test_analyze_object_handles_lists():
    obj = {"items": [{"__proto__": {"x": 1}}]}
    findings = analyze_object(obj, url="https://e")
    assert any("__proto__" in f.pattern for f in findings)


def test_analyze_object_max_depth_limits_recursion():
    obj = {"a": {"b": {"c": {"d": {"__proto__": 1}}}}}
    findings = analyze_object(obj, url="https://e", max_depth=2)
    assert all(f.pattern_type == "object_key" for f in findings)


def test_analyze_json_string_parses_valid():
    findings = analyze_json_string('{"__proto__": {"x": 1}}', url="https://e")
    assert any("__proto__" in f.pattern for f in findings)


def test_analyze_json_string_returns_empty_for_invalid():
    findings = analyze_json_string("not json", url="https://e")
    assert findings == []


def test_analyze_html_for_prototype_pollution_returns_dicts():
    html = "<html><script>obj.__proto__ = 1</script></html>"
    findings = analyze_html_for_prototype_pollution(html, url="https://e")
    assert all(isinstance(f, dict) for f in findings)
    assert any(f["pattern_type"] == "assign" for f in findings)


def test_analyze_object_for_prototype_pollution_via_string():
    findings = analyze_object_for_prototype_pollution('{"__proto__": {"x": 1}}', url="https://e")
    assert any("__proto__" in f["pattern"] for f in findings)


# ---------------------------------------------------------------------------
# Wasm introspector
# ---------------------------------------------------------------------------


def _make_minimal_wasm(imports=None, exports=None, memory=False, table=False, start=False, data_count=False):
    """Build a tiny valid wasm module with optional sections."""

    body = b"\x00asm\x01\x00\x00\x00"  # magic + version

    def leb128(n):
        out = b""
        while True:
            byte = n & 0x7F
            n >>= 7
            if n:
                out += bytes([byte | 0x80])
            else:
                out += bytes([byte])
                return out

    def name(n):
        enc = n.encode("utf-8")
        return leb128(len(enc)) + enc

    if memory:
        section = bytes([5]) + leb128(1) + bytes([0x00]) + leb128(1)  # 1 memory, no max
        body += bytes([5, len(section)]) + section
    if table:
        section = bytes([4]) + leb128(1) + bytes([0x70, 0x00]) + leb128(0) + leb128(0)
        body += bytes([4, len(section)]) + section
    if imports:
        section_body = leb128(len(imports))
        for module, func_name in imports:
            section_body += name(module) + name(func_name) + bytes([0x00]) + leb128(0)
        body += bytes([2, len(section_body)]) + section_body
    if exports:
        section_body = leb128(len(exports))
        for func_name in exports:
            section_body += name(func_name) + bytes([0x00]) + leb128(0)
        body += bytes([7, len(section_body)]) + section_body
    if start:
        body += bytes([8]) + leb128(1) + leb128(0)  # start section, 1 byte (funcidx 0)
    if data_count:
        body += bytes([12, 1, 0])  # data_count section, 1 count
    return body


def test_is_wasm_bytes_true():
    assert is_wasm_bytes(b"\x00asm\x01\x00\x00\x00") is True


def test_is_wasm_bytes_false_for_non_magic():
    assert is_wasm_bytes(b"PK\x03\x04") is False
    assert is_wasm_bytes(b"") is False
    assert is_wasm_bytes(None) is False  # type: ignore[arg-type]


def test_is_wasm_url_true():
    assert is_wasm_url("https://e.com/app.wasm") is True
    assert is_wasm_url("https://e.com/chunk.wasm?cache=1") is True


def test_is_wasm_url_false():
    assert is_wasm_url("https://e.com/app.js") is False
    assert is_wasm_url("") is False


def test_introspect_bytes_minimal_module():
    body = _make_minimal_wasm(memory=True, table=True, start=True, data_count=True)
    intro = introspect_bytes(body, url="https://e/app.wasm")
    assert intro.parse_error is None
    assert intro.has_memory is True
    assert intro.has_table is True
    assert intro.has_start is True
    assert intro.has_data_count is True
    assert intro.risk_score > 0


def test_introspect_bytes_imports_parsed():
    body = _make_minimal_wasm(imports=[("wasi_snapshot_preview1", "fd_write")])
    intro = introspect_bytes(body, url="https://e/app.wasm")
    assert any(i.module == "wasi_snapshot_preview1" for i in intro.imports)


def test_introspect_bytes_exports_parsed():
    body = _make_minimal_wasm(exports=["myFunc"])
    intro = introspect_bytes(body, url="https://e/app.wasm")
    assert any(e.name == "myFunc" for e in intro.exports)


def test_introspect_bytes_too_short():
    intro = introspect_bytes(b"\x00asm", url="https://e")
    assert intro.parse_error is not None


def test_introspect_bytes_invalid_magic():
    intro = introspect_bytes(b"AAAA\x01\x00\x00\x00", url="https://e")
    assert intro.parse_error is not None


def test_introspect_bytes_to_dict():
    body = _make_minimal_wasm(memory=True)
    intro = introspect_bytes(body, url="https://e")
    d = intro.to_dict()
    assert d["has_memory"] is True
    assert d["parse_error"] is None
    assert "risk_score" in d


def test_findings_from_introspection_high_risk_import():
    body = _make_minimal_wasm(imports=[("wasi_snapshot_preview1", "fd_write")])
    intro = introspect_bytes(body, url="https://e/app.wasm")
    findings = findings_from_introspection(intro)
    assert any(f["indicator"] == "wasm_high_risk_import" for f in findings)


def test_batch_introspect_skips_non_wasm():
    candidates = [("https://e/a.js", b"javascript code"), ("https://e/b.wasm", None)]
    findings = batch_introspect(candidates)
    assert any(f["indicator"] == "wasm_url_candidate" for f in findings)


def test_batch_introspect_processes_wasm():
    body = _make_minimal_wasm(memory=True, imports=[("env", "memory")])
    candidates = [("https://e/app.wasm", body)]
    findings = batch_introspect(candidates)
    assert isinstance(findings, list)


def test_analyze_wasm_candidates_facade():
    body = _make_minimal_wasm(memory=True)
    findings = analyze_wasm_candidates([("https://e/app.wasm", body)])
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# analyze_response facade
# ---------------------------------------------------------------------------


def test_analyze_response_none_body():
    assert analyze_response(url="https://e", body=None, content_type="text/html") == []


def test_analyze_response_html_with_sinks():
    html = "<html><script>eval(1)</script></html>"
    findings = analyze_response(url="https://e", body=html, content_type="text/html")
    assert any(f.get("pattern") == "eval" for f in findings)


def test_analyze_response_json_with_proto():
    body = '{"__proto__": {"x": 1}}'
    findings = analyze_response(url="https://e", body=body, content_type="application/json")
    assert any("__proto__" in f.get("pattern", "") for f in findings)


def test_analyze_response_wasm_bytes():
    body = _make_minimal_wasm(memory=True)
    findings = analyze_response(url="https://e/app.wasm", body=body, content_type="application/wasm")
    assert isinstance(findings, list)
