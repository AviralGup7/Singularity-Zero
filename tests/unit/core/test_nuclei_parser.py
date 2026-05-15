import json

from src.core.parsers.nuclei_parser import (
    NucleiFindingParser,
    NucleiSeverityMapper,
    parse_nuclei_jsonl,
)


def _make_line(
    template_id="template-1",
    name="Test Template",
    severity="high",
    matched_at="http://example.com",
    host="example.com",
    tags=None,
):
    tags = tags or ["xss"]
    payload = {
        "template-id": template_id,
        "info": {
            "name": name,
            "severity": severity,
            "description": "desc",
            "tags": tags,
        },
        "matched-at": matched_at,
        "host": host,
        "ip": "1.2.3.4",
        "type": "vuln",
        "matcher-name": "m1",
        "timestamp": "2026-04-11T00:00:00Z",
        "response": "raw_response",
    }
    return json.dumps(payload)


def test_severity_normalize_and_score():
    assert NucleiSeverityMapper.normalize("CRITICAL") == "critical"
    assert NucleiSeverityMapper.score("critical") == 100
    assert NucleiSeverityMapper.normalize("unknown") == "info"
    assert NucleiSeverityMapper.normalize("nonsense") == "info"
    assert NucleiSeverityMapper.score("nonsense") == 5


def test_parse_line_minimal():
    p = NucleiFindingParser()
    line = _make_line()
    nf = p.parse_line(line)
    assert nf is not None
    assert nf.template_id == "template-1"
    assert nf.template_name == "Test Template"
    assert nf.severity == "high"
    assert nf.url == "http://example.com"
    assert nf.ip_address == "1.2.3.4"


def test_parse_output_dedupe_and_mitre():
    line1 = _make_line(template_id="t1", matched_at="http://a")
    line2 = _make_line(template_id="t1", matched_at="http://a")
    line3 = _make_line(template_id="t2", matched_at="http://b", tags=["t1190", "xss"])

    results = parse_nuclei_jsonl("\n".join([line1, line2, line3]))
    # deduplication should keep two unique findings
    assert len(results) == 2

    # find the t2 result and ensure mitre attack extraction produced something sensible
    t2 = next((r for r in results if r["category"] == "t2"), None)
    assert t2 is not None
    assert isinstance(t2.get("mitre_attack", []), list)
    # Expect at least one MITRE ID mapped from tags or explicit T-prefixed tag
    assert any(t for t in t2["mitre_attack"])
