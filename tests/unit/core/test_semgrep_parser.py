import json

from src.core.parsers.semgrep_parser import (
    SemgrepSeverityMapper,
    parse_semgrep_json,
)


def _make_result(
    check_id="S001",
    path="src/foo.py",
    line=10,
    severity="WARNING",
    message="Example issue",
    cwe=None,
):
    extra = {"message": message, "metadata": {"severity": severity}}
    if cwe:
        extra["metadata"]["cwe"] = cwe
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 10},
        "extra": extra,
    }


def test_severity_mapping():
    assert SemgrepSeverityMapper.normalize("ERROR") == "critical"
    assert SemgrepSeverityMapper.normalize("warning") == "high"
    assert SemgrepSeverityMapper.normalize("info") == "info"


def test_parse_and_dedupe():
    r1 = _make_result(check_id="S1", path="a.py", line=3, severity="WARNING")
    r2 = _make_result(check_id="S1", path="a.py", line=3, severity="WARNING")
    r3 = _make_result(check_id="S2", path="b.py", line=5, severity="INFO")

    payload = {"results": [r1, r2, r3]}
    results = parse_semgrep_json(json.dumps(payload))

    # dedupe should remove duplicate r2
    assert len(results) == 2

    s2 = next((r for r in results if r["category"] == "S2"), None)
    assert s2 is not None
    assert s2["severity"] == "info"
    assert s2["module"] == "semgrep"
