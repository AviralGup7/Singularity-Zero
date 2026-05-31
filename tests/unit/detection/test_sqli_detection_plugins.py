import json

from src.analysis.active.injection.sqli import sqli_safe_probe
from src.analysis.passive.detectors.detector_sqli import sql_error_exposure_detector
from src.detection.registry import (
    detection_plugin_options,
    get_detection_plugin,
    run_detection_plugin,
)
from src.detection.runtime import prime_detection_context


class FakeResponseCache:
    def __init__(self) -> None:
        self.requested_urls: list[str] = []

    def request(self, url: str, **kwargs: object) -> dict[str, object]:
        self.requested_urls.append(url)
        _ = kwargs
        if "id=%27" in url or "query=%27" in url:
            return {
                "url": url,
                "status_code": 500,
                "body_text": "You have an error in your SQL syntax near '' at line 1",
            }
        return {"url": url, "status_code": 200, "body_text": "ok"}


def test_sqli_safe_probe_emits_finding_for_sql_error_response() -> None:
    cache = FakeResponseCache()

    findings = sqli_safe_probe(
        ["https://app.example.test/products?id=42&view=full"],
        cache,
    )

    assert findings
    finding = findings[0]
    assert finding["url"] == "https://app.example.test/products?id=42&view=full"
    assert finding["issues"] == ["sqli_error_response"]
    assert finding["probes"][0]["parameter"] == "id"
    assert json.loads(json.dumps(finding)) == finding


def test_sql_error_exposure_detector_emits_passive_finding() -> None:
    findings = sql_error_exposure_detector(
        [
            {
                "url": "https://app.example.test/search?query=books",
                "status_code": 500,
                "body_text": 'psycopg2.errors.SyntaxError: syntax error at or near "books"',
            }
        ]
    )

    assert findings
    assert findings[0]["indicator"] == "sql_error_disclosure"
    assert findings[0]["parameters"] == ["query"]
    assert "param:query" in findings[0]["signals"]
    assert json.loads(json.dumps(findings[0])) == findings[0]


def test_sqli_plugins_are_discovered_with_runtime_metadata() -> None:
    active_plugin = get_detection_plugin("sqli_safe_probe")
    passive_plugin = get_detection_plugin("sql_error_exposure_detector")

    assert active_plugin.phase == "validate"
    assert active_plugin.consumes == ("priority_urls", "response_cache")
    assert passive_plugin.input_kind == "responses_only"

    option_names = {option["name"] for option in detection_plugin_options()}
    assert {"sqli_safe_probe", "sql_error_exposure_detector"} <= option_names


def test_sqli_plugins_produce_findings_through_detection_runtime() -> None:
    cache = FakeResponseCache()
    ctx = prime_detection_context(
        urls={"https://app.example.test/products?id=42"},
        priority_urls=["https://app.example.test/products?id=42"],
        response_cache=cache,
        responses=[
            {
                "url": "https://app.example.test/search?query=books",
                "status_code": 500,
                "body_text": "SQLSTATE[42000]: syntax error or access violation",
            }
        ],
    )

    active = run_detection_plugin("sqli_safe_probe", ctx)
    passive = run_detection_plugin("sql_error_exposure_detector", ctx)

    assert active and active[0]["issues"] == ["sqli_error_response"]
    assert passive and passive[0]["issues"] == ["sql_error_disclosure"]
