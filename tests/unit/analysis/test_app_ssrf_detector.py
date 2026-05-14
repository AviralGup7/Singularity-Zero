from src.analysis.passive.detectors.detector_app_ssrf import scan_responses


def test_scan_responses_handles_version_patterns_without_capture_group() -> None:
    responses = [
        {
            "url": "https://repo.example.com/service/rest/v1/status",
            "body": "nexus repository manager",
            "headers": {"X-Request-Id": "abc-123"},
        }
    ]

    findings = scan_responses(responses)

    assert isinstance(findings, list)
    assert any(item.get("app") == "nexus" for item in findings)
