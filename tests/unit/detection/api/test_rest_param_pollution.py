"""Tests for the REST parameter pollution detector."""

from src.detection.api.rest_param_pollution import (
    RestParamPollutionFinding,
    analyze_rest_parameter_pollution,
    repeated_query_parameters,
    rest_param_pollution_findings_from_observations,
)


def test_array_binding_is_flagged_as_polluted() -> None:
    finding = analyze_rest_parameter_pollution(
        url="https://api.example.com/items",
        parameter="tag",
        observed_values=["red", "blue", "green"],
        status_code=200,
    )
    assert isinstance(finding, RestParamPollutionFinding)
    assert finding.is_ambiguous is True
    assert finding.is_array_binding is True
    assert finding.is_concat_binding is False
    assert finding.severity == "high"
    assert finding.confidence >= 0.7
    payload = finding.to_dict()
    assert payload["indicator"] == "rest_parameter_pollution"
    assert payload["binding_style"] == "array"
    assert payload["remediation_hint"]


def test_concat_binding_is_flagged_as_polluted() -> None:
    finding = analyze_rest_parameter_pollution(
        url="https://api.example.com/items",
        parameter="q",
        observed_values=["1", "2", "1,2"],
    )
    assert finding.is_concat_binding is True
    assert finding.is_ambiguous is True
    assert finding.severity == "high"


def test_first_wins_distinct_is_still_polluted() -> None:
    finding = analyze_rest_parameter_pollution(
        url="https://api.example.com/items",
        parameter="filter",
        observed_values=["active", "inactive"],
    )
    assert finding.is_ambiguous is True
    assert finding.severity in {"medium", "high"}


def test_server_error_with_repetition_is_polluted() -> None:
    finding = analyze_rest_parameter_pollution(
        url="https://api.example.com/items",
        parameter="id",
        observed_values=["1", "1"],
        status_code=500,
    )
    assert finding.is_ambiguous is True
    assert finding.severity in {"medium", "high"}


def test_single_value_is_not_polluted() -> None:
    finding = analyze_rest_parameter_pollution(
        url="https://api.example.com/items",
        parameter="id",
        observed_values=["1"],
        status_code=200,
    )
    assert finding.is_ambiguous is False
    assert finding.severity == "info"


def test_observation_adapter_skips_invalid_rows() -> None:
    findings = rest_param_pollution_findings_from_observations(
        [
            {"url": "", "parameter": "id", "observed_values": ["1", "2"]},
            {"url": "https://x", "parameter": "", "observed_values": ["1"]},
            {
                "url": "https://api.example.com/items",
                "parameter": "tag",
                "observed_values": ["red", "blue"],
            },
        ]
    )
    assert len(findings) == 1
    assert findings[0]["parameter"] == "tag"
    assert findings[0]["is_ambiguous"] is True


def test_repeated_query_parameters_collects_repeats() -> None:
    repeated = repeated_query_parameters("https://api.example.com/items?tag=red&tag=blue&q=hello")
    assert "tag" in repeated
    assert repeated["tag"] == ["red", "blue"]
    assert "q" not in repeated
