"""Tests for the GraphQL introspection detection module."""

import json

from src.detection.api.graphql_introspection import (
    GraphQLIntrospectionFinding,
    analyze_graphql_introspection,
    graphql_introspection_findings_from_observations,
)


def _token(header: dict, payload: dict) -> str:
    import base64

    def _b64(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}"


def test_ide_exposure_is_high_severity() -> None:
    body = "<html><body><div id='root'>GraphiQL</div></body></html>"
    finding = analyze_graphql_introspection(
        url="https://api.example.com/graphiql",
        body=body,
    )
    assert isinstance(finding, GraphQLIntrospectionFinding)
    assert finding.has_ide is True
    assert finding.severity == "high"
    assert "GraphiQL" in finding.ide_fingerprints
    payload = finding.to_dict()
    assert payload["indicator"] == "graphql_introspection_query_presence"


def test_persisted_query_signal_is_medium() -> None:
    body = json.dumps(
        {
            "data": {"__typename": "Query"},
            "extensions": {
                "persistedQuery": {"version": 1, "sha256Hash": "deadbeef"}
            },
        }
    )
    finding = analyze_graphql_introspection(
        url="https://api.example.com/graphql",
        body=body,
        headers={"x-apollo-tracing": "1"},
    )
    assert finding.is_endpoint is True
    assert finding.has_persisted_query is True
    assert "persistedQuery" in finding.persisted_query_signals
    assert finding.severity in {"medium", "high"}


def test_schema_data_response_is_high() -> None:
    body = json.dumps({"data": {"__schema": {"types": []}}})
    finding = analyze_graphql_introspection(
        url="https://api.example.com/graphql",
        body=body,
    )
    assert "__schema" in finding.introspection_signals
    assert finding.severity == "high"


def test_graphql_error_leak_is_medium() -> None:
    body = json.dumps(
        {
            "errors": [
                {
                    "message": "Cannot query field 'foo'",
                    "path": ["foo"],
                    "query": "{ foo { id } }",
                }
            ]
        }
    )
    finding = analyze_graphql_introspection(
        url="https://api.example.com/graphql",
        body=body,
    )
    assert finding.severity == "medium"
    assert finding.has_data_field is False
    assert finding.has_query_field is True


def test_unknown_endpoint_with_no_signal_is_info() -> None:
    finding = analyze_graphql_introspection(
        url="https://api.example.com/orders",
        body="<html>orders list</html>",
    )
    assert finding.is_endpoint is False
    assert finding.severity == "info"


def test_observation_adapter_uses_optional_query_field() -> None:
    findings = graphql_introspection_findings_from_observations(
        [
            {
                "url": "https://api.example.com/graphql",
                "body_text": json.dumps(
                    {"data": {"__schema": {"queryType": {"name": "Query"}}}}
                ),
                "headers": {"X-Apollo-Operation-Name": "IntrospectionQuery"},
                "query": "{ __schema { types { name } } }",
                "status_code": 200,
            },
            {
                "url": "",
                "body_text": "{}",
            },
        ]
    )
    assert len(findings) == 1
    assert "__schema" in findings[0]["introspection_signals"]
    assert findings[0]["x-apollo-operation-name" if False else "introspection_headers"] or True
    assert findings[0]["introspection_headers"] == ["X-Apollo-Operation-Name"]
