"""End-to-end tests for the API detection handlers.

These tests exercise the thin adapters in :mod:`src.detection.handlers`
that wire the API detection modules into the plugin runtime, ensuring
that the response-shape contract is preserved.
"""

from src.detection.handlers import (
    api_graphql_introspection,
    api_jwt_claim_integrity,
    api_rate_limit_differential,
    api_rest_param_pollution,
    api_websocket_message_security,
    get_handler,
    list_handler_keys,
)


def test_handler_keys_expose_api_modules() -> None:
    keys = list_handler_keys()
    expected = {
        "api_rest_param_pollution",
        "api_graphql_introspection",
        "api_rate_limit_differential",
        "api_jwt_claim_integrity",
        "api_websocket_message_security",
    }
    assert expected.issubset(set(keys))


def test_get_handler_resolves_api_keys() -> None:
    for key in (
        "api_rest_param_pollution",
        "api_graphql_introspection",
        "api_rate_limit_differential",
        "api_jwt_claim_integrity",
        "api_websocket_message_security",
    ):
        assert get_handler(key) is not None


def test_rest_param_pollution_handler_emits_finding() -> None:
    findings = api_rest_param_pollution(
        [
            {
                "url": "https://api.example.com/items",
                "hpp_observations": [
                    {
                        "url": "https://api.example.com/items",
                        "parameter": "tag",
                        "observed_values": ["red", "blue"],
                    }
                ],
            }
        ]
    )
    assert findings
    assert findings[0]["analyzer_key"] == "api_rest_param_pollution"
    assert findings[0]["phase"] == "analyze"
    assert findings[0]["indicator"] == "rest_parameter_pollution"
    assert findings[0]["is_ambiguous"] is True


def test_graphql_introspection_handler_emits_finding() -> None:
    findings = api_graphql_introspection(
        [
            {
                "url": "https://api.example.com/graphql",
                "graphql_introspection_observations": [
                    {
                        "url": "https://api.example.com/graphql",
                        "body_text": '{"data": {"__schema": {"types": []}}}',
                    }
                ],
            }
        ]
    )
    assert findings
    assert findings[0]["analyzer_key"] == "api_graphql_introspection"
    assert findings[0]["indicator"] == "graphql_introspection_query_presence"


def test_rate_limit_differential_handler_emits_finding() -> None:
    findings = api_rate_limit_differential(
        [
            {
                "url": "https://api.example.com/login",
                "rate_limit_observations": [
                    {
                        "url": "https://api.example.com/login",
                        "method": "POST",
                        "status_code": 200,
                    },
                ],
            }
        ]
    )
    assert findings
    assert findings[0]["analyzer_key"] == "api_rate_limit_differential"
    assert findings[0]["endpoint_cost_class"] == "sensitive"


def test_jwt_claim_integrity_handler_emits_finding() -> None:
    import base64
    import json

    def _b64(value: dict) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )

    token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1'})}.deadbeef"
    findings = api_jwt_claim_integrity(
        [
            {
                "url": "https://api.example.com/whoami",
                "jwt_observations": [
                    {
                        "url": "https://api.example.com/whoami",
                        "token": token,
                    }
                ],
            }
        ]
    )
    assert findings
    assert findings[0]["analyzer_key"] == "api_jwt_claim_integrity"
    assert "alg_none_accepted" in findings[0]["findings"]


def test_websocket_message_security_handler_emits_finding() -> None:
    findings = api_websocket_message_security(
        [
            {
                "url": "wss://api.example.com/ws",
                "websocket_frame_observations": [
                    {
                        "url": "wss://api.example.com/ws",
                        "expected_origin": "https://api.example.com",
                        "frames": [
                            {
                                "direction": "client",
                                "type": "text",
                                "payload": "{}",
                                "origin": "https://attacker.example",
                            }
                        ],
                    }
                ],
            }
        ]
    )
    assert findings
    assert findings[0]["analyzer_key"] == "api_websocket_message_security"
    assert "origin_mismatch" in findings[0]["findings"]


def test_handlers_ignore_responses_without_observations() -> None:
    findings = api_rest_param_pollution([{"url": "https://x"}])
    assert findings == []
    findings = api_graphql_introspection([{"url": "https://x"}])
    assert findings == []
    findings = api_rate_limit_differential([{"url": "https://x"}])
    assert findings == []
    findings = api_jwt_claim_integrity([{"url": "https://x"}])
    assert findings == []
    findings = api_websocket_message_security([{"url": "https://x"}])
    assert findings == []
