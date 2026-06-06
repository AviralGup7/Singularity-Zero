"""Tests for the WebSocket message-level security detector."""

import json

from src.detection.api.websocket_message_security import (
    WebSocketMessageSecurityFinding,
    analyze_websocket_message_security,
    websocket_message_findings_from_observations,
)


def test_origin_mismatch_is_high() -> None:
    frame = {
        "direction": "client",
        "type": "text",
        "payload": "{}",
        "origin": "https://attacker.example",
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
        expected_origin="https://api.example.com",
    )
    assert isinstance(finding, WebSocketMessageSecurityFinding)
    assert "origin_mismatch" in finding.findings
    assert finding.severity == "high"


def test_cross_origin_handshake_without_expected_is_medium() -> None:
    frame = {
        "direction": "client",
        "type": "text",
        "payload": "{}",
        "origin": "https://attacker.example",
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
    )
    assert "cross_origin_handshake" in finding.findings
    assert finding.severity == "medium"


def test_subprotocol_confusion_is_high() -> None:
    frame = {
        "direction": "client",
        "type": "text",
        "payload": "{}",
        "subprotocol": "graphql-transport-ws",
        "server_subprotocol": "graphql-transport-ws",
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
        allowed_subprotocols=["chat"],
    )
    assert "subprotocol_not_in_allow_list" in finding.findings
    assert "subprotocol_confusion_candidate" in finding.findings
    assert finding.severity == "high"


def test_server_frame_with_nosql_operator_is_high() -> None:
    frame = {
        "direction": "server",
        "type": "text",
        "payload": json.dumps({"filter": {"$where": "sleep(1000)"}}),
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
    )
    assert any("nosql_operator" in item for item in finding.findings)
    assert finding.severity == "high"


def test_server_frame_with_proto_key_is_high() -> None:
    frame = {
        "direction": "server",
        "type": "text",
        "payload": json.dumps({"data": {"__proto__": {"admin": True}}}),
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
    )
    assert any("proto_key" in item for item in finding.findings)
    assert finding.severity == "high"


def test_server_frame_with_cross_host_url_is_high() -> None:
    frame = {
        "direction": "server",
        "type": "text",
        "payload": json.dumps({"redirect": "https://attacker.example/callback"}),
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
    )
    assert "server_frame_cross_host_url" in finding.findings
    assert finding.severity == "high"


def test_server_frame_with_html_token_is_high() -> None:
    frame = {
        "direction": "server",
        "type": "text",
        "payload": json.dumps({"render": "<script>alert(1)</script>"}),
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
    )
    assert "server_frame_html_injection" in finding.findings
    assert finding.severity == "high"


def test_baseline_frame_is_info() -> None:
    frame = {
        "direction": "server",
        "type": "text",
        "payload": json.dumps({"ok": True, "ts": 1234567890}),
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
    )
    assert finding.severity == "info"
    assert finding.findings[0] == "baseline_review"


def test_client_frame_nosql_operator_is_high() -> None:
    frame = {
        "direction": "client",
        "type": "text",
        "payload": json.dumps({"q": {"$ne": None}}),
    }
    finding = analyze_websocket_message_security(
        url="wss://api.example.com/ws",
        frame=frame,
        frame_index=0,
    )
    assert any("client_frame_nosql_operator" in item for item in finding.findings)
    assert finding.severity == "high"


def test_observation_adapter_uses_optional_fields() -> None:
    findings = websocket_message_findings_from_observations(
        [
            {
                "url": "",
                "frames": [{"direction": "client", "type": "text", "payload": "{}"}],
            },
            {
                "url": "wss://api.example.com/ws",
                "expected_origin": "https://api.example.com",
                "allowed_subprotocols": ["chat"],
                "frames": [
                    {
                        "direction": "client",
                        "type": "text",
                        "payload": "{}",
                        "origin": "https://attacker.example",
                        "subprotocol": "graphql-ws",
                    },
                ],
            },
        ]
    )
    assert len(findings) == 1
    assert "origin_mismatch" in findings[0]["findings"]
    assert "subprotocol_not_in_allow_list" in findings[0]["findings"]
