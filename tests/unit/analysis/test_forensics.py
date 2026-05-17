import json

from src.analysis.passive.forensics import ForensicExchange, save_forensic_exchange


def test_forensic_exchange_redaction():
    headers = {
        "Authorization": "Bearer secret-token",
        "Content-Type": "application/json",
        "Cookie": "session=123",
    }
    exchange = ForensicExchange(
        url="https://example.com",
        method="POST",
        request_headers=headers,
        request_body=b'{"key": "value"}',
        response_status=200,
        response_headers={"X-Server": "prod"},
        response_body=b'{"status": "ok"}',
        latency_seconds=0.1,
    )

    data = exchange.to_dict()
    assert data["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert data["request"]["headers"]["Cookie"] == "[REDACTED]"
    assert data["request"]["headers"]["Content-Type"] == "application/json"


def test_forensic_exchange_truncation():
    exchange = ForensicExchange(
        url="https://example.com",
        method="GET",
        request_headers={},
        request_body=None,
        response_status=200,
        response_headers={},
        response_body=b"A" * 1000,
        latency_seconds=0.1,
        max_body_bytes=10,
    )

    data = exchange.to_dict()
    assert len(data["response"]["body_snippet"]) == 10
    assert data["response"]["truncated"] is True


def test_save_forensic_exchange(tmp_path):
    exchange = ForensicExchange(
        url="https://example.com",
        method="GET",
        request_headers={},
        request_body=None,
        response_status=200,
        response_headers={},
        response_body=b"test",
        latency_seconds=0.1,
    )

    path = save_forensic_exchange(tmp_path, exchange, "test-target")
    assert path.exists()
    assert path.name.startswith("exchange_")

    saved_data = json.loads(path.read_text())
    assert saved_data["exchange_id"] == exchange.exchange_id
