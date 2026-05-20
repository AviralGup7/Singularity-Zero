"""
Unit tests for the Cognitive Flow Prober.
"""

from unittest.mock import MagicMock

import pytest

from src.analysis.behavior.flow_prober import FlowProber
from src.analysis.passive.runtime import ResponseCache


@pytest.fixture
def mock_cache():
    cache = MagicMock(spec=ResponseCache)
    return cache

def test_flow_token_extraction():
    prober = FlowProber(MagicMock())
    chain = [
        "https://example.com/api/cart/add?cart_id=123",
        "https://example.com/api/cart/checkout?cart_id=123&step=2",
        "https://example.com/api/cart/confirm?order_uuid=abc-def"
    ]
    tokens = prober._extract_flow_tokens(chain)

    assert "cart_id" in tokens
    assert "123" in tokens["cart_id"]
    assert "step" in tokens
    assert "order_uuid" in tokens

def test_strip_tokens():
    prober = FlowProber(MagicMock())
    url = "https://example.com/api/step2?cart_id=123&other=val"
    tokens = {"cart_id": {"123"}}

    stripped = prober._strip_tokens(url, tokens)
    assert "cart_id" not in stripped
    assert "other=val" in stripped

def test_probe_flow_integrity_unaffected(mock_cache):
    # Setup: Server correctly rejects stripped requests
    mock_cache.request.return_value = {"status_code": 403}

    prober = FlowProber(mock_cache)
    flow = {
        "label": "test_flow",
        "chain": [
            "https://example.com/api/start",
            "https://example.com/api/end?session=xyz"
        ]
    }
    tokens = {"session": {"xyz"}}

    findings = prober._probe_flow_integrity(flow, tokens)
    assert len(findings) == 0

def test_probe_flow_integrity_vulnerable(mock_cache):
    # Setup: Server incorrectly accepts stripped request (200 OK)
    mock_cache.request.return_value = {"status_code": 200}

    prober = FlowProber(mock_cache)
    flow = {
        "label": "vulnerable_flow",
        "chain": [
            "https://example.com/api/start",
            "https://example.com/api/end?session=xyz"
        ]
    }
    tokens = {"session": {"xyz"}}

    findings = prober._probe_flow_integrity(flow, tokens)
    assert len(findings) > 0
    assert findings[0]["title"] == "Unenforced State Transition"

def test_probe_state_tampering_vulnerable(mock_cache):
    # Setup: Server accepts mutated ID (200 OK)
    mock_cache.request.return_value = {"status_code": 200}

    prober = FlowProber(mock_cache)
    flow = {
        "label": "checkout_flow",
        "chain": [
            "https://example.com/api/start",
            "https://example.com/api/checkout?cart_id=100"
        ]
    }
    # In this setup:
    # 1. Strategy A will try to strip 'cart_id' from step 2 -> https://example.com/api/checkout
    # 2. Strategy B will try to mutate 'cart_id' to 101
    # Both will result in 200 OK findings.

    tokens = {"cart_id": {"100"}}

    findings = prober._probe_flow_integrity(flow, tokens)
    assert len(findings) >= 1
    titles = [f["title"] for f in findings]
    assert "Loose State-to-Session Binding" in titles
    assert "Unenforced State Transition" in titles
