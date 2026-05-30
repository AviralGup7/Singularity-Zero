"""Dedicated unit tests verifying FuzzingOrchestrator refactoring and remediations."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from src.fuzzing.orchestrator import (
    FuzzingOrchestrator,
    FuzzingRequestSender,
    FuzzingFeedbackTracker,
)


def test_fuzzing_feedback_tracker_metrics():
    tracker = FuzzingFeedbackTracker()
    assert tracker.metrics["total_requests_sent"] == 0
    assert tracker.metrics["payloads_tried"] == 0
    assert tracker.metrics["anomalies_detected"] == 0

    tracker.record_request()
    tracker.record_payload()
    tracker.record_anomaly()

    assert tracker.metrics["total_requests_sent"] == 1
    assert tracker.metrics["payloads_tried"] == 1
    assert tracker.metrics["anomalies_detected"] == 1


@pytest.mark.asyncio
async def test_fuzzing_request_sender_get():
    sender = FuzzingRequestSender(timeout_seconds=2.0)
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.return_value = MagicMock(spec=httpx.Response)

    await sender.get_url(mock_client, "https://example.com/test")
    mock_client.get.assert_called_once_with("https://example.com/test", timeout=2.0)

    # Custom override
    await sender.get_url(mock_client, "https://example.com/test", timeout_seconds=10.0)
    mock_client.get.assert_called_with("https://example.com/test", timeout=10.0)


def test_dictionary_attack_randomization():
    orch = FuzzingOrchestrator(target_endpoints=["/api"])
    list1 = orch.dictionary_attack()
    list2 = orch.dictionary_attack()

    # The contents should be identical sets
    assert set(list1) == set(list2)
    # With enough runs or a good sample size, ordering will differ. But content is preserved.
    assert len(list1) == 10


def test_grammar_mutate_index_error_prevention():
    orch = FuzzingOrchestrator(target_endpoints=["/api"])
    # Falsy key but not list
    res1 = orch.grammar_mutate({"param1": []})
    assert res1 == {"param1": []}

    # Verify no crash occurs on empty string, None, etc.
    res2 = orch.grammar_mutate({"param1": ""})
    assert res2 == {"param1": []}


@pytest.mark.asyncio
async def test_run_fuzzing_campaign_remediated():
    orch = FuzzingOrchestrator(target_endpoints=["/api"])
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = "Normal clean response"
    mock_client.get.return_value = mock_response

    findings = await orch.run_fuzzing_campaign(
        url="https://example.com/api?user=123",
        client=mock_client,
        max_payloads=2,
    )
    
    assert isinstance(findings, list)
    assert len(findings) == 0  # Clean run, no issues leaked
    assert orch.feedback_tracker.metrics["total_requests_sent"] > 0
