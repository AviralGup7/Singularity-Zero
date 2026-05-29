"""Unit tests for FuzzingOrchestrator, mutation strategies, and coverage-guided feedback loops."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from src.fuzzing.orchestrator import FuzzingOrchestrator


def test_fuzzer_mutations() -> None:
    """Test mutation generators in FuzzingOrchestrator."""
    orchestrator = FuzzingOrchestrator([])

    # Test bit-flipping
    base_val = "admin"
    flipped = orchestrator.bit_flip(base_val)
    assert isinstance(flipped, str)
    assert flipped != base_val or len(base_val) <= 1

    # Test boundary values
    bounds = orchestrator.boundary_values("numeric")
    assert "0" in bounds
    assert "-1" in bounds
    assert "2147483647" in bounds

    # Test dictionary attack payloads
    payloads = orchestrator.dictionary_attack()
    assert "' OR '1'='1" in payloads
    assert "../../../../etc/passwd" in payloads

    # Test grammar mutation
    grammar = {"username": ["user1", "user2"]}
    mutated = orchestrator.grammar_mutate(grammar)
    assert "username" in mutated
    assert len(mutated["username"]) > len(grammar["username"])


def test_fuzzer_coverage_feedback() -> None:
    """Test response size and status code coverage-guided feedback loop."""
    orchestrator = FuzzingOrchestrator([])
    endpoint = "/api/users"

    # First time observing status 200 + size 150 -> coverage increase!
    first = orchestrator.record_feedback(endpoint, 200, 150)
    assert first is True

    # Same status + same size band (100-199 bytes) -> no coverage increase
    second = orchestrator.record_feedback(endpoint, 200, 180)
    assert second is False

    # New status code -> coverage increase!
    third = orchestrator.record_feedback(endpoint, 403, 150)
    assert third is True

    # New size band (200-299 bytes) -> coverage increase!
    fourth = orchestrator.record_feedback(endpoint, 200, 250)
    assert fourth is True


@pytest.mark.anyio
async def test_active_fuzzing_campaign(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test run_fuzzing_campaign executes mutator requests and returns parsed findings."""
    orchestrator = FuzzingOrchestrator([])
    url = "https://api.example.com/search?q=test"

    # Mock HTTP client responses
    class MockResponse:
        def __init__(self, status_code: int, text: str) -> None:
            self.status_code = status_code
            self.text = text

    class MockAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            self.calls = 0

        async def get(self, url: str) -> MockResponse:
            self.calls += 1
            # If injecting single quote, return a simulated SQL error leak
            if "'" in url:
                return MockResponse(200, "SQL syntax error in query line 1")
            # If injecting admin bypass, return 200 OK (base was 403)
            elif "admin" in url:
                return MockResponse(200, "Successfully logged in as admin")
            # Default response
            return MockResponse(403, "Forbidden")

        async def aclose(self) -> None:
            pass

    # Patch AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    findings = await orchestrator.run_fuzzing_campaign(url)

    assert isinstance(findings, list)
    # Fuzzer should identify the simulated SQL injection leak and/or structural bypass
    assert len(findings) > 0
    for f in findings:
        assert f["url"] == url
        assert f["probe_type"] == "fuzzing_campaign"
        assert f["severity"] in {"high", "medium"}
        assert "evidence" in f
