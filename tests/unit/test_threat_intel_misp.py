"""Unit tests for the MISP Client connector and ThreatIntelCorrelator IoC feed checks."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from src.intelligence.feeds.misp import MISPClient, MISPConfig
from src.intelligence.threat_intel import ThreatIntelCorrelator


@pytest.mark.anyio
async def test_misp_client_ioc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test MISPClient REST attribute searching and check_ioc."""
    config = MISPConfig(api_key="test_key_xyz", base_url="https://misp.example.com/api")

    class MockResponse:
        def __init__(self, status_code: int, data: dict) -> None:
            self.status_code = status_code
            self._data = data

        def json(self) -> dict:
            return self._data

        def raise_for_status(self) -> None:
            pass

    async def mock_request(self, method: str, url: str, **kwargs: Any) -> MockResponse:
        headers = self.headers
        assert "Authorization" in headers
        assert headers["Authorization"] == "test_key_xyz"

        json_val = kwargs.get("json", {})
        val = json_val.get("value", "")
        if val == "1.1.1.1":
            return MockResponse(
                200,
                {
                    "response": {
                        "Attribute": [
                            {
                                "event_id": "101",
                                "category": "Network activity",
                                "type": "ip-dst",
                                "value": "1.1.1.1",
                                "Event": {"info": "Known malicious host"},
                            }
                        ]
                    }
                },
            )
        return MockResponse(200, {"response": {}})

    monkeypatch.setattr(httpx.AsyncClient, "request", mock_request)

    async with MISPClient(config) as client:
        # Match malicious host
        res_match = await client.check_ioc("1.1.1.1")
        assert res_match["matched"] is True
        assert len(res_match["events"]) == 1
        assert res_match["events"][0]["event_id"] == "101"
        assert res_match["events"][0]["category"] == "Network activity"

        # Match clean host
        res_clean = await client.check_ioc("clean.example.com")
        assert res_clean["matched"] is False


@pytest.mark.anyio
async def test_threat_intel_correlator_async(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test ThreatIntelCorrelator async matching and findings enrichment."""
    monkeypatch.setenv("PIPELINE_THREAT_INTEL_TEST_MODE", "1")
    correlator = ThreatIntelCorrelator(enable_threat_intel=True)

    # Test match_ioc_async on simulated malicious keyword
    ioc_res = await correlator.match_ioc_async("malicious-c2-server.com")
    assert ioc_res["malicious"] is True
    assert ioc_res["reputation_score"] == 85
    assert "MISP Feed 42" in ioc_res["matched_feeds"]

    # Test enrich_findings_with_intel_async
    findings = [
        {
            "id": "vuln-01",
            "category": "sql_injection",
            "url": "https://malicious-c2-server.com/search",
        },
        {"id": "vuln-02", "category": "xss", "url": "https://clean.example.com/input"},
    ]

    enriched = await correlator.enrich_findings_with_intel_async(findings)

    assert isinstance(enriched, list)
    assert len(enriched) == 2
    # Verify CVE enrichment
    assert "CVE-2024-27956" in enriched[0]["cve_correlations"]
    # Verify IoC correlation enrichment on target URL
    assert "ioc_correlation" in enriched[0]["threat_intel"]
    assert enriched[0]["threat_intel"]["ioc_correlation"]["malicious"] is True
