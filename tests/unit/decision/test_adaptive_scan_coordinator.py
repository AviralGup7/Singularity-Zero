"""Unit tests for the AdaptiveScanCoordinator."""

from unittest.mock import AsyncMock

import pytest

from src.decision.adaptive_scan import AdaptiveScanCoordinator


@pytest.mark.asyncio
async def test_coordinator_initialization():
    urls = ["https://example.com/api", "https://example.com/login"]
    probe_fn = AsyncMock(return_value=[])

    coordinator = AdaptiveScanCoordinator(urls, probe_fn)
    assert coordinator._batch_size == 50
    assert coordinator._concurrency == 10

@pytest.mark.asyncio
async def test_coordinator_run_empty():
    coordinator = AdaptiveScanCoordinator([], AsyncMock(), early_terminate=False)
    result = await coordinator.run()
    assert result.scanned == 0
    assert result.findings_count == 0

@pytest.mark.asyncio
async def test_coordinator_scan_batch():
    urls = ["https://a.com", "https://b.com"]
    # Mock probe that returns a finding for a.com
    async def mock_probe(url):
        if "a.com" in url:
            return [{"url": url, "category": "test", "severity": "high"}]
        return []

    coordinator = AdaptiveScanCoordinator(urls, mock_probe, batch_size=2, early_terminate=False)
    result = await coordinator.run()

    assert result.scanned == 2
    assert result.findings_count == 1
    assert any("a.com" in f["url"] for f in result.results[0].findings)
@pytest.mark.asyncio
async def test_coordinator_boosting():
    # Use URLs with significant path overlap to trigger boosting
    urls = [
        "https://example.com/api/v1/target",
        "https://example.com/api/v1/vulnerable"
    ]

    # Mock probe that returns a finding for /vulnerable
    async def mock_probe(url):
        if "vulnerable" in url:
            # Finding on /vulnerable should boost /target due to path overlap
            return [{"url": url, "category": "idor", "severity": "high"}]
        return []

    coordinator = AdaptiveScanCoordinator(
        urls,
        mock_probe,
        batch_size=1,
        boost_on_findings=True,
        early_terminate=False
    )

    # Force /vulnerable to be scanned first by boosting it manually
    coordinator._queue.boost_url("https://example.com/api/v1/vulnerable", factor=10.0)

    result = await coordinator.run()

    assert result.scanned == 2
    assert result.findings_count == 1
    assert result.boosted_count >= 1

    # Check if /target was boosted
    target_item = coordinator._queue._url_map["https://example.com/api/v1/target"]
    assert any("path_overlap" in b for b in target_item.boost_factors)

