from unittest.mock import AsyncMock

try:
    import pytest
except ImportError:
    class _PytestMock:
        class mark:
            @staticmethod
            def asyncio(f):
                return f
    pytest = _PytestMock()  # type: ignore[assignment]

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
    assert any("a.com" in f["url"] for r in result.results for f in r.findings)


@pytest.mark.asyncio
async def test_coordinator_boosting():
    # Use URLs with significant path overlap to trigger boosting
    urls = ["https://example.com/api/v1/target", "https://example.com/api/v1/vulnerable"]

    # Mock probe that returns a finding for /vulnerable
    async def mock_probe(url):
        if "vulnerable" in url:
            # Finding on /vulnerable should boost /target due to path overlap
            return [{"url": url, "category": "idor", "severity": "high"}]
        return []

    coordinator = AdaptiveScanCoordinator(
        urls, mock_probe, batch_size=1, boost_on_findings=True, early_terminate=False
    )

    # Force /vulnerable to be scanned first by boosting it manually
    coordinator._queue.boost_url("https://example.com/api/v1/vulnerable", factor=10.0)

    result = await coordinator.run()

    assert result.scanned == 2
    assert result.findings_count == 1


@pytest.mark.asyncio
async def test_coordinator_with_hunt_budget_exhaustion():
    from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer

    urls = [f"https://example.com/api/{i}" for i in range(20)]
    enforcer = HuntBudgetEnforcer(budget=HuntBudget(max_requests=2))

    async def mock_probe(url):
        return []

    coordinator = AdaptiveScanCoordinator(
        urls,
        mock_probe,
        batch_size=1,
        concurrency=1,
        early_terminate=True,
        early_terminate_min=1,
        budget_enforcer=enforcer,
    )
    result = await coordinator.run()

    assert result.early_terminated is True
    assert enforcer.is_exhausted()
    assert result.budget_snapshot is not None
