"""Tests for continuous monitoring and asset inventory."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.monitoring.asset_inventory import (
    AssetDiff,
    AssetInventoryManager,
    AWSAssetInventory,
    AzureAssetInventory,
    CloudAssetInventory,
    GCPAssetInventory,
)
from src.core.monitoring.continuous_scan import (
    ContinuousScanMode,
    ScanCycleResult,
)


class TestAWSAssetInventory:
    @pytest.mark.asyncio
    async def test_discover_assets_no_boto3(self):
        with patch.dict("sys.modules", {"boto3": None}):
            inv = AWSAssetInventory()
            result = await inv.discover_assets()
            assert result == set()

    @pytest.mark.asyncio
    async def test_discover_assets_with_boto3(self):
        fake_boto3 = MagicMock()
        fake_boto3.Session.return_value.region_name = "us-east-1"
        with patch.dict("sys.modules", {"boto3": fake_boto3}):
            inv = AWSAssetInventory()
            result = await inv.discover_assets()
            assert isinstance(result, set)


class TestGCPAssetInventory:
    @pytest.mark.asyncio
    async def test_discover_assets_no_google_cloud(self):
        with patch.dict("sys.modules", {"google.cloud.compute_v1": None, "google.cloud": None}):
            inv = GCPAssetInventory()
            result = await inv.discover_assets()
            assert result == set()


class TestAzureAssetInventory:
    @pytest.mark.asyncio
    async def test_discover_assets_no_azure(self):
        with patch.dict("sys.modules", {"azure.identity": None, "azure.mgmt.compute": None}):
            inv = AzureAssetInventory()
            result = await inv.discover_assets()
            assert result == set()


class TestAssetInventoryManager:
    @pytest.fixture
    def manager(self):
        return AssetInventoryManager({"cloud_providers": "aws,gcp,azure"})

    @pytest.mark.asyncio
    async def test_discover_all_no_providers(self):
        manager = AssetInventoryManager({})
        result = await manager.discover_all()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_register_provider(self, manager):
        provider = AsyncMock(spec=CloudAssetInventory)
        provider.discover_assets.return_value = {"https://example.com"}
        manager.register_provider("test", provider)
        result = await manager.discover_all()
        assert "https://example.com" in result

    @pytest.mark.asyncio
    async def test_diff_against_checkpoint_new_assets(self):
        manager = AssetInventoryManager({})
        checkpoint_mgr = MagicMock()
        state = MagicMock()
        state.scanned_assets = ["https://existing.com"]
        checkpoint_mgr.load.return_value = state
        diff = manager.diff_against_checkpoint(
            {"https://existing.com", "https://new.com"}, checkpoint_mgr
        )
        assert "https://new.com" in diff.new
        assert "https://existing.com" in diff.unchanged
        assert diff.removed == set()

    @pytest.mark.asyncio
    async def test_diff_against_checkpoint_no_previous(self):
        manager = AssetInventoryManager({})
        checkpoint_mgr = MagicMock()
        checkpoint_mgr.load.return_value = None
        diff = manager.diff_against_checkpoint({"https://new.com"}, checkpoint_mgr)
        assert "https://new.com" in diff.new
        assert diff.unchanged == set()
        assert diff.removed == set()


class TestScanCycleResult:
    def test_defaults(self):
        result = ScanCycleResult()
        assert result.new_assets == set()
        assert result.removed_assets == set()
        assert result.scans_triggered == []
        assert result.new_findings == []
        assert result.alerts_sent == 0


class TestContinuousScanMode:
    @pytest.fixture
    def continuous_mode(self):
        orchestrator = MagicMock()
        inventory_mgr = MagicMock()
        inventory_mgr.discover_all = AsyncMock(return_value=set())
        inventory_mgr.diff_against_checkpoint.return_value = AssetDiff(new=set(), removed=set(), unchanged=set())
        checkpoint_mgr = MagicMock()
        return ContinuousScanMode(orchestrator, inventory_mgr, checkpoint_mgr)

    @pytest.mark.asyncio
    async def test_run_cycle_no_assets(self, continuous_mode):
        result = await continuous_mode.run_cycle(output_dir=MagicMock())
        assert result.scans_triggered == []
        assert result.new_assets == set()
        assert result.removed_assets == set()

    @pytest.mark.asyncio
    async def test_persist_assets(self, continuous_mode):
        checkpoint_mgr = MagicMock()
        state = MagicMock()
        checkpoint_mgr.ensure_state.return_value = state
        continuous_mode._checkpoint_mgr = checkpoint_mgr
        await continuous_mode._persist_assets({"https://a.com", "https://b.com"})
        state.scanned_assets = sorted({"https://a.com", "https://b.com"})
        checkpoint_mgr.save.assert_called()

    @pytest.mark.asyncio
    async def test_alert_new_high_severity_no_manager(self, continuous_mode):
        alerts = await continuous_mode._alert_new_high_severity(
            [{"severity": "critical", "url": "https://x.com"}]
        )
        assert alerts == 0

    @pytest.mark.asyncio
    async def test_alert_new_high_severity_with_manager(self, continuous_mode):
        fake_mgr = MagicMock()
        fake_mgr.send_finding = AsyncMock(return_value=[MagicMock(success=True)])
        continuous_mode._notification_manager = fake_mgr
        alerts = await continuous_mode._alert_new_high_severity(
            [{"severity": "critical", "url": "https://x.com"}]
        )
        assert alerts == 1
        fake_mgr.send_finding.assert_called_once()

    @pytest.mark.asyncio
    async def test_alert_skips_non_high(self, continuous_mode):
        fake_mgr = MagicMock()
        fake_mgr.send_finding = AsyncMock()
        continuous_mode._notification_manager = fake_mgr
        alerts = await continuous_mode._alert_new_high_severity(
            [{"severity": "low", "url": "https://x.com"}]
        )
        assert alerts == 0
        fake_mgr.send_finding.assert_not_called()
