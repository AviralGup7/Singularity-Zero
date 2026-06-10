"""Continuous scan mode with asset inventory and diff-based scheduling."""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.monitoring.asset_inventory import AssetInventoryManager
from src.infrastructure.notifications.manager import NotificationManager

logger = get_pipeline_logger(__name__)


@dataclass
class ScanCycleResult:
    new_assets: set[str] = field(default_factory=set)
    removed_assets: set[str] = field(default_factory=set)
    scans_triggered: list[str] = field(default_factory=list)
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    alerts_sent: int = 0


class ContinuousScanMode:
    def __init__(
        self,
        orchestrator: Any,
        inventory_mgr: AssetInventoryManager,
        checkpoint_mgr: Any,
        alert_callback: Any | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._inventory_mgr = inventory_mgr
        self._checkpoint_mgr = checkpoint_mgr
        self._alert_callback = alert_callback
        self._notification_manager: NotificationManager | None = None

    async def _ensure_notification_manager(self) -> NotificationManager | None:
        if self._notification_manager is None:
            try:
                from src.infrastructure.notifications.manager import ManagerConfig
                mgr = NotificationManager(ManagerConfig())
                await mgr.initialize()
                self._notification_manager = mgr
            except Exception as exc:
                logger.warning("Notification manager initialization failed: %s", exc)
                return None
        return self._notification_manager

    async def _persist_assets(self, assets: set[str]) -> None:
        try:
            state = self._checkpoint_mgr.ensure_state()
            state.scanned_assets = sorted(assets)
            self._checkpoint_mgr.save(state)
        except Exception as exc:
            logger.warning("Failed to persist scanned_assets: %s", exc)

    async def _load_previous_findings(self) -> list[dict[str, Any]]:
        try:
            state = self._checkpoint_mgr.load()
            if state is None:
                return []
            stored = getattr(state, "previous_findings", None)
            if isinstance(stored, list):
                return stored
            return []
        except Exception:
            return []

    async def _alert_new_high_severity(self, new_findings: list[dict[str, Any]]) -> int:
        notification_mgr = await self._ensure_notification_manager()
        if notification_mgr is None:
            return 0
        alerts_sent = 0
        for finding in new_findings:
            severity = str(finding.get("severity", "")).lower()
            if severity not in ("high", "critical"):
                continue
            try:
                results = await notification_mgr.send_finding(
                    finding_title=finding.get("title", "High/Critical Finding"),
                    finding_description=f"Asset: {finding.get('url', 'unknown')}",
                    severity=severity,
                    target=finding.get("target"),
                    endpoint=finding.get("url"),
                    correlation_id=None,
                )
                if results:
                    alerts_sent += 1
            except Exception as exc:
                logger.warning("Failed to send alert for finding: %s", exc)
        return alerts_sent

    async def _run_pipeline_for_scope(self, scope_entries: list[str], output_dir: Path, target_name: str, config_path: Path) -> int:
        scope_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(scope_entries) + "\n")
                scope_file = f.name
            cycle_args = argparse.Namespace(
                config=str(config_path),
                scope=scope_file,
                force_fresh_run=True,
                dry_run=False,
                skip_crtsh=False,
                refresh_cache=False,
                validate_config=False,
                policy=None,
                incremental=False,
                base_ref=None,
                branch=None,
                legacy_exit_codes=False,
                resume_from=None,
                max_duration_seconds=None,
                ci_fail_on_severity=None,
                continuous=False,
                monitor_interval=3600,
                asset_diff_only=False,
                replay_archive=None,
            )
            return self._orchestrator.run_sync(cycle_args)
        finally:
            if scope_file and Path(scope_file).exists():
                Path(scope_file).unlink(missing_ok=True)

    async def run_cycle(self, output_dir: Path, target_name: str = "continuous", asset_diff_only: bool = False, config_path: Path | None = None) -> ScanCycleResult:
        result = ScanCycleResult()
        current_assets = await self._inventory_mgr.discover_all()
        asset_diff = self._inventory_mgr.diff_against_checkpoint(current_assets, self._checkpoint_mgr)
        result.new_assets = asset_diff.new
        result.removed_assets = asset_diff.removed

        scan_targets = asset_diff.new | asset_diff.unchanged
        if asset_diff_only:
            scan_targets = asset_diff.new
        result.scans_triggered = sorted(scan_targets)

        if not scan_targets:
            logger.info("No new or changed assets to scan this cycle")
            await self._persist_assets(current_assets)
            return result

        if config_path is None:
            config_path = Path("configs/pipeline.json")

        await self._run_pipeline_for_scope(sorted(scan_targets), output_dir, target_name, config_path)
        result.scans_triggered = sorted(scan_targets)

        try:
            state = self._checkpoint_mgr.load()
            if state is not None:
                findings = []
                for key in ("reportable_findings", "merged_findings", "nuclei_findings"):
                    raw = getattr(state, key, None)
                    if isinstance(raw, list):
                        findings.extend(raw)
                previous_findings = await self._load_previous_findings()
                prev_keys = {
                    (f.get("url", ""), f.get("category", ""), f.get("severity", ""))
                    for f in previous_findings
                }
                new_high = [
                    f for f in findings
                    if (f.get("url", ""), f.get("category", ""), f.get("severity", "")) not in prev_keys
                    and f.get("severity", "").lower() in ("high", "critical")
                ]
                result.new_findings = new_high
                result.alerts_sent = await self._alert_new_high_severity(new_high)
                state.previous_findings = findings
                self._checkpoint_mgr.save(state)
        except Exception as exc:
            logger.warning("Failed to evaluate findings for alerts: %s", exc)

        await self._persist_assets(current_assets)
        return result

    async def run_continuous(self, interval_seconds: int = 3600, output_dir: Path = Path("output"), target_name: str = "continuous", asset_diff_only: bool = False, config_path: Path | None = None) -> None:
        logger.info("Starting continuous scan mode (interval=%ds)", interval_seconds)
        try:
            while True:
                cycle_start = asyncio.get_running_loop().time()
                try:
                    result = await self.run_cycle(
                        output_dir=output_dir,
                        target_name=target_name,
                        asset_diff_only=asset_diff_only,
                        config_path=config_path,
                    )
                    logger.info(
                        "Cycle complete: new=%d removed=%d scans=%d alerts=%d",
                        len(result.new_assets),
                        len(result.removed_assets),
                        len(result.scans_triggered),
                        result.alerts_sent,
                    )
                except Exception as exc:
                    logger.exception("Continuous scan cycle failed: %s", exc)
                elapsed = asyncio.get_running_loop().time() - cycle_start
                wait = max(0, interval_seconds - elapsed)
                await asyncio.sleep(wait)
        except asyncio.CancelledError:
            logger.info("Continuous scan mode cancelled")
