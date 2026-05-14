"""Live hosts orchestration service."""

import asyncio
import logging
import time
from typing import Any

from src.analysis.behavior.service_runtime import DEFAULT_PORT_SCAN_TARGETS
from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext


class LiveHostsOrchestrator:
    """Orchestrates live host probing and service enrichment."""

    def __init__(
        self,
        args: Any,
        config: Any,
        ctx: PipelineContext,
        emit_progress_func: Any,
        probe_live_hosts_func: Any,
        run_service_enrichment_func: Any,
        tool_diagnostics_func: Any,
        record_recon_failure_func: Any,
    ) -> None:
        self.args = args
        self.config = config
        self.ctx = ctx
        self.emit_progress = emit_progress_func
        self.probe_live_hosts = probe_live_hosts_func
        self.run_service_enrichment = run_service_enrichment_func
        self.tool_diagnostics = tool_diagnostics_func
        self.record_recon_failure = record_recon_failure_func

    def _parse_analysis_settings(self) -> dict[str, Any]:
        analysis_settings = getattr(self.config, "analysis", {}) or {}
        if not isinstance(analysis_settings, dict):
            analysis_settings = {}
        return analysis_settings

    def _parse_filters(self) -> dict[str, Any]:
        filters = getattr(self.config, "filters", {}) or {}
        if not isinstance(filters, dict):
            filters = {}
        return filters

    def _get_service_scan_config(
        self, analysis_settings: dict[str, Any]
    ) -> tuple[int, int, int, list[int]]:
        service_scan_max_hosts = max(
            1, int(analysis_settings.get("service_scan_max_hosts", 20) or 20)
        )
        service_scan_workers = max(1, int(analysis_settings.get("service_scan_workers", 8) or 8))
        service_scan_timeout_seconds = max(
            1,
            int(
                analysis_settings.get(
                    "service_scan_timeout_seconds",
                    max(2, getattr(self.config, "http_timeout_seconds", 6) // 2 or 3),
                )
                or 3
            ),
        )
        service_scan_ports = analysis_settings.get("service_scan_ports", DEFAULT_PORT_SCAN_TARGETS)
        if not isinstance(service_scan_ports, (list, tuple, set)):
            service_scan_ports = DEFAULT_PORT_SCAN_TARGETS
        parsed_service_scan_ports: list[int] = []
        for port in service_scan_ports:
            try:
                parsed_service_scan_ports.append(int(port))
            except (TypeError, ValueError):
                continue
        return (
            service_scan_max_hosts,
            service_scan_workers,
            service_scan_timeout_seconds,
            parsed_service_scan_ports,
        )

    def _get_enrichment_config(self, analysis_settings: dict[str, Any]) -> tuple[int, int, int]:
        enrichment_heartbeat_seconds = max(
            1,
            int(analysis_settings.get("service_enrichment_progress_interval_seconds", 20) or 20),
        )
        service_enrichment_timeout_reserve_seconds = max(
            1,
            int(
                analysis_settings.get(
                    "service_enrichment_stage_timeout_reserve_seconds",
                    3,
                )
                or 3
            ),
        )
        service_enrichment_max_duration_seconds = max(
            1,
            int(analysis_settings.get("service_enrichment_max_duration_seconds", 180) or 180),
        )
        return (
            enrichment_heartbeat_seconds,
            service_enrichment_timeout_reserve_seconds,
            service_enrichment_max_duration_seconds,
        )

    def _get_stage_timeout_override(self, filters: dict[str, Any]) -> int | None:
        stage_timeout_overrides = filters.get("stage_timeout_overrides", {})
        if not isinstance(stage_timeout_overrides, dict):
            stage_timeout_overrides = {}
        try:
            raw_live_hosts_stage_timeout = stage_timeout_overrides.get("live_hosts")
            live_hosts_stage_timeout_hint = (
                max(1, int(raw_live_hosts_stage_timeout))
                if raw_live_hosts_stage_timeout is not None
                else None
            )
        except (TypeError, ValueError):
            live_hosts_stage_timeout_hint = None
        return live_hosts_stage_timeout_hint

    def _emit_live_hosts_progress(self, message: Any, percent: Any, **meta: Any) -> None:
        try:
            pct = int(percent)
        except (TypeError, ValueError):
            pct = 36
        try:
            processed = int(meta.get("processed", 0) or 0)
        except (TypeError, ValueError):
            processed = 0
        try:
            total = int(meta.get("total", 0) or 0)
        except (TypeError, ValueError):
            total = 0
        try:
            active = int(meta.get("concurrency", 0) or 0)
        except (TypeError, ValueError):
            active = 0
        if active <= 0:
            active = 1
        self.emit_progress(
            "live_hosts",
            str(message),
            max(0, min(100, pct)),
            status="running",
            stage_status="running",
            active_task_count=active,
            targets_done=max(0, processed),
            targets_queued=max(0, total - processed) if total > 0 else 0,
            targets_scanning=min(active, max(0, total - processed)) if total > 0 else active,
            **meta,
        )

    def _emit_enrichment_heartbeat(
        self, elapsed_seconds: float, current_live_hosts: set[str]
    ) -> None:
        self.emit_progress(
            "live_hosts",
            f"Service enrichment still running ({elapsed_seconds:.0f}s elapsed)",
            47,
            status="running",
            stage_status="running",
            targets_done=len(current_live_hosts),
            targets_queued=0,
            targets_scanning=min(self.service_scan_workers, max(1, len(current_live_hosts))),
            event_trigger="recon_live_hosts_enrichment_heartbeat",
            details={
                "elapsed_seconds": round(elapsed_seconds, 2),
                "service_scan_max_hosts": self.service_scan_max_hosts,
                "service_scan_port_count": self.service_scan_port_count,
            },
        )

    async def run(self) -> StageOutput:
        from .async_utils import _run_sync_with_heartbeat

        stage_started = time.monotonic()
        probe_duration = 0.0
        enrichment_duration = 0.0
        persistence_duration = 0.0
        enrichment_timed_out = False
        live_hosts_tool_diagnostics: dict[str, dict[str, Any]] = {}

        # Local state for stage output
        live_records: list[dict[str, Any]] = []
        live_hosts: set[str] = set()
        service_results: dict[str, Any] = {}

        try:
            self.emit_progress("live_hosts", "Probing live hosts", 36)
            stage_started = time.monotonic()
            live_hosts_tool_diagnostics = self.tool_diagnostics(self.config, ("httpx",))
            analysis_settings = self._parse_analysis_settings()

            (
                self.service_scan_max_hosts,
                self.service_scan_workers,
                self.service_scan_timeout_seconds,
                self.service_scan_port_count,
            ) = self._get_service_scan_config(analysis_settings)

            (
                enrichment_heartbeat_seconds,
                service_enrichment_timeout_reserve_seconds,
                service_enrichment_max_duration_seconds,
            ) = self._get_enrichment_config(analysis_settings)

            filters = self._parse_filters()
            live_hosts_stage_timeout_hint = self._get_stage_timeout_override(filters)

            # Compute runtime budget for enrichment
            self.service_enrichment_runtime_budget_seconds = service_enrichment_max_duration_seconds
            if live_hosts_stage_timeout_hint is not None:
                elapsed_before_enrichment = time.monotonic() - stage_started
                remaining_stage_budget = int(
                    live_hosts_stage_timeout_hint
                    - elapsed_before_enrichment
                    - service_enrichment_timeout_reserve_seconds
                )
                self.service_enrichment_runtime_budget_seconds = max(
                    1,
                    min(service_enrichment_max_duration_seconds, remaining_stage_budget),
                )
                if (
                    self.service_enrichment_runtime_budget_seconds
                    < service_enrichment_max_duration_seconds
                ):
                    self.emit_progress(
                        "live_hosts",
                        (
                            "Clamping service enrichment runtime budget to "
                            f"{self.service_enrichment_runtime_budget_seconds}s to respect "
                            f"live_hosts stage timeout ({live_hosts_stage_timeout_hint}s)"
                        ),
                        47,
                        status="running",
                        stage_status="running",
                        event_trigger="recon_live_hosts_enrichment_budget_clamped",
                        details={
                            "service_enrichment_max_duration_seconds": service_enrichment_max_duration_seconds,
                            "service_enrichment_runtime_budget_seconds": self.service_enrichment_runtime_budget_seconds,
                            "live_hosts_stage_timeout_seconds": live_hosts_stage_timeout_hint,
                            "service_enrichment_timeout_reserve_seconds": service_enrichment_timeout_reserve_seconds,
                            "probe_duration_seconds": round(probe_duration, 2),
                        },
                    )

            # Probe live hosts
            probe_started = time.monotonic()
            live_records, live_hosts = await asyncio.to_thread(
                self.probe_live_hosts,
                self.ctx.subdomains,
                self.config,
                self._emit_live_hosts_progress,
                force_recheck=self.args.refresh_cache,
            )
            probe_duration = time.monotonic() - probe_started
            self.emit_progress(
                "live_hosts",
                f"Live-host probe phase completed in {probe_duration:.2f}s",
                47,
                status="running",
                stage_status="running",
                targets_done=len(live_records),
                targets_queued=0,
                targets_scanning=0,
                event_trigger="recon_live_hosts_probe_complete",
                details={
                    "probe_duration_seconds": round(probe_duration, 2),
                    "subdomain_count": len(self.ctx.subdomains),
                    "live_record_count": len(live_records),
                    "live_host_count": len(live_hosts),
                },
            )

            # Run service enrichment
            self.emit_progress(
                "live_hosts",
                (
                    "Starting service enrichment "
                    f"(max_hosts={self.service_scan_max_hosts}, ports={self.service_scan_port_count}, "
                    f"workers={self.service_scan_workers})"
                ),
                47,
                status="running",
                stage_status="running",
                targets_done=len(live_hosts),
                targets_queued=0,
                targets_scanning=min(self.service_scan_workers, max(1, len(live_hosts))),
                event_trigger="recon_live_hosts_enrichment_started",
                details={
                    "service_scan_max_hosts": self.service_scan_max_hosts,
                    "service_scan_port_count": self.service_scan_port_count,
                    "service_scan_workers": self.service_scan_workers,
                    "service_scan_timeout_seconds": self.service_scan_timeout_seconds,
                    "service_enrichment_max_duration_seconds": service_enrichment_max_duration_seconds,
                    "service_enrichment_runtime_budget_seconds": self.service_enrichment_runtime_budget_seconds,
                    "live_hosts_stage_timeout_seconds": live_hosts_stage_timeout_hint,
                },
            )

            enrichment_started = time.monotonic()
            try:
                (
                    enriched_records,
                    enriched_hosts,
                    enriched_services,
                ) = await _run_sync_with_heartbeat(
                    lambda: self.run_service_enrichment(
                        self.ctx.subdomains,
                        live_records,
                        self.config,
                        runtime_budget_seconds=self.service_enrichment_runtime_budget_seconds,
                    ),
                    heartbeat_seconds=enrichment_heartbeat_seconds,
                    on_heartbeat=lambda elapsed: self._emit_enrichment_heartbeat(
                        elapsed, live_hosts
                    ),
                    max_duration_seconds=self.service_enrichment_runtime_budget_seconds,
                )
                live_records, live_hosts, service_results = (
                    enriched_records,
                    enriched_hosts,
                    enriched_services,
                )
                enrichment_duration = time.monotonic() - enrichment_started
                self.emit_progress(
                    "live_hosts",
                    f"Service enrichment completed in {enrichment_duration:.2f}s",
                    47,
                    status="running",
                    stage_status="running",
                    targets_done=len(live_hosts),
                    targets_queued=0,
                    targets_scanning=0,
                    event_trigger="recon_live_hosts_enrichment_complete",
                    details={
                        "enrichment_duration_seconds": round(enrichment_duration, 2),
                        "live_record_count": len(live_records),
                        "live_host_count": len(live_hosts),
                        "service_result_keys": len(service_results),
                    },
                )
            except TimeoutError:
                enrichment_timed_out = True
                enrichment_duration = time.monotonic() - enrichment_started
                service_results = {}
                self.emit_progress(
                    "live_hosts",
                    (
                        "Service enrichment timed out after "
                        f"{enrichment_duration:.0f}s; continuing with probe-phase live hosts"
                    ),
                    47,
                    status="warning",
                    stage_status="running",
                    targets_done=len(live_hosts),
                    targets_queued=0,
                    targets_scanning=0,
                    event_trigger="recon_live_hosts_enrichment_timeout",
                    details={
                        "enrichment_duration_seconds": round(enrichment_duration, 2),
                        "service_enrichment_max_duration_seconds": service_enrichment_max_duration_seconds,
                        "service_enrichment_runtime_budget_seconds": self.service_enrichment_runtime_budget_seconds,
                        "live_hosts_stage_timeout_seconds": live_hosts_stage_timeout_hint,
                        "service_scan_max_hosts": self.service_scan_max_hosts,
                        "service_scan_port_count": self.service_scan_port_count,
                    },
                )

            # Persist live hosts (side effect allowed)
            persistence_started = time.monotonic()
            self.ctx.output_store.write_live_hosts(live_records, live_hosts)
            persistence_duration = time.monotonic() - persistence_started
            self.emit_progress(
                "live_hosts",
                f"Live-host artifact persistence completed in {persistence_duration:.2f}s",
                47,
                status="running",
                stage_status="running",
                targets_done=len(live_hosts),
                targets_queued=0,
                targets_scanning=0,
                event_trigger="recon_live_hosts_persistence_complete",
                details={
                    "persistence_duration_seconds": round(persistence_duration, 2),
                },
            )

            # Record stage metrics
            stage_duration = time.monotonic() - stage_started
            services_discovered = len(service_results.get("port_scan_integration", []))
            stage_details = {
                "subdomain_count": len(self.ctx.subdomains),
                "live_record_count": len(live_records),
                "live_host_count": len(live_hosts),
                "services_discovered": services_discovered,
                "probe_duration_seconds": round(probe_duration, 2),
                "enrichment_duration_seconds": round(enrichment_duration, 2),
                "persistence_duration_seconds": round(persistence_duration, 2),
                "service_enrichment_timed_out": enrichment_timed_out,
                "service_enrichment_runtime_budget_seconds": self.service_enrichment_runtime_budget_seconds,
                "live_hosts_stage_timeout_seconds": live_hosts_stage_timeout_hint,
            }

            if len(live_hosts) == 0:
                self.emit_progress(
                    "live_hosts",
                    "Warning: Recon found no alive hosts. Downstream stages will have no targets.",
                    48,
                    status="warning",
                )
                module_metrics = {
                    "status": "warning",
                    "duration_seconds": round(stage_duration, 2),
                    "details": stage_details,
                    "fatal": False,
                }
            elif enrichment_timed_out:
                module_metrics = {
                    "status": "warning",
                    "duration_seconds": round(stage_duration, 2),
                    "details": stage_details,
                    "fatal": False,
                }
            else:
                module_metrics = {
                    "status": "ok",
                    "duration_seconds": round(stage_duration, 2),
                    "details": stage_details,
                    "fatal": False,
                }

            self.emit_progress(
                "live_hosts",
                f"Found {len(live_hosts)} live hosts",
                48,
                stage_percent=100,
                status="running",
                stage_status="running",
                high_value_target_count=len(live_hosts),
                targets_done=len(live_hosts),
                targets_queued=0,
                targets_scanning=0,
                event_trigger="recon_live_hosts_discovered",
            )

            state_delta: dict[str, Any] = {
                "live_records": live_records,
                "live_hosts": live_hosts,
                "service_results": service_results,
                "module_metrics": {"live_hosts": module_metrics},
            }
            return StageOutput(
                stage_name="live_hosts",
                outcome=StageOutcome.COMPLETED,
                duration_seconds=stage_duration,
                metrics=module_metrics,
                state_delta=state_delta,
            )

        except Exception as exc:
            logger = logging.getLogger(__name__)
            logger.error("Stage 'live_hosts' failed: %s", exc)
            # Reset state to empty in state_delta
            state_delta = {
                "live_records": [],
                "live_hosts": set(),
                "service_results": {},
                "module_metrics": {
                    "live_hosts": {
                        "status": "error",
                        "error": str(exc),
                        "duration_seconds": 0.0,
                    }
                },
            }
            failure_details: dict[str, Any] = {
                "exception_type": exc.__class__.__name__,
                "tool_diagnostics": live_hosts_tool_diagnostics,
            }
            if probe_duration > 0:
                failure_details["probe_duration_seconds"] = round(probe_duration, 2)
            if enrichment_duration > 0:
                failure_details["enrichment_duration_seconds"] = round(enrichment_duration, 2)
            if persistence_duration > 0:
                failure_details["persistence_duration_seconds"] = round(persistence_duration, 2)

            self.record_recon_failure(
                stage_name="live_hosts",
                ctx=self.ctx,
                reason_code="live_hosts_stage_exception",
                error=f"Live-host probing failed: {exc}",
                details=failure_details,
                duration_seconds=None,
                failure_step="src.recon.live_hosts.probe_live_hosts",
                fatal=True,
            )
            duration = round(time.monotonic() - stage_started, 2) if stage_started else 0.0
            return StageOutput(
                stage_name="live_hosts",
                outcome=StageOutcome.FAILED,
                duration_seconds=duration,
                error=str(exc),
                reason="live_hosts_stage_exception",
                metrics=state_delta["module_metrics"]["live_hosts"],
                state_delta=state_delta,
            )
