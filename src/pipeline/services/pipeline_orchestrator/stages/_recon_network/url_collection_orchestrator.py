"""URL collection orchestration service."""

import asyncio
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext
from src.recon.common import normalize_url

from .async_utils import _run_sync_with_heartbeat
from .url_stats import _should_refresh_low_signal_url_cache, _url_discovery_stats


class UrlCollectionOrchestrator:
    """Orchestrates URL collection from live hosts."""

    def __init__(
        self,
        args: Any,
        config: Any,
        ctx: PipelineContext,
        emit_progress_func: Any,
        emit_url_progress_func: Any,
        collect_urls_func: Any,
        resolve_cached_stage_func: Any,
        load_cached_set_func: Any,
        save_cached_set_func: Any,
        load_cached_json_func: Any,
        save_cached_json_func: Any,
        validate_recon_payload_func: Any,
        tool_diagnostics_func: Any,
        record_recon_failure_func: Any,
    ) -> None:
        self.args = args
        self.config = config
        self.ctx = ctx
        self.emit_progress = emit_progress_func
        self.emit_url_progress = emit_url_progress_func
        self.collect_urls = collect_urls_func
        self.resolve_cached_stage = resolve_cached_stage_func
        self.load_cached_set = load_cached_set_func
        self.save_cached_set = save_cached_set_func
        self.load_cached_json = load_cached_json_func
        self.save_cached_json = save_cached_json_func
        self.validate_recon_payload = validate_recon_payload_func
        self.tool_diagnostics = tool_diagnostics_func
        self.record_recon_failure = record_recon_failure_func

    def _parse_filters(self) -> dict[str, Any]:
        filters = getattr(self.config, "filters", {}) or {}
        if not isinstance(filters, dict):
            filters = {}
        return filters

    def _get_url_collection_config(self, filters: dict[str, Any]) -> None:
        """Parse and store URL collection config as instance attributes."""
        self.url_collection_heartbeat_seconds = max(
            1,
            int(filters.get("url_collection_progress_interval_seconds", 20) or 20),
        )
        self.url_collection_max_duration_seconds = max(
            1,
            int(filters.get("url_collection_max_duration_seconds", 480) or 480),
        )
        self.url_recollection_max_duration_seconds = max(
            1,
            int(
                filters.get(
                    "url_recollection_max_duration_seconds",
                    self.url_collection_max_duration_seconds,
                )
                or self.url_collection_max_duration_seconds
            ),
        )

    def _emit_url_collection_heartbeat(self, elapsed_seconds: float) -> None:
        self.emit_progress(
            "urls",
            f"URL provider orchestration still running ({elapsed_seconds:.0f}s elapsed)",
            56,
            status="running",
            stage_status="running",
            event_trigger="recon_urls_collection_heartbeat",
            details={
                "elapsed_seconds": round(elapsed_seconds, 2),
                "live_host_count": len(self.ctx.live_hosts),
            },
        )

    def _emit_refresh_heartbeat(self, elapsed_seconds: float) -> None:
        self.emit_progress(
            "urls",
            f"Fresh URL recollection still running ({elapsed_seconds:.0f}s elapsed)",
            58,
            status="running",
            stage_status="running",
            event_trigger="recon_urls_recollection_heartbeat",
            details={
                "elapsed_seconds": round(elapsed_seconds, 2),
                "live_host_count": len(self.ctx.live_hosts),
            },
        )

    async def run(self) -> StageOutput:
        stage_started = time.monotonic()
        url_tool_diagnostics: dict[str, dict[str, Any]] = {}

        # Local mutable state (not written to ctx.result)
        self._urls: set[str] = set()
        self._url_meta: dict[str, Any] = {}

        try:
            self.emit_progress("urls", "Collecting URLs", 56)
            stage_started = time.monotonic()
            url_tool_diagnostics = self.tool_diagnostics(
                self.config, ("gau", "waybackurls", "katana")
            )
            url_cache_path = self.ctx.output_store.cache_root / "urls.json"
            refresh_cache = bool(getattr(self.args, "refresh_cache", False))

            filters = self._parse_filters()
            self._get_url_collection_config(filters)

            cached_urls: set[str] = set()
            if self.ctx.use_cache and not refresh_cache:
                cached_urls = await asyncio.to_thread(self.load_cached_set, url_cache_path)

            self.emit_progress(
                "urls",
                f"Starting URL provider orchestration across {len(self.ctx.live_hosts)} live hosts",
                56,
                status="running",
                stage_status="running",
                event_trigger="recon_urls_collection_started",
                details={
                    "live_host_count": len(self.ctx.live_hosts),
                    "use_cache": bool(self.ctx.use_cache),
                },
            )

            # Primary collection phase
            fallback_urls = {
                normalize_url(host) for host in self.ctx.live_hosts if normalize_url(host)
            }
            try:
                self._urls = await self._run_collection_phase(
                    url_cache_path,
                    refresh_cache,
                    self.url_collection_heartbeat_seconds,
                    self.url_collection_max_duration_seconds,
                    self._url_meta,
                )
            except TimeoutError:
                self._handle_collection_timeout(fallback_urls)

            # Check for budget exceed
            collection_budget_meta: dict[str, Any] = {}
            if isinstance(self._url_meta, dict):
                candidate_meta = self._url_meta.get("collection_budget", {})
                if isinstance(candidate_meta, dict):
                    collection_budget_meta = candidate_meta
            collection_budget_exceeded = bool(collection_budget_meta.get("budget_exceeded", False))
            if collection_budget_exceeded:
                self._handle_budget_exceeded(collection_budget_meta)

            # Persist cache metadata
            used_cached_urls = bool(cached_urls)
            await self._persist_url_cache(used_cached_urls, self._url_meta)

            # Validate and compute stats
            self.validate_recon_payload(
                {"urls": sorted(self._urls), "live_hosts": sorted(self.ctx.live_hosts)}
            )
            stage_duration = time.monotonic() - stage_started
            (
                fallback_urls_stat,
                discovered_urls,
                source_contribution,
                source_contribution_inferred,
            ) = _url_discovery_stats(
                self._urls,
                self.ctx.live_hosts,
                self._url_meta,
            )
            if source_contribution_inferred:
                self.emit_progress(
                    "urls",
                    "URL source metadata missing from cache; inferring contribution from discovered URLs",
                    57,
                    status="running",
                    stage_status="running",
                    source_contribution_inferred=True,
                    discovered_url_count=len(discovered_urls),
                )

            # Check if cache needs refresh due to low signal
            if (
                self.ctx.use_cache
                and not bool(getattr(self.args, "refresh_cache", False))
                and _should_refresh_low_signal_url_cache(
                    self.config,
                    live_host_count=len(self.ctx.live_hosts),
                    total_url_count=len(self._urls),
                    discovered_url_count=len(discovered_urls),
                    source_contribution_inferred=source_contribution_inferred,
                )
            ):
                self.emit_progress(
                    "urls",
                    "Cached URL corpus looks low-signal; recollecting fresh URLs",
                    58,
                    status="running",
                    stage_status="running",
                    cached_url_count=len(self._urls),
                    cached_discovered_url_count=len(discovered_urls),
                    live_host_count=len(self.ctx.live_hosts),
                )
                self.fresh_stage_meta: dict[str, Any] = {}
                fresh_urls = await self._run_refresh_phase(
                    self.url_recollection_max_duration_seconds,
                    self.fresh_stage_meta,
                )
                await self._process_refresh_results(fresh_urls)
                # Recompute stats after potential refresh
                (
                    fallback_urls_stat,
                    discovered_urls,
                    source_contribution,
                    source_contribution_inferred,
                ) = _url_discovery_stats(
                    self._urls,
                    self.ctx.live_hosts,
                    self._url_meta,
                )

            # Compute final metrics
            stage_duration = time.monotonic() - stage_started
            unavailable_source_tools = sorted(
                tool_name
                for tool_name, diag in url_tool_diagnostics.items()
                if bool(diag.get("configured")) and not bool(diag.get("available"))
            )
            if len(self._urls) == 0:
                self.emit_progress(
                    "urls",
                    "Warning: URL stage collected no URLs.",
                    60,
                    status="warning",
                )
                module_metrics = {
                    "status": "warning",
                    "duration_seconds": round(stage_duration, 2),
                    "details": {
                        "live_host_count": len(self.ctx.live_hosts),
                        "source_contribution_count": source_contribution,
                        "fallback_url_count": len(fallback_urls),
                        "collection_budget_exceeded": collection_budget_exceeded,
                        "collection_budget_phase": collection_budget_meta.get("phase", ""),
                        "sources": self._url_meta,
                        "source_contribution_inferred": source_contribution_inferred,
                        "tool_diagnostics": url_tool_diagnostics,
                    },
                    "fatal": False,
                }
            elif len(discovered_urls) == 0 or source_contribution == 0:
                fallback_only_error = "Warning: URL collection produced only fallback seed URLs and no discovery-source URLs."
                if unavailable_source_tools:
                    fallback_only_error = (
                        f"{fallback_only_error} "
                        f"Unavailable source tools: {', '.join(unavailable_source_tools)}."
                    )
                self.emit_progress(
                    "urls",
                    fallback_only_error,
                    60,
                    status="warning",
                )
                module_metrics = {
                    "status": "warning",
                    "duration_seconds": round(stage_duration, 2),
                    "details": {
                        "url_count": len(self._urls),
                        "fallback_url_count": len(fallback_urls),
                        "discovered_url_count": len(discovered_urls),
                        "source_contribution_count": source_contribution,
                        "collection_budget_exceeded": collection_budget_exceeded,
                        "collection_budget_phase": collection_budget_meta.get("phase", ""),
                        "sources": self._url_meta,
                        "source_contribution_inferred": source_contribution_inferred,
                        "tool_diagnostics": url_tool_diagnostics,
                        "unavailable_source_tools": unavailable_source_tools,
                    },
                    "fatal": False,
                }
            else:
                module_metrics = {
                    "status": "ok",
                    "duration_seconds": round(stage_duration, 2),
                    "details": {
                        "url_count": len(self._urls),
                        "fallback_url_count": len(fallback_urls),
                        "discovered_url_count": len(discovered_urls),
                        "source_contribution_count": source_contribution,
                        "collection_budget_exceeded": collection_budget_exceeded,
                        "collection_budget_phase": collection_budget_meta.get("phase", ""),
                        "sources": self._url_meta,
                        "source_contribution_inferred": source_contribution_inferred,
                        "tool_diagnostics": url_tool_diagnostics,
                    },
                    "fatal": False,
                }
            self.emit_progress(
                "urls",
                f"Collected {len(self._urls)} URLs",
                68,
                stage_percent=100,
                status="running",
                stage_status="running",
                high_value_target_count=len(discovered_urls),
                signal_noise_ratio=round(len(discovered_urls) / max(1, len(self._urls)), 3),
                targets_done=len(self._urls),
                targets_queued=0,
                targets_scanning=0,
                event_trigger="recon_urls_collected",
            )

            state_delta: dict[str, Any] = {
                "urls": self._urls,
                "url_stage_meta": self._url_meta,
                "module_metrics": {"urls": module_metrics},
            }
            return StageOutput(
                stage_name="urls",
                outcome=StageOutcome.COMPLETED,
                duration_seconds=stage_duration,
                metrics=module_metrics,
                state_delta=state_delta,
            )

        except Exception as exc:
            import logging

            logger = logging.getLogger(__name__)
            logger.error("Stage 'urls' failed: %s", exc)
            state_delta = {
                "urls": set(),
                "url_stage_meta": {},
                "module_metrics": {
                    "urls": {
                        "status": "error",
                        "error": str(exc),
                        "duration_seconds": 0.0,
                    }
                },
            }
            self.record_recon_failure(
                stage_name="urls",
                ctx=self.ctx,
                reason_code="url_collection_stage_exception",
                error=f"URL collection failed: {exc}",
                details={"exception_type": exc.__class__.__name__},
                duration_seconds=None,
                failure_step="src.recon.urls.collect_urls",
                fatal=True,
            )
            duration = round(time.monotonic() - stage_started, 2) if stage_started else 0.0
            return StageOutput(
                stage_name="urls",
                outcome=StageOutcome.FAILED,
                duration_seconds=duration,
                error=str(exc),
                reason="url_collection_stage_exception",
                metrics=state_delta["module_metrics"]["urls"],
                state_delta=state_delta,
            )

    async def _run_collection_phase(
        self,
        url_cache_path: Any,
        refresh_cache: bool,
        heartbeat_sec: int,
        max_duration_sec: int,
        stage_meta: dict[str, Any],
    ) -> set[str]:
        """Run primary URL collection with heartbeat."""
        return await _run_sync_with_heartbeat(
            lambda: self._collect_urls_sync(
                self.ctx.use_cache, refresh_cache, url_cache_path, stage_meta
            ),
            heartbeat_seconds=heartbeat_sec,
            on_heartbeat=self._emit_url_collection_heartbeat,
            max_duration_seconds=max_duration_sec,
        )

    def _collect_urls_sync(
        self,
        use_cache: bool,
        refresh_cache: bool,
        url_cache_path: Any,
        stage_meta: dict[str, Any],
    ) -> set[str]:
        if use_cache:
            from typing import cast
            return cast(set[str], self.resolve_cached_stage(
                url_cache_path,
                refresh_cache,
                lambda: self.collect_urls(
                    self.ctx.live_hosts,
                    self.ctx.scope_entries,
                    self.config,
                    progress_callback=self.emit_url_progress,
                    stage_meta=stage_meta,
                    runtime_budget_seconds=self.url_collection_max_duration_seconds,
                ),
            ))
        from typing import cast
        return cast(set[str], self.collect_urls(
            self.ctx.live_hosts,
            self.ctx.scope_entries,
            self.config,
            self.emit_url_progress,
            stage_meta,
            runtime_budget_seconds=self.url_collection_max_duration_seconds,
        ))

    def _handle_collection_timeout(self, fallback_urls: set[str]) -> None:
        self.emit_progress(
            "urls",
            (
                "URL provider orchestration timed out after "
                f"{self.url_collection_max_duration_seconds}s; continuing with live-host fallback URLs"
            ),
            58,
            status="warning",
            stage_status="running",
            event_trigger="recon_urls_collection_timeout",
            details={
                "url_collection_max_duration_seconds": self.url_collection_max_duration_seconds,
                "live_host_count": len(self.ctx.live_hosts),
                "fallback_url_count": len(fallback_urls),
            },
        )
        self._urls = fallback_urls
        self._url_meta.clear()

    def _handle_budget_exceeded(self, budget_meta: dict[str, Any]) -> None:
        self.emit_progress(
            "urls",
            (
                "URL provider orchestration reached runtime budget during "
                f"{budget_meta.get('phase', 'collection')}; continuing with collected URLs"
            ),
            58,
            status="warning",
            stage_status="running",
            event_trigger="recon_urls_collection_timeout",
            details={
                "url_collection_max_duration_seconds": self.url_collection_max_duration_seconds,
                "live_host_count": len(self.ctx.live_hosts),
                "collected_url_count": len(self._urls),
                "budget_phase": budget_meta.get("phase", ""),
                "elapsed_seconds": budget_meta.get("elapsed_seconds", 0),
            },
        )

    async def _persist_url_cache(
        self,
        used_cached_urls: bool,
        stage_meta: dict[str, Any],
    ) -> None:
        if used_cached_urls:
            try:
                cached_meta = self.load_cached_json(
                    self.ctx.output_store.cache_root / "urls_meta.json"
                )
            except Exception:
                cached_meta = {}
            if cached_meta:
                stage_meta.clear()
                stage_meta.update(cached_meta)
        else:
            try:
                await asyncio.to_thread(
                    self.save_cached_json,
                    self.ctx.output_store.cache_root / "urls_meta.json",
                    stage_meta,
                )
            except Exception:
                pass

    async def _run_refresh_phase(
        self,
        recollection_max_sec: int,
        fresh_meta: dict[str, Any],
    ) -> set[str] | None:
        try:
            fresh_urls = await _run_sync_with_heartbeat(
                lambda: self.collect_urls(
                    self.ctx.live_hosts,
                    self.ctx.scope_entries,
                    self.config,
                    self.emit_url_progress,
                    fresh_meta,
                    runtime_budget_seconds=recollection_max_sec,
                ),
                heartbeat_seconds=self.url_collection_heartbeat_seconds,
                on_heartbeat=self._emit_refresh_heartbeat,
                max_duration_seconds=recollection_max_sec,
            )
            self.fresh_stage_meta = fresh_meta  # store for processing
            from typing import cast
            return cast(set[str] | None, fresh_urls)
        except TimeoutError:
            self.emit_progress(
                "urls",
                (
                    "Fresh URL recollection timed out after "
                    f"{recollection_max_sec}s; keeping existing URL corpus"
                ),
                58,
                status="warning",
                stage_status="running",
                event_trigger="recon_urls_recollection_timeout",
                details={
                    "url_recollection_max_duration_seconds": recollection_max_sec,
                    "live_host_count": len(self.ctx.live_hosts),
                    "cached_url_count": len(self._urls),
                },
            )
            return None

    async def _process_refresh_results(
        self,
        fresh_urls: set[str] | None,
    ) -> None:
        if not fresh_urls:
            return
        refresh_budget_meta: dict[str, Any] = {}
        if hasattr(self, "fresh_stage_meta") and isinstance(self.fresh_stage_meta, dict):
            candidate_refresh_meta = self.fresh_stage_meta.get("collection_budget", {})
            if isinstance(candidate_refresh_meta, dict):
                refresh_budget_meta = candidate_refresh_meta
        refresh_budget_exceeded = bool(refresh_budget_meta.get("budget_exceeded", False))
        if refresh_budget_exceeded:
            self.emit_progress(
                "urls",
                (
                    "Fresh URL recollection reached runtime budget during "
                    f"{refresh_budget_meta.get('phase', 'collection')}; keeping existing URL corpus"
                ),
                58,
                status="warning",
                stage_status="running",
                event_trigger="recon_urls_recollection_timeout",
                details={
                    "url_recollection_max_duration_seconds": self.url_recollection_max_duration_seconds,
                    "live_host_count": len(self.ctx.live_hosts),
                    "cached_url_count": len(self._urls),
                    "budget_phase": refresh_budget_meta.get("phase", ""),
                    "elapsed_seconds": refresh_budget_meta.get("elapsed_seconds", 0),
                },
            )
        else:
            self._urls.clear()
            self._urls.update(fresh_urls)
            self._url_meta.clear()
            self._url_meta.update(self.fresh_stage_meta)
            await asyncio.to_thread(
                self.save_cached_set,
                self.ctx.output_store.cache_root / "urls.json",
                set(self._urls),
            )
            try:
                meta_path = self.ctx.output_store.cache_root / "urls_meta.json"
                await asyncio.to_thread(self.save_cached_json, meta_path, self._url_meta)
            except Exception:
                pass
            self.ctx.output_store.write_urls(self._urls)
            self.validate_recon_payload(
                {"urls": sorted(self._urls), "live_hosts": sorted(self.ctx.live_hosts)}
            )
