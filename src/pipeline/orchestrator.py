from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from src.core.checkpoint.manager import CheckpointManager, LocalCheckpointStore
from src.core.config.typed_config import ValidatedPipelineConfig
from src.core.events.event_bus import get_event_bus
from src.core.ids import generate_run_id
from src.core.storage.abstraction import create_storage_backend
from src.pipeline.engine import (
    ExecutionContext,
    PipelineEngine,
    PipelineState,
    Stage,
    StageArtifacts,
)

logger = logging.getLogger(__name__)


# Built-in stages
class SubdomainDiscoveryStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("subdomain_discovery", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        from src.core.config.typed_config import PipelineConfig

        config = PipelineConfig(
            target_name=context.target_name,
            output_dir=context.config.get("output_dir", "output"),
            http_timeout_seconds=context.config.get("http_timeout_seconds", 12),
            mode=context.config.get("mode", "default"),
            cache=context.config.get("cache", {}),
            tools=context.config.get("tools", {}),
        )

        enumerator = getattr(context, "subdomain_enumerator", None) or context.config.get(
            "subdomain_enumerator"
        )
        if enumerator is None:
            from src.recon.subdomains import enumerate_subdomains

            enumerator = enumerate_subdomains

        subdomains = await enumerator(state.scope_entries, config, skip_crtsh=False)

        return StageArtifacts(
            subdomains=frozenset(subdomains),
        )


class LiveHostProbingStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("live_host_probing", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        prober = getattr(context, "live_host_prober", None) or context.config.get(
            "live_host_prober"
        )
        if prober is None:
            from src.recon.live_hosts import probe_live_hosts

            prober = probe_live_hosts

        live_hosts, live_records = await prober(
            state.subdomains,
            context.config,
            lambda msg, pct: logger.info(msg),
        )

        return StageArtifacts(
            live_hosts=frozenset(live_hosts),
            live_records=live_records,
        )


class URLCollectionStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("url_collection", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        from src.recon.urls import collect_urls

        urls = await collect_urls(
            state.live_hosts,
            state.scope_entries,
            context.config,
            lambda msg, pct: logger.info(msg),
        )

        return StageArtifacts(
            urls=frozenset(urls),
        )


class ParameterDiscoveryStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("parameter_discovery", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        from src.recon.filters import extract_parameters

        params = extract_parameters(state.urls)

        return StageArtifacts(
            parameters=frozenset(params),
        )


class TargetProfilingStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("target_profiling", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        from src.recon.scoring import infer_target_profile

        profile = infer_target_profile(state.urls)

        return StageArtifacts(
            technology_summary=(profile,),
        )


class URLRankingStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("url_ranking", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        from src.recon.filters import filter_similar
        from src.recon.scoring import rank_urls

        ranked = rank_urls(
            list(state.urls),
            state.scope_entries,
            context.config.get("filters", {}),
            context.config.get("scoring", {}),
            context.config.get("mode", "default"),
            context.config.get("profile"),
        )

        # Apply URL cap
        limit = context.config.get("filters", {}).get("max_collected_urls", 5000)
        if context.config.get("filters", {}).get("adaptive_url_cap", True):
            if len(state.scope_entries) >= 200:
                limit *= 4
            elif len(state.scope_entries) >= 75:
                limit *= 2

        if len(ranked) > limit:
            ranked = filter_similar(ranked, max_results=limit)

        return StageArtifacts(
            priority_urls=ranked,
        )


class DeepAnalysisStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("deep_analysis", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        # Run analysis modules
        from src.analysis.behavior import analyze_behavior
        from src.analysis.intelligence import analyze_intelligence

        findings = []

        # Run behavior analysis
        behavior_findings = await analyze_behavior(
            state.priority_urls,
            state.scope_entries,
            context.config,
        )
        findings.extend(behavior_findings)

        # Run intelligence analysis
        intel_findings = await analyze_intelligence(
            state.priority_urls,
            state.scope_entries,
            context.config,
        )
        findings.extend(intel_findings)

        return StageArtifacts(
            findings=tuple(findings),
        )


class ValidationStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("validation", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        from src.execution.validators.facade import validate_findings

        validated = await validate_findings(
            state.findings,
            state.scope_entries,
            context.config,
        )

        return StageArtifacts(
            findings=tuple(validated),
        )


class ReportingStage(Stage):
    def __init__(self, config: dict | None = None):
        super().__init__("reporting", config)

    async def execute(self, state: PipelineState, context: ExecutionContext) -> StageArtifacts:
        from src.reporting.pages import generate_run_report
        from src.reporting.report_artifacts import write_report_package

        summary = {
            "target_name": context.target_name,
            "generated_at_utc": datetime.now().isoformat(),
            "counts": {
                "subdomains": len(state.subdomains),
                "live_hosts": len(state.live_hosts),
                "urls": len(state.urls),
                "parameters": len(state.parameters),
                "priority_urls": len(state.priority_urls),
                "findings": len(state.findings),
            },
            "findings": state.findings,
            "subdomains": state.subdomains,
            "live_hosts": state.live_hosts,
            "urls": state.urls,
            "parameters": state.parameters,
            "priority_urls": state.priority_urls,
        }

        # Generate HTML report
        generate_run_report(
            run_dir=Path(context.config.get("output_dir", "output"))
            / context.target_name
            / context.run_id,
            summary=summary,
            diff_summary=None,
            screenshots=[],
            priority_urls=state.priority_urls,
            parameters=state.parameters,
            analysis_results={},
        )

        # Write signed report package
        write_report_package(
            run_dir=Path(context.config.get("output_dir", "output"))
            / context.target_name
            / context.run_id,
            target_name=context.target_name,
            summary=summary,
            findings=state.findings,
            diff_summary=None,
        )

        return StageArtifacts()


# Pipeline orchestration
def create_default_stages(config: dict) -> list[Stage]:
    """Create default pipeline stages based on config."""
    stages = [
        SubdomainDiscoveryStage(config.get("tools")),
        LiveHostProbingStage(config.get("tools")),
        URLCollectionStage(config.get("tools")),
        ParameterDiscoveryStage(config.get("tools")),
        TargetProfilingStage(config.get("tools")),
        URLRankingStage(config.get("tools")),
    ]

    if config.get("analysis", {}).get("enabled", True):
        stages.append(DeepAnalysisStage(config.get("analysis")))

    if config.get("validation", {}).get("enabled", True):
        stages.append(ValidationStage(config.get("validation")))

    stages.append(ReportingStage(config.get("output")))

    # Set dependencies
    stages[1].depends_on("subdomain_discovery")  # live_hosts depends on subdomains
    stages[2].depends_on("live_host_probing")  # urls depends on live_hosts
    stages[3].depends_on("url_collection")  # parameters depends on urls
    stages[4].depends_on("url_collection")  # profiling depends on urls
    stages[5].depends_on("target_profiling")  # ranking depends on profiling
    if len(stages) > 6:
        stages[6].depends_on("url_ranking")  # deep_analysis depends on ranking
    if len(stages) > 7:
        stages[7].depends_on("deep_analysis")  # validation depends on analysis
    if len(stages) > 8:
        stages[8].depends_on("validation")  # reporting depends on validation

    return stages


def create_pipeline_engine(config: ValidatedPipelineConfig) -> PipelineEngine:
    """Create pipeline engine with all stages."""
    stages = create_default_stages(config.__dict__)

    context = ExecutionContext(
        run_id=generate_run_id(),
        target_name=config.target_name,
        config=config.__dict__,
        storage=None,  # Will be set at runtime
        event_bus=None,  # Will be set at runtime
        checkpoint_manager=None,  # Will be set at runtime
    )

    engine = PipelineEngine(
        stages=stages,
        config=config.__dict__,
        context=context,
        max_retries=config.tools.get("retry_attempts", 2),
        retry_delay=config.tools.get("retry_backoff_seconds", 2.0),
    )

    return engine


async def run_pipeline(config: ValidatedPipelineConfig, run_id: str) -> PipelineState:
    """Run the leftover demo pipeline using the passed-in config.

    Process-wide services are owned by ``PipelineOrchestrator`` / the
    event-bus singleton. This helper does not publish a global locator.
    """
    storage = create_storage_backend(config.storage or {"backend": "local"})
    checkpoint_manager = CheckpointManager(
        store=LocalCheckpointStore(Path(config.output_dir) / config.target_name / "checkpoints"),
        run_id=run_id,
    )
    context = ExecutionContext(
        run_id=run_id,
        target_name=config.target_name,
        config=config.__dict__,
        storage=storage,
        event_bus=get_event_bus(),
        checkpoint_manager=checkpoint_manager,
    )

    engine = create_pipeline_engine(config)
    engine.context = context

    checkpoint = await checkpoint_manager.load()
    if checkpoint:
        state = PipelineState.from_dict(checkpoint.__dict__)
    else:
        state = PipelineState(
            run_id=run_id,
            target_name=config.target_name,
            scope_entries=config.scope_entries or [],
        )

    try:
        return await engine.execute(state)
    finally:
        closer = getattr(storage, "close", None)
        if closer is not None:
            result = closer()
            if hasattr(result, "__await__"):
                await result
