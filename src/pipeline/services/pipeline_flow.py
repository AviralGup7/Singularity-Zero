import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger


@dataclass(frozen=True)
class PipelineStage:
    key: str
    label: str
    percent_start: int
    percent_end: int
    owns_layers: tuple[str, ...]


PIPELINE_STAGES: tuple[PipelineStage, ...] = (
    PipelineStage("startup", "Load config and initialize runtime", 0, 5, ("core", "platform")),
    PipelineStage("subdomains", "Enumerate subdomains", 5, 15, ("recon",)),
    PipelineStage(
        "live_hosts", "Probe live hosts and enrich services", 15, 30, ("recon", "analysis")
    ),
    PipelineStage("urls", "Collect and normalize URLs", 30, 45, ("recon",)),
    PipelineStage("parameters", "Extract URL parameters", 45, 55, ("recon",)),
    PipelineStage(
        "ranking", "Rank and select deep-analysis targets", 55, 62, ("recon", "analysis")
    ),
    PipelineStage(
        "passive_scan",
        "Run passive detection and analysis",
        62,
        72,
        ("analysis", "detection"),
    ),
    PipelineStage(
        "active_scan",
        "Run active scanning probes",
        72,
        80,
        ("analysis", "execution"),
    ),
    PipelineStage("nuclei", "Execute nuclei validation checks", 80, 86, ("execution",)),
    PipelineStage(
        "access_control",
        "Test access control and authorization",
        86,
        90,
        ("analysis", "execution"),
    ),
    PipelineStage(
        "validation",
        "Validate findings with active probes",
        90,
        94,
        ("execution",),
    ),
    PipelineStage(
        "intelligence",
        "Merge intelligence and enrich findings",
        94,
        97,
        ("intelligence",),
    ),
    PipelineStage(
        "reporting",
        "Generate reports and dashboard",
        97,
        100,
        ("reporting", "ui"),
    ),
)


def pipeline_flow_manifest() -> list[dict[str, object]]:
    return [
        {
            "key": stage.key,
            "label": stage.label,
            "percent_start": stage.percent_start,
            "percent_end": stage.percent_end,
            "owns_layers": list(stage.owns_layers),
        }
        for stage in PIPELINE_STAGES
    ]


def run_pipeline(
    config: dict[str, Any], scope_entries: list[str], output_dir: str, args: Any
) -> None:
    """Execute the security pipeline with the given configuration.

    Args:
        config: Pipeline configuration dictionary.
        scope_entries: List of scope entries to analyze.
        output_dir: Directory for output artifacts.
        args: Parsed command-line arguments.
    """
    from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

    logger = get_pipeline_logger(__name__)
    logger.info("Starting pipeline with %d scope entries", len(scope_entries))

    # If caller preloaded inputs, orchestrator can consume those directly.
    if not hasattr(args, "_loaded_config"):
        setattr(args, "_loaded_config", config)
    if not hasattr(args, "_loaded_scope_entries"):
        setattr(args, "_loaded_scope_entries", list(scope_entries))

    # Backward-compatible fallback for external callers that only pass file args.
    if not getattr(args, "config", None) or not getattr(args, "scope", None):
        runtime_dir = Path(output_dir) / ".runtime_inputs"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        config_path = runtime_dir / "runtime.config.json"
        scope_path = runtime_dir / "runtime.scope.txt"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        scope_path.write_text("\n".join(scope_entries) + "\n", encoding="utf-8")
        setattr(args, "config", str(config_path))
        setattr(args, "scope", str(scope_path))

    orchestrator = PipelineOrchestrator()
    result = orchestrator.run_sync(args)

    if result != 0:
        logger.warning("Pipeline completed with exit code %d", result)
    else:
        logger.info("Pipeline complete. Output directory: %s", output_dir)
