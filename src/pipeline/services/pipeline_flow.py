import json
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger


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
