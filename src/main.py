#!/usr/bin/env python3
"""
Cyber Security Test Pipeline - Main Entry Point

Usage:
    python -m src.main --config config.json
    python -m src.main --target example.com --mode full
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path

from src.core.di.container import container
from src.core.config.typed_config import PipelineConfig, load_config, register_config
from src.core.observability.metrics import MetricsCollector
from src.pipeline.engine import PipelineEngine, ExecutionContext
from src.core.events.event_bus import get_event_bus, Event
from src.core.checkpoint.manager import CheckpointManager, LocalCheckpointStore
from src.core.storage.abstraction import create_storage_backend
from src.pipeline.engine import Stage, StageArtifacts, StageStatus

logger = logging.getLogger(__name__)


class ScanStage(Stage):
    """Example scan stage."""

    def __init__(self, config: dict | None = None):
        super().__init__("scan", config)

    async def execute(self, state, context) -> StageArtifacts:
        logger.info("Running scan stage")
        # Simulate scan
        await asyncio.sleep(1)
        return StageArtifacts(
            urls=frozenset(["https://example.com"]),
            parameters=frozenset(["id", "user", "token"]),
        )


class AnalysisStage(Stage):
    """Example analysis stage."""

    def __init__(self, config: dict | None = None):
        super().__init__("analysis", config)

    async def execute(self, state, context) -> StageArtifacts:
        logger.info("Running analysis stage")
        await asyncio.sleep(0.5)
        return StageArtifacts(
            findings=({
                "title": "Example Finding",
                "severity": "medium",
                "url": "https://example.com",
                "category": "example",
            },),
        )


async def run_pipeline(config: PipelineConfig, run_id: str) -> None:
    """Run the complete pipeline."""
    logger.info("Starting pipeline", run_id=run_id, target=config.target_name)

    # Setup components
    storage = create_storage_backend(config.storage)
    event_bus = get_event_bus()
    await event_bus.start()

    checkpoint_store = LocalCheckpointStore(Path(config.output_dir) / config.target_name / "checkpoints")
    checkpoint_mgr = CheckpointManager(checkpoint_store, run_id)

    # Try to resume from checkpoint
    checkpoint = await checkpoint_mgr.load()
    if checkpoint:
        logger.info("Resuming from checkpoint", version=checkpoint.version)

    # Build stages
    stages = [
        ScanStage(config.tools),
        AnalysisStage(config.analysis),
    ]

    # Create pipeline engine
    context = ExecutionContext(
        run_id=run_id,
        target_name=config.target_name,
        config=config.to_dict(),
        storage=storage,
        event_bus=event_bus,
        checkpoint_manager=checkpoint_mgr,
    )

    engine = PipelineEngine(stages, config.to_dict(), context)

    # Initial state
    from src.core.models.pipeline_state import PipelineState
    state = PipelineState(
        run_id=run_id,
        target_name=config.target_name,
        scope_entries=config.scope_entries or [],
    )

    # Execute
    try:
        final_state = await engine.execute(state)
        logger.info("Pipeline completed", completed=len(final_state.completed_stages))
    except Exception as e:
        logger.error("Pipeline failed", error=str(e))
        raise
    finally:
        await event_bus.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cyber Security Test Pipeline")
    parser.add_argument("--config", type=Path, default=Path("config.json"), help="Configuration file")
    parser.add_argument("--target", help="Target name (overrides config)")
    parser.add_argument("--mode", default="default", help="Scan mode")
    parser.add_argument("--run-id", help="Run ID (auto-generated if not provided)")
    parser.add_argument("--output-dir", help="Output directory (overrides config)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    # Load config
    if args.config.exists():
        config = load_config(args.config)
    else:
        logger.warning("Config file not found, using defaults")
        config = PipelineConfig(
            target_name="default",
            output_dir="output",
        )

    # Override from CLI
    if args.target:
        config.target_name = args.target
    if args.mode:
        config.mode = args.mode
    if args.output_dir:
        config.output_dir = args.output_dir

    # Run ID
    run_id = args.run_id or f"run_{int(time.time())}"

    # Register config with DI
    register_config(config)

    # Run pipeline
    try:
        await run_pipeline(config, run_id)
        return 0
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        return 130
    except Exception as e:
        logger.exception("Pipeline failed", error=str(e))
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
