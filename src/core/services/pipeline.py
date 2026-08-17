from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any

from src.core.checkpoint.manager import CheckpointManager
from src.core.config.typed_config import ValidatedPipelineConfig, load_config, register_config
from src.core.di.container import container
from src.core.events.event_bus import EventBus
from src.core.storage.abstraction import StorageBackend, create_storage_backend

logger = logging.getLogger(__name__)


@dataclass
class PipelineServices:
    """Central service container for the pipeline."""

    config: ValidatedPipelineConfig
    storage: StorageBackend
    event_bus: EventBus
    checkpoint_manager: CheckpointManager
    pipeline_engine: Any | None = None


# Global services instance
_services: PipelineServices | None = None


def get_services() -> PipelineServices:
    global _services
    if _services is None:
        raise RuntimeError(
            "Pipeline services not initialized. Call setup_pipeline_services() first."
        )
    return _services


def setup_pipeline_services(config_path: str | None = None) -> PipelineServices:
    """Initialize all pipeline services."""
    global _services

    # Load config
    if config_path:
        config = load_config(config_path)
    else:
        config = ValidatedPipelineConfig(
            target_name="default",
            output_dir="output",
        )

    # Register config
    register_config(config)

    # Create services
    storage = create_storage_backend(config.storage)
    event_bus = EventBus()
    checkpoint_manager = CheckpointManager(
        run_id=config.target_name,
        storage=storage,
    )

    # Create pipeline engine dynamically
    engine_mod = importlib.import_module("src.pipeline.engine")
    pipeline_engine = engine_mod.PipelineEngine(
        stages=[],  # Will be populated by caller
        config=config.__dict__,
        context=None,  # Will be set when running
    )

    _services = PipelineServices(
        config=config,
        storage=storage,
        event_bus=event_bus,
        checkpoint_manager=checkpoint_manager,
        pipeline_engine=pipeline_engine,
    )

    # Register with DI container
    container.register_instance(StorageBackend, storage)
    container.register_instance(EventBus, event_bus)
    container.register_instance(CheckpointManager, checkpoint_manager)
    container.register_instance(ValidatedPipelineConfig, config)

    logger.info("Pipeline services initialized")
    return _services


async def shutdown_pipeline_services() -> None:
    """Gracefully shutdown all services."""
    global _services
    if _services:
        await _services.storage.close()
        await _services.event_bus.stop()
        _services = None
        logger.info("Pipeline services shutdown complete")
