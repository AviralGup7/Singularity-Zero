"""Manages the run inputs, variables, correlation IDs, run paths, output stores, and checkpoint managers."""

from typing import Any

from src.core.contracts.pipeline_runtime import PipelineInput


class ExecutionContext:
    """Manages the run inputs, variables, correlation IDs, run paths, output stores, and checkpoint managers."""

    def __init__(self) -> None:
        self.pipeline_input: PipelineInput | None = None
        self.pipeline_correlation_id: str = ""
        self.checkpoint_mgr: Any = None
        self.wal: Any = None
