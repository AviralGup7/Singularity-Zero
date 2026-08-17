from __future__ import annotations

from typing import Any

from src.core.config.typed_config import ValidatedPipelineConfig
from src.core.storage.abstraction import StorageBackend, create_storage_backend
from src.core.storage.factory import (
    create_artifact_store,
    create_checkpoint_store,
    create_finding_store,
)
from src.core.storage.interfaces import (
    ArtifactStore,
    CheckpointStore,
    FindingStore,
    VersionId,
)


def create_storage(config: ValidatedPipelineConfig | None = None) -> StorageBackend:
    """Create storage backend from config."""
    if config is None:
        from src.core.di.container import container

        config = container.resolve(ValidatedPipelineConfig)

    storage_config = config.storage or {"backend": "local", "path": "storage"}
    return create_storage_backend(storage_config)


__all__ = [
    "StorageBackend",
    "create_storage_backend",
    "ArtifactStore",
    "CheckpointStore",
    "FindingStore",
    "VersionId",
    "create_artifact_store",
    "create_checkpoint_store",
    "create_finding_store",
    "create_storage",
]
