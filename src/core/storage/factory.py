from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.storage.interfaces import ArtifactStore, CheckpointStore, FindingStore


def create_artifact_store(config: dict[str, Any] | None, default_path: Path) -> ArtifactStore:
    """Create an ArtifactStore based on configuration."""
    config = config or {}
    backend = config.get("backend", "local").lower()

    if backend == "s3":
        from src.core.storage.s3_backends import S3ArtifactStore

        return S3ArtifactStore(
            bucket=config["bucket"],
            prefix=config.get("prefix", ""),
            endpoint_url=config.get("endpoint_url"),
            region_name=config.get("region_name"),
        )

    from src.core.storage.local_backends import LocalArtifactStore

    return LocalArtifactStore(default_path)


def create_checkpoint_store(config: dict[str, Any] | None, default_path: Path) -> CheckpointStore:
    """Create a CheckpointStore based on configuration."""
    config = config or {}
    backend = config.get("backend", "local").lower()

    if backend == "s3":
        from src.core.storage.s3_backends import S3CheckpointStore

        return S3CheckpointStore(
            bucket=config["bucket"],
            prefix=config.get("prefix", ""),
            endpoint_url=config.get("endpoint_url"),
            region_name=config.get("region_name"),
        )

    from src.core.storage.local_backends import LocalCheckpointStore

    return LocalCheckpointStore(default_path)


def create_finding_store(config: dict[str, Any] | None, default_path: Path) -> FindingStore:
    """Create a FindingStore based on configuration."""
    config = config or {}
    backend = config.get("backend", "local").lower()

    if backend == "s3":
        from src.core.storage.s3_backends import S3FindingStore

        return S3FindingStore(
            bucket=config["bucket"],
            prefix=config.get("prefix", ""),
            endpoint_url=config.get("endpoint_url"),
            region_name=config.get("region_name"),
        )

    from src.core.storage.local_backends import LocalFindingStore

    return LocalFindingStore(default_path)
