from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

VersionId = str
"""Opaque identifier for a single stored version of a checkpoint artifact.

Backends pick their own encoding (e.g. ``"v3"`` or a backend-specific token);
callers must treat the value as opaque and round-trip it through
:meth:`CheckpointStore.read_version_by_id` /
:meth:`CheckpointStore.delete_version` only.
"""


@runtime_checkable
class ArtifactStore(Protocol):
    def put(self, key: str, payload: bytes) -> str: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...

    def delete(self, key: str) -> None: ...

    def list(self, prefix: str = "") -> list[str]: ...


@runtime_checkable
class CheckpointStore(Protocol):
    """Durable store for checkpoint state, per-stage context snapshots, and stage deltas.

    Implementations may be local-filesystem, object storage (S3/GCS), or
    a distributed KV (Redis). All methods are required; concrete
    implementations must round-trip arbitrary JSON-serialisable payloads
    and must not expose backend-specific path or URL shapes through
    :data:`VersionId`.
    """

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> VersionId: ...

    def list_run_ids(self) -> list[str]: ...

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None: ...

    def read_version_by_id(
        self, run_id: str, version_id: VersionId
    ) -> dict[str, Any] | None: ...

    def list_version_ids(self, run_id: str) -> list[VersionId]: ...

    def delete_version(self, run_id: str, version_id: VersionId) -> None: ...

    def write_context_snapshot(
        self, run_id: str, stage_name: str, payload: dict[str, Any]
    ) -> VersionId: ...

    def read_context_snapshot(
        self, run_id: str, stage_name: str
    ) -> dict[str, Any] | None: ...

    def write_stage_delta(
        self,
        run_id: str,
        stage_name: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> VersionId: ...

    def list_stage_deltas(
        self, run_id: str, stage_name: str
    ) -> list[dict[str, Any]]: ...


@runtime_checkable
class FindingStore(Protocol):
    def save_many(self, run_id: str, findings: list[dict[str, Any]]) -> None: ...

    def load_many(self, run_id: str) -> list[dict[str, Any]]: ...
