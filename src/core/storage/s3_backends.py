from __future__ import annotations
import logging

import json
from typing import Any

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore

from src.core.storage.interfaces import ArtifactStore, CheckpointStore, FindingStore, VersionId


def _parse_version_id(version_id: VersionId) -> int:
    if not isinstance(version_id, str) or not version_id.startswith("v"):
        raise ValueError(f"Invalid checkpoint version id: {version_id!r}")
    suffix = version_id[1:]
    if not suffix.isdigit():
        raise ValueError(f"Invalid checkpoint version id: {version_id!r}")
    return int(suffix)


def _stage_safe_name(stage_name: str) -> str:
    safe = str(stage_name or "").strip() or "unknown"
    if any(c in safe for c in ("/", "\\", "..")):
        raise ValueError(f"Invalid stage name: {stage_name!r}")
    return safe


class _S3Base:
    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        endpoint_url: str | None = None,
        region_name: str | None = None,
    ) -> None:
        if boto3 is None:
            raise ImportError(
                "boto3 is required for S3 storage backends. Install with: pip install boto3"
            )
        self._bucket = bucket
        self._prefix = prefix.strip("/")

        client_kwargs: dict[str, Any] = {}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
        if region_name:
            client_kwargs["region_name"] = region_name

        self._s3 = boto3.client("s3", **client_kwargs)
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            self._s3.head_bucket(Bucket=self._bucket)
        except ClientError as exc:
            logging.warning("Operation failed in s3_backends.py: %s", exc, exc_info=True)  # noqa: BLE001

    def _s3_key(self, key: str) -> str:
        key = str(key).strip("/")
        return f"{self._prefix}/{key}" if self._prefix else key


class S3ArtifactStore(_S3Base, ArtifactStore):
    def put(self, key: str, payload: bytes) -> str:
        s3_key = self._s3_key(key)
        self._s3.put_object(Bucket=self._bucket, Key=s3_key, Body=payload)
        return f"s3://{self._bucket}/{s3_key}"

    def get(self, key: str) -> bytes:
        s3_key = self._s3_key(key)
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=s3_key)
            return bytes(response["Body"].read())
        except ClientError as e:
            raise FileNotFoundError(f"S3 object not found: {s3_key}") from e

    def exists(self, key: str) -> bool:
        try:
            self._s3.head_object(Bucket=self._bucket, Key=self._s3_key(key))
            return True
        except ClientError:
            return False

    def delete(self, key: str) -> None:
        try:
            self._s3.delete_object(Bucket=self._bucket, Key=self._s3_key(key))
        except ClientError as exc:
            logging.warning("Operation failed in s3_backends.py: %s", exc, exc_info=True)  # noqa: BLE001

    def list(self, prefix: str = "") -> list[str]:
        s3_prefix = self._s3_key(prefix)
        if s3_prefix and not s3_prefix.endswith("/"):
            s3_prefix += "/"

        results = []
        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self._bucket, Prefix=s3_prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if self._prefix:
                        key = key[len(self._prefix) :].lstrip("/")
                    results.append(key)
        except ClientError as exc:
            logging.warning("Operation failed in s3_backends.py: %s", exc, exc_info=True)  # noqa: BLE001
        return sorted(results)


class S3CheckpointStore(_S3Base, CheckpointStore):
    """S3-backed CheckpointStore.

    Layout under the configured ``prefix``::

        <prefix>/<run_id>/checkpoint_v<n>.json
        <prefix>/<run_id>/context_<stage>.json
        <prefix>/<run_id>/delta_<stage>_<seq:06d>.json
    """

    def _run_prefix(self, run_id: str) -> str:
        return self._s3_key(run_id)

    def list_run_ids(self) -> list[str]:
        prefix = f"{self._prefix}/" if self._prefix else ""
        run_ids: set[str] = set()
        for key in self._list_object_keys(prefix):
            if "/checkpoint_v" not in key:
                continue
            relative = key[len(prefix):] if prefix else key
            run_id = relative.split("/", 1)[0]
            if run_id:
                run_ids.add(run_id)
        return sorted(run_ids)

    def _checkpoint_key(self, run_id: str, version: int) -> str:
        return f"{self._run_prefix(run_id)}/checkpoint_v{version}.json"

    def _context_snapshot_key(self, run_id: str, stage_name: str) -> str:
        return (
            f"{self._run_prefix(run_id)}/context_{_stage_safe_name(stage_name)}.json"
        )

    def _stage_delta_key(
        self, run_id: str, stage_name: str, sequence: int
    ) -> str:
        return (
            f"{self._run_prefix(run_id)}"
            f"/delta_{_stage_safe_name(stage_name)}_{sequence:06d}.json"
        )

    def _list_object_keys(self, prefix: str) -> list[str]:
        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            return [
                obj["Key"]
                for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix)
                for obj in page.get("Contents", [])
            ]
        except ClientError:
            return []

    def _key_to_version_id(self, key: str) -> VersionId | None:
        name = key.rsplit("/", 1)[-1]
        if not (name.startswith("checkpoint_v") and name.endswith(".json")):
            return None
        try:
            return f"v{_parse_version_id('v' + name[len('checkpoint_v'):-len('.json')])}"
        except ValueError:
            return None

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> VersionId:
        key = self._checkpoint_key(run_id, version)
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=body)
        return f"v{version}"

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None:
        if run_id:
            prefix = f"{self._run_prefix(run_id)}/"
        else:
            prefix = f"{self._prefix}/" if self._prefix else ""

        candidates: list[tuple[int, str]] = []
        for key in self._list_object_keys(prefix):
            version_id = self._key_to_version_id(key)
            if version_id is None:
                continue
            try:
                version = _parse_version_id(version_id)
            except ValueError:
                continue
            candidates.append((version, key))
        if not candidates:
            return None
        candidates.sort()
        latest_key = candidates[-1][1]
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=latest_key)
            return dict(json.loads(response["Body"].read().decode("utf-8")))
        except (ClientError, json.JSONDecodeError):
            return None

    def read_version_by_id(
        self, run_id: str, version_id: VersionId
    ) -> dict[str, Any] | None:
        version = _parse_version_id(version_id)
        key = self._checkpoint_key(run_id, version)
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=key)
            return dict(json.loads(response["Body"].read().decode("utf-8")))
        except (ClientError, json.JSONDecodeError):
            return None

    def list_version_ids(self, run_id: str) -> list[VersionId]:
        prefix = f"{self._run_prefix(run_id)}/"
        ids: list[VersionId] = []
        for key in self._list_object_keys(prefix):
            version_id = self._key_to_version_id(key)
            if version_id is not None:
                ids.append(version_id)
        ids.sort(key=_parse_version_id)
        return ids

    def delete_version(self, run_id: str, version_id: VersionId) -> None:
        version = _parse_version_id(version_id)
        try:
            self._s3.delete_object(
                Bucket=self._bucket, Key=self._checkpoint_key(run_id, version)
            )
        except ClientError as exc:
            logging.warning("Operation failed in s3_backends.py: %s", exc, exc_info=True)  # noqa: BLE001

    def write_context_snapshot(
        self, run_id: str, stage_name: str, payload: dict[str, Any]
    ) -> VersionId:
        key = self._context_snapshot_key(run_id, stage_name)
        body = json.dumps(payload, default=str).encode("utf-8")
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=body)
        return f"context:{_stage_safe_name(stage_name)}"

    def read_context_snapshot(
        self, run_id: str, stage_name: str
    ) -> dict[str, Any] | None:
        key = self._context_snapshot_key(run_id, stage_name)
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=key)
            return dict(json.loads(response["Body"].read().decode("utf-8")))
        except (ClientError, json.JSONDecodeError):
            return None

    def write_stage_delta(
        self,
        run_id: str,
        stage_name: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> VersionId:
        key = self._stage_delta_key(run_id, stage_name, sequence)
        body = json.dumps(payload, default=str).encode("utf-8")
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=body)
        return f"delta:{_stage_safe_name(stage_name)}:{sequence:06d}"

    def list_stage_deltas(
        self, run_id: str, stage_name: str
    ) -> list[dict[str, Any]]:
        safe = _stage_safe_name(stage_name)
        prefix = f"{self._run_prefix(run_id)}/delta_{safe}_"
        results: list[dict[str, Any]] = []
        for key in self._list_object_keys(prefix):
            name = key.rsplit("/", 1)[-1]
            if not name.endswith(".json"):
                continue
            try:
                response = self._s3.get_object(Bucket=self._bucket, Key=key)
                payload = dict(json.loads(response["Body"].read().decode("utf-8")))
            except (ClientError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                results.append(payload)
        results.sort(key=lambda item: int(item.get("sequence", 0) or 0))
        return results


class S3FindingStore(_S3Base, FindingStore):
    def save_many(self, run_id: str, findings: list[dict[str, Any]]) -> None:
        key = self._s3_key(f"{run_id}.findings.json")
        body = json.dumps(findings, indent=2).encode("utf-8")
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=body)

    def load_many(self, run_id: str) -> list[dict[str, Any]]:
        key = self._s3_key(f"{run_id}.findings.json")
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=key)
            data = response["Body"].read().decode("utf-8")
            return list(json.loads(data) or [])
        except ClientError:
            return []
