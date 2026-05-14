from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore

from src.core.storage.interfaces import ArtifactStore, CheckpointStore, FindingStore


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

        client_kwargs = {}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
        if region_name:
            client_kwargs["region_name"] = region_name

        self._s3 = boto3.client("s3", **client_kwargs)
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            self._s3.head_bucket(Bucket=self._bucket)
        except ClientError:
            pass

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
        except ClientError:
            pass

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
        except ClientError:
            pass
        return sorted(results)


class S3CheckpointStore(_S3Base, CheckpointStore):
    def _run_prefix(self, run_id: str) -> str:
        return self._s3_key(run_id)

    def write(self, run_id: str, version: int, payload: dict[str, Any]) -> Path:
        key = f"{self._run_prefix(run_id)}/checkpoint_v{version}.json"
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=body)
        return Path(f"s3://{self._bucket}/{key}")

    def read_latest(self, run_id: str | None = None) -> dict[str, Any] | None:
        if run_id:
            prefix = f"{self._run_prefix(run_id)}/"
        else:
            prefix = f"{self._prefix}/" if self._prefix else ""

        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            candidates = []
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    if obj["Key"].endswith(".json") and "checkpoint_v" in obj["Key"]:
                        candidates.append(obj["Key"])

            if not candidates:
                return None

            candidates.sort()
            latest_key = candidates[-1]
            response = self._s3.get_object(Bucket=self._bucket, Key=latest_key)
            return dict(json.loads(response["Body"].read().decode("utf-8")))
        except ClientError:
            return None

    def read_version(self, path: str | Path) -> dict[str, Any] | None:
        path_str = str(path)
        if not path_str.startswith(f"s3://{self._bucket}/"):
            return None
        key = path_str[len(f"s3://{self._bucket}/") :]
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=key)
            return dict(json.loads(response["Body"].read().decode("utf-8")))
        except ClientError:
            return None

    def list_versions(self, run_id: str) -> list[str | Path]:
        prefix = f"{self._run_prefix(run_id)}/"
        versions: list[str | Path] = []
        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    if obj["Key"].endswith(".json") and "checkpoint_v" in obj["Key"]:
                        versions.append(f"s3://{self._bucket}/{obj['Key']}")
        except ClientError:
            pass
        return sorted(versions)

    def delete(self, path: str | Path) -> None:
        path_str = str(path)
        if not path_str.startswith(f"s3://{self._bucket}/"):
            return
        key = path_str[len(f"s3://{self._bucket}/") :]
        try:
            self._s3.delete_object(Bucket=self._bucket, Key=key)
        except ClientError:
            pass


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

