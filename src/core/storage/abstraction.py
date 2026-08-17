from __future__ import annotations

import abc
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

# ---------------------------------------------------------------------------
# DEPRECATED: This module is the old storage abstraction.
# New code should use src.core.storage.interfaces + src.core.storage.factory
# + the backend files in src.core.storage (local_backends, s3_backends,
# redis_backends). The RedisStorageBackend below is BROKEN and will be removed.
# ---------------------------------------------------------------------------


@dataclass
class ArtifactRef:
    key: str
    size: int
    checksum: str
    metadata: dict = field(default_factory=dict)


class StorageBackend[T](abc.ABC):
    """Abstract storage interface - business code depends only on this."""

    @abc.abstractmethod
    async def put(self, key: str, data: bytes, metadata: dict | None = None) -> ArtifactRef:
        ...

    @abc.abstractmethod
    async def get(self, key: str) -> bytes | None:
        ...

    @abc.abstractmethod
    async def exists(self, key: str) -> bool:
        ...

    @abc.abstractmethod
    async def delete(self, key: str) -> bool:
        ...

    @abc.abstractmethod
    async def list(self, prefix: str = "") -> list[str]:
        ...

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[StorageTransaction]:
        """Optional: for backends supporting atomic writes."""
        yield StorageTransaction(self)


@dataclass
class StorageTransaction:
    backend: StorageBackend
    _operations: list = field(default_factory=list)

    def put(self, key: str, data: bytes, metadata: dict | None = None):
        self._operations.append(("put", key, data, metadata))

    def delete(self, key: str):
        self._operations.append(("delete", key))

    async def commit(self):
        for op in self._operations:
            if op[0] == "put":
                await self.backend.put(op[1], op[2], op[3])
            elif op[0] == "delete":
                await self.backend.delete(op[1])


# --- Local filesystem implementation ---

class LocalStorageBackend:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace("..", "").lstrip("/")
        return self.root / safe

    async def put(self, key: str, data: bytes, metadata: dict | None = None) -> ArtifactRef:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

        import hashlib
        checksum = hashlib.sha256(data).hexdigest()

        if metadata:
            (path.with_suffix(".meta.json")).write_text(json.dumps(metadata))

        return ArtifactRef(key=key, size=len(data), checksum=checksum, metadata=metadata or {})

    async def get(self, key: str) -> bytes | None:
        path = self._path(key)
        if not path.exists():
            return None
        return path.read_bytes()

    async def exists(self, key: str) -> bool:
        return self._path(key).exists()

    async def delete(self, key: str) -> bool:
        path = self._path(key)
        if path.exists():
            path.unlink()
            meta = path.with_suffix(".meta.json")
            if meta.exists():
                meta.unlink()
            return True
        return False

    async def list(self, prefix: str = "") -> list[str]:
        base = self._path(prefix)
        if not base.exists():
            return []
        return [str(p.relative_to(self.root)) for p in base.rglob("*") if p.is_file() and not p.name.endswith(".meta.json")]


# --- S3 implementation ---

class S3StorageBackend:
    def __init__(self, bucket: str, prefix: str = "", **client_kwargs):
        self.bucket = bucket
        self.prefix = prefix
        try:
            import boto3
            self._s3 = boto3.client("s3", **client_kwargs)
        except ImportError:
            raise RuntimeError("boto3 required for S3 backend. Install with: pip install boto3")

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}".lstrip("/")

    async def put(self, key: str, data: bytes, metadata: dict | None = None) -> ArtifactRef:
        import hashlib
        checksum = hashlib.sha256(data).hexdigest()
        full_key = self._key(key)

        extra_args = {"ContentLength": len(data)}
        if metadata:
            extra_args["Metadata"] = {k: str(v) for k, v in metadata.items()}

        self._s3.put_object(Bucket=self.bucket, Key=full_key, Body=data, **extra_args)

        return ArtifactRef(key=key, size=len(data), checksum=checksum, metadata=metadata or {})

    async def get(self, key: str) -> bytes | None:
        full_key = self._key(key)
        try:
            resp = self._s3.get_object(Bucket=self.bucket, Key=full_key)
            return resp["Body"].read()
        except self._s3.exceptions.NoSuchKey:
            return None

    async def exists(self, key: str) -> bool:
        full_key = self._key(key)
        try:
            self._s3.head_object(Bucket=self.bucket, Key=full_key)
            return True
        except self._s3.exceptions.ClientError:
            return False

    async def delete(self, key: str) -> bool:
        full_key = self._key(key)
        try:
            self._s3.delete_object(Bucket=self.bucket, Key=full_key)
            return True
        except self._s3.exceptions.ClientError:
            return False

    async def list(self, prefix: str = "") -> list[str]:
        full_prefix = self._prefix(prefix)
        paginator = self._s3.get_paginator("list_objects_v2")
        keys = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=full_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if self.prefix:
                    key = key[len(self.prefix):].lstrip("/")
                keys.append(key)
        return keys

    def _prefix(self, prefix: str) -> str:
        return f"{self.prefix}/{prefix}".lstrip("/")


# --- Factory ---

def create_storage_backend(config: dict) -> Any:
    backend = config.get("backend", "local").lower()
    if backend == "local":
        return LocalStorageBackend(Path(config.get("path", "storage")))
    if backend == "s3":
        return S3StorageBackend(
            bucket=config["bucket"],
            prefix=config.get("prefix", ""),
            endpoint_url=config.get("endpoint_url"),
            region_name=config.get("region"),
        )
    if backend == "redis":
        return RedisStorageBackend(config["redis_url"])
    raise ValueError(f"Unknown storage backend: {backend}")


# Redis backend (async)
class RedisStorageBackend:
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._pool = None

    async def _get_pool(self):
        if self._pool is None:
            import redis.asyncio as redis
            self._pool = redis.ConnectionPool.from_url(self.redis_url)
        return self._pool

    async def put(self, key: str, data: bytes, metadata: dict | None = None) -> ArtifactRef:
        import hashlib
        checksum = hashlib.sha256(data).hexdigest()
        redis = await self._get_pool()
        if await redis.exists(key):
            meta_raw = await redis.hgetall(f"{key}:meta")
            existing_meta = {k.decode(): json.loads(v.decode()) for k, v in meta_raw.items()} if meta_raw else (metadata or {})
            return ArtifactRef(key=key, size=len(data), checksum=checksum, metadata=existing_meta)

        await redis.set(key, data)
        if metadata:
            await redis.hset(f"{key}:meta", mapping={k: json.dumps(v) for k, v in metadata.items()})
        return ArtifactRef(key=key, size=len(data), checksum=checksum, metadata=metadata or {})

    async def get(self, key: str) -> bytes | None:
        redis = await self._get_pool()
        return await redis.get(key)

    async def exists(self, key: str) -> bool:
        redis = await self._get_pool()
        return await redis.exists(key) > 0

    async def delete(self, key: str) -> bool:
        redis = await self._get_pool()
        await redis.delete(key, f"{key}:meta")
        return True

    async def list(self, prefix: str = "") -> list[str]:
        redis = await self._get_pool()
        return [k.decode() for k in await redis.keys(f"{prefix}*")]
