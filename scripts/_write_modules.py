"""Bootstrap: create all frontier submodule files and update proc_pool/wal as re-export shims."""

import io
import os

FRONTIER = r"D:\cyber security test pipeline - Copy\src\core\frontier"

files = {}

# ── vfs_isolation.py ────────────────────────────────────────────────────
files["vfs_isolation.py"] = '''"""Cyber Security Test Pipeline - Ghost-VFS Isolation
Encryption policy, hardware enclave, and eBPF hook abstractions.
"""

from __future__ import annotations

import os
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.encryption import secure_wipe

logger = get_pipeline_logger(__name__)

DEFAULT_ROTATION_INTERVAL: float = 14400.0


class VFSEncryptionPolicy:
    """Policy engine for VFS access control."""

    def __init__(self, role_permissions: dict[str, list[str]] | None = None) -> None:
        self.role_permissions = role_permissions or {
            "admin": ["read", "write", "delete", "export", "import"],
            "system": ["read", "write", "delete", "export", "import"],
            "analyst": ["read"],
            "audit": ["read"],
        }

    def is_allowed(self, principal: str, action: str, path: str) -> bool:
        allowed = self.role_permissions.get(principal, [])
        if action not in allowed:
            return False
        cleaned = os.path.normpath(path).replace("\\\\", "/").lower()
        parts = [p for p in cleaned.split("/") if p]
        if "secrets" in parts or cleaned.endswith((".pem", ".key")):
            return principal in ("admin", "system")
        return True


class HardwareEnclaveProvider:
    """Stub for SGX/SEV enclave integrations."""

    @staticmethod
    def is_available() -> bool:
        return False

    @staticmethod
    def seal_data(data: bytes) -> bytes:
        return data

    @staticmethod
    def unseal_data(data: bytes) -> bytes:
        return data


class eBPFHookManager:  # noqa: N801
    """Stub for eBPF memory pinning hooks."""

    @staticmethod
    def pin_memory(address_space: Any) -> None:
        pass

    @staticmethod
    def unpin_memory(address_space: Any) -> None:
        pass
'''

# ── vfs_paths.py ───────────────────────────────────────────────────────
files["vfs_paths.py"] = '''"""Cyber Security Test Pipeline - Ghost-VFS Path Utilities
Path validation and normalization for the volatile virtual filesystem.
"""

from __future__ import annotations

import os
import posixpath


class VFSPathMixin:
    """Mixin providing path validation for GhostVFS."""

    def _validate_path(self, path: str) -> str:
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")
        if "\\x00" in raw_path:
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")

        virtual_path = raw_path.replace("\\\\", "/")
        parts = virtual_path.split("/")
        cleaned_path = posixpath.normpath(virtual_path)
        if (
            cleaned_path in ("", ".")
            or ".." in parts
            or posixpath.isabs(cleaned_path)
            or cleaned_path.startswith("/")
            or (len(cleaned_path) > 1 and cleaned_path[1] == ":")
        ):
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")
        return cleaned_path
'''

# ── vfs_mounts.py ──────────────────────────────────────────────────────
files["vfs_mounts.py"] = r'''"""Cyber Security Test Pipeline - Ghost-VFS Mounts
Disk persistence helpers (flush_to_disk, load_from_disk, bundle export/import).
"""

from __future__ import annotations

import base64
import os
import pathlib
import tempfile
from typing import TYPE_CHECKING

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.encryption import (
    Argon2idAESGCM,
    SecretLease,
    sealed_bundle_decrypt,
    sealed_bundle_encrypt,
    secure_wipe,
)

logger = get_pipeline_logger(__name__)

if TYPE_CHECKING:
    from src.core.frontier.vfs_isolation import VFSEncryptionPolicy


class VFSMountsMixin:
    """Mixin providing disk persistence and bundle export/import for GhostVFS."""

    def flush_to_disk(self: Any, physical_path: str, master_key: str) -> None:
        self._ensure_active()
        logger.info("Ghost-VFS: Flushing volatile state to %s", physical_path)

        base_abs = os.path.abspath(physical_path)
        count = 0
        for path in self.list_files():
            try:
                path = self._validate_path(path)
                full_path = pathlib.Path(base_abs).joinpath(path).resolve()
                if os.path.commonpath([base_abs, str(full_path)]) != base_abs:
                    logger.error("Ghost-VFS: Path traversal blocked for path: %s", path)
                    continue

                policy: "VFSEncryptionPolicy" = self._policy_engine
                if not policy.is_allowed(self._principal, "export", path):
                    logger.error("Ghost-VFS: Policy blocked flushing of path: %s", path)
                    continue

                target_dir = os.path.dirname(full_path)
                os.makedirs(target_dir, exist_ok=True)

                with self.lease_file(path) as lease:
                    sealed = Argon2idAESGCM(master_key).encrypt(
                        lease.bytes, f"ghost-vfs:{path}".encode()
                    )

                with self._lock:
                    fd, temp_file_path = tempfile.mkstemp(
                        dir=target_dir, prefix=".vfs_tmp_", suffix=".tmp"
                    )
                    try:
                        with os.fdopen(fd, "wb") as f:
                            f.write(sealed.encode("utf-8"))
                        os.replace(temp_file_path, full_path)
                    except Exception as e:
                        logger.error("Ghost-VFS: Write fallback failed for %s: %s", temp_file_path, e)
                        try:
                            os.close(fd)
                        except OSError as exc:
                            logger.warning("Ghost-VFS: fd close error: %s", exc)
                        if os.path.exists(temp_file_path):
                            try:
                                os.remove(temp_file_path)
                            except Exception as ex:
                                logger.debug("Ghost-VFS: temp remove error: %s", ex)
                        raise

                count += 1
            except Exception as e:
                logger.error("Ghost-VFS: Failed to flush %s to disk: %s", path, e)

        logger.info("Ghost-VFS: Flush complete. %d artifacts persisted to disk.", count)

    def load_from_disk(self: Any, physical_path: str, master_key: str) -> None:
        self._ensure_active()
        logger.info("Ghost-VFS: Loading volatile state from %s", physical_path)

        base_abs = os.path.abspath(physical_path)
        count = 0
        for root, _, files in os.walk(base_abs):
            for file in files:
                full_path = os.path.abspath(os.path.join(root, file))

                if os.path.commonpath([base_abs, full_path]) != base_abs:
                    logger.error("Ghost-VFS: Path traversal blocked during load: %s", full_path)
                    continue

                try:
                    rel_path = self._validate_path(os.path.relpath(full_path, base_abs))
                except ValueError:
                    logger.error("Ghost-VFS: Invalid path during load: %s", full_path)
                    continue

                if not self._policy_engine.is_allowed(self._principal, "import", rel_path):
                    logger.error("Ghost-VFS: Policy blocked load of path: %s", rel_path)
                    continue

                try:
                    with open(full_path, "rb") as f:
                        file_content = f.read()

                    if len(file_content) < 28:
                        logger.error("Ghost-VFS: File %s is too short for crypto format", rel_path)
                        continue

                    decrypted = Argon2idAESGCM(master_key).decrypt(
                        file_content, f"ghost-vfs:{rel_path}".encode()
                    )
                    self.write_file(rel_path, decrypted)
                    secure_wipe(bytearray(decrypted))
                    count += 1
                except Exception as e:
                    logger.error("Ghost-VFS: Failed to load/decrypt %s: %s", rel_path, e)

        logger.info("Ghost-VFS: Load complete. %d files re-hydrated.", count)

    def export_sealed_bundle(
        self: Any, output_path: str, master_key: str, *, name: str = "ghost-vfs"
    ) -> None:
        self._ensure_active()
        records: dict[str, str] = {}
        for path in self.list_files():
            try:
                path = self._validate_path(path)
            except ValueError:
                logger.error("Ghost-VFS: Invalid path blocked during bundle export: %s", path)
                continue

            if not self._policy_engine.is_allowed(self._principal, "export", path):
                logger.error("Ghost-VFS: Policy blocked bundle export of path: %s", path)
                continue

            with self.lease_file(path) as lease:
                records[path] = Argon2idAESGCM(master_key).encrypt(
                    lease.bytes, f"ghost-vfs-bundle:{path}".encode()
                )
        bundle = sealed_bundle_encrypt(
            name, records, master_key, aad=b"csp:ghost-vfs:sealed-bundle"
        )

        target_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(target_dir, exist_ok=True)
        with self._lock:
            fd, temp_file_path = tempfile.mkstemp(
                dir=target_dir, prefix=".bundle_tmp_", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(bundle)
                os.replace(temp_file_path, output_path)
            except Exception as e:
                logger.error("Ghost-VFS: Sealed bundle write fallback failed: %s", e)
                try:
                    os.close(fd)
                except OSError as exc:
                    logger.warning("Ghost-VFS: fd close error after bundle write: %s", exc)
                if os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except Exception as ex:
                        logger.debug("Ghost-VFS: temp remove error: %s", ex)
                raise

        logger.info("Ghost-VFS: Sealed bundle exported to %s with %d files.", output_path, len(records))

    def import_sealed_bundle(self: Any, bundle_path: str, master_key: str) -> None:
        self._ensure_active()
        with open(bundle_path, encoding="utf-8") as fh:
            payload = sealed_bundle_decrypt(
                fh.read(), master_key, aad=b"csp:ghost-vfs:sealed-bundle"
            )
        for path, encrypted in payload["records"].items():
            try:
                cleaned_path = self._validate_path(str(path))
            except ValueError:
                logger.error("Ghost-VFS: Path traversal blocked during bundle import: %s", path)
                continue

            if not self._policy_engine.is_allowed(self._principal, "import", cleaned_path):
                logger.error("Ghost-VFS: Policy blocked bundle import of path: %s", path)
                continue

            decrypted = Argon2idAESGCM(master_key).decrypt(
                str(encrypted), f"ghost-vfs-bundle:{cleaned_path}".encode()
            )
            try:
                self.write_file(cleaned_path, decrypted)
            finally:
                secure_wipe(bytearray(decrypted))
'''

# ── state_validation.py ────────────────────────────────────────────────
files["state_validation.py"] = '''"""Cyber Security Test Pipeline - State Validation
HLC clocks, VectorClock, LWW CRDT set primitives, and utility functions.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Any, TypeVar

T = TypeVar("T")

try:
    from src.core.frontier import _state_cython  # type: ignore
except ImportError:
    try:
        import _state_cython  # type: ignore
    except ImportError:
        _state_cython = None


@dataclass(frozen=True)
class HybridLogicalClock:
    """Hybrid Logical Clock (HLC) for bounded distributed causality tracking."""

    physical_time: float = field(default_factory=time.monotonic)
    logical_counter: int = 0
    node_id: str = "local"

    def tick(self, now: float | None = None) -> HybridLogicalClock:
        physical_now = now if now is not None else time.monotonic()
        l_new = max(self.physical_time, physical_now)
        c_new = (self.logical_counter + 1) if l_new == self.physical_time else 0
        return HybridLogicalClock(l_new, c_new, self.node_id)

    def update(self, remote: HybridLogicalClock, now: float | None = None) -> HybridLogicalClock:
        physical_now = now if now is not None else time.monotonic()
        l_new = max(self.physical_time, remote.physical_time, physical_now)
        if l_new == self.physical_time == remote.physical_time:
            c_new = max(self.logical_counter, remote.logical_counter) + 1
        elif l_new == self.physical_time:
            c_new = self.logical_counter + 1
        elif l_new == remote.physical_time:
            c_new = remote.logical_counter + 1
        else:
            c_new = 0
        return HybridLogicalClock(l_new, c_new, self.node_id)

    def is_later_than(self, other: HybridLogicalClock) -> bool:
        if self.physical_time > other.physical_time:
            return True
        if self.physical_time < other.physical_time:
            return False
        if self.logical_counter > other.logical_counter:
            return True
        if self.logical_counter < other.logical_counter:
            return False
        return self.node_id > other.node_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "l": self.physical_time,
            "c": self.logical_counter,
            "node": self.node_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> HybridLogicalClock:
        if not data:
            return cls()
        return cls(
            physical_time=float(data.get("l", 0.0)),
            logical_counter=int(data.get("c", 0)),
            node_id=str(data.get("node", "local")),
        )


@dataclass(frozen=True)
class VectorClock:
    """Logical clock kept for interface backwards-compatibility."""

    versions: MappingProxyType[str, int] = field(default_factory=lambda: MappingProxyType({}))

    def increment(self, node_id: str) -> VectorClock:
        next_v = dict(self.versions)
        next_v[node_id] = next_v.get(node_id, 0) + 1
        return VectorClock(MappingProxyType(next_v))

    def merge(self, other: VectorClock) -> VectorClock:
        next_v = dict(self.versions)
        for nid, v in other.versions.items():
            next_v[nid] = max(next_v.get(nid, 0), v)
        return VectorClock(MappingProxyType(next_v))

    def prune(self, active_node_ids: set[str]) -> VectorClock:
        next_v = {nid: v for nid, v in self.versions.items() if nid in active_node_ids}
        return VectorClock(MappingProxyType(next_v))

    def is_later_than(self, other: VectorClock) -> bool:
        at_least_one_greater = False
        for nid in set(self.versions) | set(other.versions):
            v = self.versions.get(nid, 0)
            other_v = other.versions.get(nid, 0)
            if v < other_v:
                return False
            if v > other_v:
                at_least_one_greater = True
        return at_least_one_greater

    def to_dict(self) -> dict[str, int]:
        return dict(self.versions)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> VectorClock:
        return cls(MappingProxyType({str(k): int(v) for k, v in (data or {}).items()}))


@dataclass(frozen=True)
class LWWElement:
    """An element with causal versioning using Hybrid Logical Clocks."""

    value: Any
    hlc: HybridLogicalClock = field(default_factory=HybridLogicalClock)
    vclock: VectorClock = field(default_factory=VectorClock)
    timestamp: float = field(default_factory=time.time)
    deleted: bool = False


class LWWset[T]:
    """
    A Last-Write-Wins Element Set CRDT.
    Uses Hybrid Logical Clocks (HLC) for deterministic event tie-breaking.
    """

    def __init__(self) -> None:
        self._elements: dict[Any, LWWElement] = {}
        self._clock = HybridLogicalClock(0.0, 0, "local")
        self._lock = RLock()

    def add(
        self,
        item: T,
        timestamp: float | None = None,
        hlc: HybridLogicalClock | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        ts, clock = self._event_clock(timestamp, hlc)
        key = self._key(item)
        element = LWWElement(_clone_value(item), clock, vclock or VectorClock(), ts, deleted=False)
        with self._lock:
            existing = self._elements.get(key)
            if existing is None or _element_wins(element, existing):
                self._elements[key] = element

    def remove(
        self,
        item: T,
        timestamp: float | None = None,
        hlc: HybridLogicalClock | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        ts, clock = self._event_clock(timestamp, hlc)
        key = self._key(item)
        element = LWWElement(_clone_value(item), clock, vclock or VectorClock(), ts, deleted=True)
        with self._lock:
            existing = self._elements.get(key)
            if existing is None or _element_wins(element, existing):
                self._elements[key] = element

    def merge(self, other: LWWset[T]) -> None:
        with other._lock:
            incoming = list(other._elements.items())
            other_clock = other._clock
        with self._lock:
            self._clock = self._clock.update(other_clock)
            for item, element in incoming:
                existing = self._elements.get(item)
                if existing is None or _element_wins(element, existing):
                    self._elements[item] = _clone_element(element)

    @property
    def tombstone_count(self) -> int:
        with self._lock:
            return sum(1 for el in self._elements.values() if el.deleted)

    def compact(self, max_tombstone_age_seconds: float = 86400.0) -> int:
        now = time.time()
        with self._lock:
            to_remove = [
                k
                for k, el in self._elements.items()
                if el.deleted and (now - el.timestamp) >= max_tombstone_age_seconds
            ]
            for k in to_remove:
                del self._elements[k]
        return len(to_remove)

    def compact_with_budget(
        self,
        max_tombstone_age_seconds: float,
        budget_ms: float,
        start_time: float,
    ) -> int:
        now = time.time()
        with self._lock:
            tombstones = [
                (k, el.timestamp)
                for k, el in self._elements.items()
                if el.deleted and (now - el.timestamp) >= max_tombstone_age_seconds
            ]
        if not tombstones:
            return 0

        if _state_cython and hasattr(_state_cython, "radix_sort_timestamps"):
            sorted_tombstones = _state_cython.radix_sort_timestamps(tombstones)
        else:
            sorted_tombstones = radix_sort_timestamps(tombstones)

        purged = 0
        for k, _ in sorted_tombstones:
            if (time.time() - start_time) * 1000.0 >= budget_ms:
                break
            with self._lock:
                if k in self._elements:
                    del self._elements[k]
                    purged += 1
        return purged

    def to_set(self) -> set[T]:
        with self._lock:
            return {_clone_value(el.value) for el in self._elements.values() if not el.deleted}

    def values(self) -> list[T]:
        with self._lock:
            return [_clone_value(el.value) for el in self._elements.values() if not el.deleted]

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                str(k): {
                    "v": _clone_value(el.value),
                    "hlc": el.hlc.to_dict(),
                    "vc": el.vclock.to_dict(),
                    "ts": el.timestamp,
                    "d": el.deleted,
                }
                for k, el in self._elements.items()
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LWWset[T]:
        lww = cls()
        for k, v in data.items():
            if not isinstance(v, dict) or "v" not in v:
                continue
            try:
                ts = float(v.get("ts", 0.0))
            except (TypeError, ValueError):
                continue
            hlc_data = v.get("hlc")
            if hlc_data:
                hlc = HybridLogicalClock.from_dict(hlc_data)
            else:
                hlc = HybridLogicalClock(ts, 0, "local")

            element = LWWElement(
                _clone_value(v["v"]),
                hlc,
                VectorClock.from_dict(v.get("vc", {})),
                ts,
                bool(v.get("d", False)),
            )
            lww._elements[k] = element
            if hlc.is_later_than(lww._clock):
                lww._clock = hlc
        return lww

    @property
    def tombstone_count(self) -> int:
        with self._lock:
            return sum(1 for el in self._elements.values() if el.deleted)

    def _event_clock(
        self, timestamp: float | None, hlc: HybridLogicalClock | None
    ) -> tuple[float, HybridLogicalClock]:
        if hlc is not None:
            with self._lock:
                if hlc.is_later_than(self._clock):
                    self._clock = hlc
            return (timestamp if timestamp is not None else hlc.physical_time), hlc
        if timestamp is not None:
            ts = float(timestamp)
            clock = HybridLogicalClock(ts, 0, "local")
            with self._lock:
                if clock.is_later_than(self._clock):
                    self._clock = clock
            return ts, clock
        ts = time.time()
        with self._lock:
            self._clock = self._clock.tick(ts)
            return ts, self._clock

    @staticmethod
    def _key(item: Any) -> Any:
        try:
            hash(item)
            return item
        except TypeError:
            if isinstance(item, dict):
                fid = item.get("id")
                if not fid:
                    stable_parts = [
                        str(item.get("type", "")),
                        str(item.get("title", "")),
                        str(item.get("url", item.get("endpoint", ""))),
                        str(item.get("parameter", "")),
                        str(item.get("method", "")),
                    ]
                    generated_fid = hashlib.sha256(
                        "|".join(stable_parts).encode("utf-8")
                    ).hexdigest()
                    try:
                        item["id"] = generated_fid
                    except TypeError:
                        pass
                    return generated_fid
                return fid
            return repr(item)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _clone_value[T](value: T) -> T:
    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _clone_element(element: LWWElement) -> LWWElement:
    return LWWElement(
        _clone_value(element.value),
        element.hlc,
        element.vclock,
        element.timestamp,
        element.deleted,
    )


def _element_wins(candidate: LWWElement, existing: LWWElement) -> bool:
    if candidate.hlc.is_later_than(existing.hlc):
        return True
    if existing.hlc.is_later_than(candidate.hlc):
        return False
    if candidate.deleted != existing.deleted:
        return candidate.deleted
    return _stable_json(candidate.value) > _stable_json(existing.value)


def stable_digest(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def radix_sort_timestamps(items: list[tuple[Any, float]]) -> list[tuple[Any, float]]:
    if not items:
        return []
    min_ts = min(item[1] for item in items)
    int_items: list[tuple[Any, float, int]] = []
    for key, ts in items:
        int_items.append((key, ts, int((ts - min_ts) * 1000)))

    max_val = max(i[2] for i in int_items)
    if max_val == 0:
        return [(i[0], i[1]) for i in int_items]

    base = 10
    placement = 1
    while placement <= max_val:
        buckets: list[list] = [[] for _ in range(base)]
        for item in int_items:
            buckets[(item[2] // placement) % base].append(item)
        int_items = [item for bucket in buckets for item in bucket]
        placement *= base

    return [(item[0], item[1]) for item in int_items]
'''

# Also write ghost_vfs.py, state.py, state_snapshots.py, state_transitions.py, and proc_pool/wal re-export shims here...

for name, content in files.items():
    path = os.path.join(FRONTIER, name)
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(content)
    print(f"  Created {path}")
