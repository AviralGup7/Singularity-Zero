"""High-throughput Bloom filter for URL frontier deduplication."""

from __future__ import annotations

import hashlib
import math
import os
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, cast

import numpy as np

from src.core.logging.trace_logging import get_pipeline_logger

mmh3_impl: Any

try:
    import mmh3

    mmh3_impl = mmh3
except ImportError:  # pragma: no cover - exercised only in minimal dev environments.

    class _MurmurFallback:
        @staticmethod
        def hash64(item: str) -> tuple[int, int]:
            digest = hashlib.blake2b(item.encode("utf-8"), digest_size=16).digest()
            return (
                int.from_bytes(digest[:8], "little", signed=True),
                int.from_bytes(digest[8:], "little", signed=True),
            )

    mmh3_impl = _MurmurFallback()

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a runtime dependency, but keep import safe.
    psutil = None


GIB = 1024**3
DEFAULT_MEMORY_SAFETY_BUFFER_BYTES = 2 * GIB


@dataclass(frozen=True)
class BloomProcessResult:
    """Batch URL filtering result."""

    total: int
    normalized: int
    known: int
    added: int
    chunk_size: int
    duplicates: np.ndarray
    new_urls: np.ndarray


class NeuralBloomFilter:
    """
    Frontier Probabilistic Filter.
    Optimized for high-throughput membership testing with minimal RAM footprint.
    """

    def __init__(self, capacity: int = 1000000, error_rate: float = 0.01) -> None:
        if capacity <= 0:
            raise ValueError("Bloom filter capacity must be positive")
        if not 0.0 < error_rate < 1.0:
            raise ValueError("Bloom filter error_rate must be between 0 and 1")

        self.capacity = capacity
        self.error_rate = error_rate
        self._lock = threading.RLock()

        # Calculate bit array size and number of hash functions
        self.bit_size = -int((capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.hash_count = max(1, int((self.bit_size / capacity) * math.log(2)))

        # Fix #326: Use math.ceil instead of floor+1 to avoid wasting a byte when
        # bit_size is an exact multiple of 8.
        self.bits = np.zeros(math.ceil(self.bit_size / 8), dtype=np.uint8)
        self.element_count = 0

    def _get_offsets(self, item: str) -> list[int]:
        """Compute bit offsets for the given item."""
        offsets = []
        # Use MurmurHash3 for speed
        h1, h2 = mmh3_impl.hash64(item)
        h1_u = np.uint64(h1 & ((1 << 64) - 1))
        h2_u = np.uint64(h2 & ((1 << 64) - 1))
        if h2_u == 0:
            h2_u = np.uint64(0x9E3779B97F4A7C15)
        for i in range(self.hash_count):
            # Kirsch-Mitzenmacher optimization: generate k hashes from 2
            offset = int((h1_u + np.uint64(i) * h2_u) % np.uint64(self.bit_size))
            offsets.append(offset)
        return offsets

    def _hash_arrays(self, items: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Return two MurmurHash3 seed arrays used for double hashing."""
        if items.size == 0:
            return np.array([], dtype=np.int64), np.array([], dtype=np.int64)

        # Batch with numpy vectorized operations to reduce interpreter overhead
        vec_hash = np.frompyfunc(mmh3_impl.hash64, 1, 2)
        h1, h2 = vec_hash(items.astype(np.str_))
        return h1.astype(np.int64), h2.astype(np.int64)

    def _offset_matrix(self, items: np.ndarray) -> np.ndarray:
        """Compute all Bloom bit offsets for a batch using NumPy C-level loops."""
        h1, h2 = self._hash_arrays(items)
        if h1.size == 0:
            return np.empty((0, self.hash_count), dtype=np.int64)
        rounds = np.arange(self.hash_count, dtype=np.uint64)
        offsets = (
            h1.astype(np.uint64)[:, None] + (rounds[None, :] * h2.astype(np.uint64)[:, None])
        ) % np.uint64(self.bit_size)
        return offsets.astype(np.int64, copy=False)

    def _byte_and_mask_arrays(self, items: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        offsets = self._offset_matrix(items)
        byte_idx = offsets >> 3
        bit_idx = offsets & 7
        masks = np.left_shift(np.uint8(1), bit_idx.astype(np.uint8))
        return byte_idx, masks

    @staticmethod
    def normalize_urls(urls: Sequence[str] | np.ndarray) -> np.ndarray:
        """Normalize URL strings in bulk with numpy.char operations."""
        arr = np.asarray(urls, dtype=np.str_)
        if arr.size == 0:
            return arr
        lowered = np.char.lower(np.char.strip(arr))
        http_mask = np.char.startswith(lowered, "http://")
        https_mask = np.char.startswith(lowered, "https://")
        valid_mask = np.logical_or(http_mask, https_mask)

        # Fix #327: Log silently dropped non-HTTP URLs
        dropped = arr.size - np.count_nonzero(valid_mask)
        if dropped > 0:
            get_pipeline_logger(__name__).debug(
                "Dropped %d non-HTTP URLs during normalization", dropped
            )

        return cast(np.ndarray, lowered[valid_mask])

    @staticmethod
    def adaptive_chunk_size(
        sample_count: int = 100_000,
        safety_buffer_bytes: int = DEFAULT_MEMORY_SAFETY_BUFFER_BYTES,
        min_chunk_size: int = 65_536,
        max_chunk_size: int = 2_000_000,
    ) -> int:
        """Choose a chunk size from available RAM while avoiding tiny temp arrays."""
        env_override = os.getenv("BLOOM_CHUNK_SIZE")
        if env_override:
            try:
                override = int(env_override)
            except ValueError:
                get_pipeline_logger(__name__).warning(
                    "Ignoring invalid BLOOM_CHUNK_SIZE=%r", env_override
                )
            else:
                return max(min_chunk_size, min(max_chunk_size, override))

        available = psutil.virtual_memory().available if psutil else 4 * GIB
        working = max(256 * 1024 * 1024, available - safety_buffer_bytes)

        # Fix #227: Remove dead computation. per_url_bytes is a fixed estimate.
        # Hash seeds, k offsets, byte indices, masks, and membership intermediates.
        per_url_bytes = 64 + 24 * 7  # 7 hash functions, 24 bytes each
        estimated = int(working // per_url_bytes)
        return max(min_chunk_size, min(max_chunk_size, estimated))

    def add(self, item: str) -> None:
        """Add an item to the filter."""
        with self._lock:
            already_present = item in self
            for offset in self._get_offsets(item):
                byte_idx = offset // 8
                bit_idx = offset % 8
                self.bits[byte_idx] |= 1 << bit_idx
            if not already_present:
                self.element_count += 1

    def __contains__(self, item: str) -> bool:
        """Check if an item is likely in the filter."""
        with self._lock:
            for offset in self._get_offsets(item):
                byte_idx = offset // 8
                bit_idx = offset % 8
                if not (self.bits[byte_idx] & (1 << bit_idx)):
                    return False
            return True

    def contains_many(
        self, items: Sequence[str] | np.ndarray, *, normalize: bool = True
    ) -> np.ndarray:
        """Vectorized membership test for a batch of URLs."""
        arr = self.normalize_urls(items) if normalize else np.asarray(items, dtype=np.str_)
        if arr.size == 0:
            return np.array([], dtype=np.bool_)
        with self._lock:
            byte_idx, masks = self._byte_and_mask_arrays(arr)
            hits = np.bitwise_and(self.bits[byte_idx], masks) == masks
            return cast(np.ndarray, np.all(hits, axis=1))

    def add_many(self, items: Sequence[str] | np.ndarray, *, normalize: bool = True) -> int:
        """Add a batch of URLs with vectorized byte and bit writes."""
        arr = self.normalize_urls(items) if normalize else np.asarray(items, dtype=np.str_)
        if arr.size == 0:
            return 0
        with self._lock:
            duplicates = self.contains_many(arr, normalize=False)
            new_urls = np.unique(arr[np.logical_not(duplicates)])
            if new_urls.size == 0:
                return 0
            byte_idx, masks = self._byte_and_mask_arrays(new_urls)
            np.bitwise_or.at(self.bits, byte_idx.ravel(), masks.ravel())
            self.element_count += int(new_urls.size)
            return int(new_urls.size)

    def process_urls(
        self,
        urls: Sequence[str] | Iterable[str],
        *,
        add_missing: bool = True,
        chunk_size: int | None = None,
    ) -> BloomProcessResult:
        """Filter URLs in adaptive chunks and optionally insert new members."""
        if not isinstance(urls, Sequence):
            urls = list(urls)

        total = len(urls)
        effective_chunk = chunk_size or self.adaptive_chunk_size()
        known_total = 0
        added_total = 0
        duplicate_chunks: list[np.ndarray] = []
        new_url_chunks: list[np.ndarray] = []

        for start in range(0, total, effective_chunk):
            chunk = self.normalize_urls(urls[start : start + effective_chunk])
            if chunk.size == 0:
                continue
            duplicates = self.contains_many(chunk, normalize=False)
            _, first_indices = np.unique(chunk, return_index=True)
            first_seen = np.zeros(chunk.size, dtype=np.bool_)
            first_seen[first_indices] = True
            duplicates = np.logical_or(duplicates, np.logical_not(first_seen))
            new_mask = np.logical_not(duplicates)
            new_urls = chunk[new_mask]
            known_total += int(np.count_nonzero(duplicates))
            if add_missing and new_urls.size:
                # Fix Q-15: add_many already increments self.element_count,
                # so we just capture the count for the result.
                added_count = self.add_many(new_urls, normalize=False)
                added_total += added_count
            duplicate_chunks.append(duplicates)
            new_url_chunks.append(new_urls)

        duplicates_all = (
            np.concatenate(duplicate_chunks) if duplicate_chunks else np.array([], dtype=np.bool_)
        )
        new_urls_all = (
            np.concatenate(new_url_chunks) if new_url_chunks else np.array([], dtype=np.str_)
        )
        return BloomProcessResult(
            total=total,
            normalized=int(duplicates_all.size),
            known=known_total,
            added=added_total,
            chunk_size=effective_chunk,
            duplicates=duplicates_all,
            new_urls=new_urls_all,
        )

    def get_stats(self) -> dict[str, Any]:  # Fix #231: typed return hint
        """Return filter diagnostics."""
        with self._lock:
            ones = int(np.unpackbits(self.bits).sum())
            fill_ratio = float(ones / self.bit_size)
            # Fix S0-2: Use standard theoretical formula for Bloom filter FP probability
            false_positive_probability = float(
                (1.0 - math.exp(-self.element_count * self.hash_count / self.bit_size))
                ** self.hash_count
            )
            return {
                "capacity": int(self.capacity),
                "error_rate": float(self.error_rate),
                "element_count": self.element_count,
                "memory_mb": round(self.bits.nbytes / 1024 / 1024, 2),
                "bit_size_mb": round(self.bit_size / 8 / 1024 / 1024, 2),
                "fill_ratio": round(fill_ratio, 4),
                "false_positive_probability": false_positive_probability,
                "hash_count": self.hash_count,
            }

    def reset(self) -> None:
        """Clear all bits while preserving capacity and error-rate configuration."""
        with self._lock:
            self.bits.fill(0)
            self.element_count = 0

    def merge(self, other: NeuralBloomFilter) -> None:
        """Perform a fast bitwise OR to merge filters from different workers."""
        # Fix #379: Also check hash_count; same bit_size + different hash_count = corrupt results.
        if self.bit_size != other.bit_size:
            raise ValueError("Cannot merge Bloom Filters with different bit_size")
        if self.hash_count != other.hash_count:
            raise ValueError(
                f"Cannot merge Bloom Filters with different hash_count "
                f"({self.hash_count} vs {other.hash_count})"
            )
        first, second = (
            (self._lock, other._lock)
            if id(self._lock) <= id(other._lock)
            else (other._lock, self._lock)
        )
        with first, second:
            self.bits |= other.bits
            # Fix #229: Use addition as an upper-bound estimate (max() undercounts after merge).
            self.element_count = self.element_count + other.element_count

    def merge_bits(
        self,
        bits: np.ndarray,
        *,
        element_count: int = 0,
        added_count: int = 0,
    ) -> None:
        """Merge a serialized bit array into this filter."""
        if bits.shape != self.bits.shape:
            raise ValueError("Cannot merge Bloom Filter snapshot with different bit layout")
        with self._lock:
            self.bits |= bits
            self.element_count = max(
                self.element_count + max(0, int(added_count)),
                int(element_count),
            )

    def snapshot_bytes(self) -> bytes:
        """Return a compact binary snapshot of the packed bit array."""
        with self._lock:
            return self.bits.tobytes()

    def snapshot_payload(self) -> tuple[bytes, dict[str, Any]]:
        """Return packed bits and diagnostics from the same locked state."""
        with self._lock:
            return self.bits.tobytes(), self.get_stats()

    def decode_snapshot_bytes(self, payload: bytes) -> np.ndarray:
        """Decode a Bloom snapshot without mutating the current filter."""
        if len(payload) != self.bits.nbytes:
            raise ValueError("Snapshot bit array does not match this filter")
        bits = cast(np.ndarray, np.frombuffer(payload, dtype=np.uint8).copy())
        if bits.shape != self.bits.shape:
            raise ValueError("Snapshot bit array does not match this filter")
        return bits

    def load_snapshot_bytes(self, payload: bytes) -> np.ndarray:
        """Decode a Bloom snapshot into an owned NumPy array."""
        bits = self.decode_snapshot_bytes(payload)
        with self._lock:
            self.bits = bits
        return bits
