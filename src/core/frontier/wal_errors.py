"""Shared WAL / outbox integrity errors (I15 fail-closed)."""

from __future__ import annotations


class WALCorruptionError(RuntimeError):
    """Raised when a durable log record fails CRC-64 verification.

    Recovery must abort with zero state mutations.
    """
