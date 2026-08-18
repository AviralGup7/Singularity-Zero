"""Collision-resistant identifiers for jobs and pipeline runs."""

from __future__ import annotations

import uuid

from src.core.checkpoint.recovery import generate_run_id

__all__ = ["generate_run_id", "new_job_id", "new_worker_id"]


def new_job_id() -> str:
    """Return a 32-char hex job id. Short 8-char prefixes collide under load."""
    return uuid.uuid4().hex


def new_worker_id(prefix: str = "worker-") -> str:
    """Return a unique worker id. 6-hex suffixes collide under modest load."""
    return f"{prefix}{uuid.uuid4().hex}"
