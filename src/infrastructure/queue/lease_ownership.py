"""Shared ownership checks for lease RELEASE / COMPLETE / FAIL.

Lua scripts in ``lua_scripts.py`` implement the same rules atomically in
Redis. The fallback emulator and unit tests call these helpers so the
in-process path cannot drift from the invariant:

    job.worker_id == caller_worker_id

An empty caller is never a wildcard.
"""

from __future__ import annotations


def reject_if_not_owner(current_worker_id: str | None, caller_worker_id: str | None) -> str | None:
    """Return ``worker_mismatch`` when the caller does not own the job."""
    caller = "" if caller_worker_id is None else str(caller_worker_id)
    current = "" if current_worker_id is None else str(current_worker_id)
    if caller == "" or current != caller:
        return "worker_mismatch"
    return None


def reject_if_lease_mismatch(
    current_version: str | None, expected_version: str | None
) -> str | None:
    """Return ``lease_version_mismatch`` when a CAS token does not match.

    An empty expected version is a no-op (coordinator may not know it);
    the worker-id check is still required and the job state transition
    makes a second release fail with ``wrong_state``.
    """
    expected = "" if expected_version is None else str(expected_version)
    if expected == "":
        return None
    current = "" if current_version is None else str(current_version)
    if current != expected:
        return "lease_version_mismatch"
    return None
