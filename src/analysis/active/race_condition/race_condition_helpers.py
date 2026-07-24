"""Helper functions for race condition probing.

Part A updates:
- Replaced ThreadPoolExecutor-based concurrency with asyncio + httpx.AsyncClient so that
  race requests fire near-simultaneously on a single host. Uses
  ``asyncio.gather()`` for true concurrent scheduling and ``time.perf_counter_ns()`` to
  record per-request inter-arrival jitter.
- ``make_concurrent_requests`` still accepts a ``ResponseCache`` instance, but also works
  in a pure asyncio mode that does not require a cache.
- Added ``RaceCoordinator`` for distributed (multi-worker) race coordination and UDP
  timestamp sync helpers.
- Added ``measure_from_response_date_header`` for server-side timing baseline.

Part B updates:
- Added ``ActorRaceTester`` with multi-actor race, state comparison, and double-submit
  primitives.

This module is a re-export hub — the actual implementations live in the sub-modules
``concurrent_utils``, ``coordinator``, and ``actor_tester``.
"""

import logging

from .actor_tester import ActorRaceTester
from .concurrent_utils import (
    RaceResponse,
    build_finding,
    calculate_confidence,
    calculate_severity,
    classify_race_type,
    compute_body_hash,
    detect_balance_changes,
    detect_duplicate_processing,
    detect_response_inconsistency,
    detect_timing_discrepancy,
    detect_toctou,
    extract_json_value,
    is_race_prone_endpoint,
    make_concurrent_requests,
)
from .coordinator import (
    RaceCoordinator,
    measure_from_response_date_header,
    select_synchronized_workers,
    sync_workers,
)

logger = logging.getLogger(__name__)

__all__ = [
    "RaceResponse",
    "RaceCoordinator",
    "ActorRaceTester",
    "make_concurrent_requests",
    "measure_from_response_date_header",
    "sync_workers",
    "select_synchronized_workers",
    "build_finding",
    "calculate_confidence",
    "calculate_severity",
    "classify_race_type",
    "detect_balance_changes",
    "detect_duplicate_processing",
    "detect_response_inconsistency",
    "detect_timing_discrepancy",
    "detect_toctou",
    "extract_json_value",
    "is_race_prone_endpoint",
    "compute_body_hash",
]
