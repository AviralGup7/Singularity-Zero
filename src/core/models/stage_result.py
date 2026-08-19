from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import MISSING, dataclass, field
from enum import Enum, StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from src.core.contracts.pipeline_runtime import StageInput, StageOutput

from src.core.frontier.state import (
    CRDTCompactionBudget,
    NeuralState,
)
from src.core.frontier.state import (
    compact_state as run_compaction,
)


class StageName(StrEnum):
    """Valid pipeline stage identifiers."""

    SCOPE = "scope"
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    HOST_PROBING = "host_probing"
    SERVICE_ENUMERATION = "service_enumeration"
    URL_COLLECTION = "url_collection"
    PARAMETER_DISCOVERY = "parameter_discovery"
    TARGET_PROFILING = "target_profiling"
    DEEP_ANALYSIS = "deep_analysis"
    VALIDATION = "validation"
    MERGING = "merging"
    REPORTING = "reporting"
    SCREENSHOTS = "screenshots"
    DIFF = "diff"
    NUCLEI_SCAN = "nuclei_scan"


class StageStatus(StrEnum):
    """Lifecycle status of a pipeline stage."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class StageMetric(TypedDict, total=False):
    """Per-stage metrics recorded during execution."""

    duration_seconds: float
    started_at: float
    finished_at: float
    status: str
    error: str
    items_processed: int
    items_output: int
    reason: str


logger = logging.getLogger(__name__)

# Keys owned by NeuralState / WAL metadata. Journal-field replay must
# never touch these or list.extend will fight the CRDT and double-apply.
_CRDT_OWNED_KEYS = frozenset(
    {
        "subdomains",
        "urls",
        "discovered_urls",
        "findings",
        "active_scan_findings",
        "reportable_findings",
        "vulnerabilities",
        "_neural_state",
        "_wal_id",
        "wal_id",
        "hlc",
        "_ts",
        "_node_id",
        "node_id",
    }
)


@dataclass
class StageResult:
    """Consolidated result of all pipeline stages with CRDT synchronization."""

    # ------------------------------------------------------------------
    # Neural-Mesh Resilience Core
    # ------------------------------------------------------------------

    #: Internal CRDT state container for synchronization across stage deltas.
