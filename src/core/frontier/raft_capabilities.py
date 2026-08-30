"""Raft deployment capability matrix (architecture review P0-10).

Separates what the *library* can do (in-process MultiNodeRaftCluster tests)
from what the *live CLI / production default* actually runs (quorum-1 single
home). Atlas and operators must not conflate the two.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class RaftDeploymentMode(StrEnum):
    """How Raft is actually wired in this process."""

    SINGLE_NODE_QUORUM_1 = "single_node_quorum_1"
    IN_PROCESS_MULTI_NODE = "in_process_multi_node"  # test / lab only
    NETWORKED_MULTI_NODE = "networked_multi_node"  # not production-default


@dataclass(frozen=True, slots=True)
class RaftCapability:
    name: str
    supported_in_library: bool
    production_default: bool
    tested: bool
    notes: str


# Machine-readable matrix — extend when a capability graduates to prod default.
RAFT_CAPABILITY_MATRIX: tuple[RaftCapability, ...] = (
    RaftCapability(
        name="single_node_propose_commit",
        supported_in_library=True,
        production_default=True,
        tested=True,
        notes="Live CLI / launcher default. Quorum size = 1.",
    ),
    RaftCapability(
        name="in_process_3_node_quorum",
        supported_in_library=True,
        production_default=False,
        tested=True,
        notes="MultiNodeRaftCluster + InMemoryRaftTransport (unit tests).",
    ),
    RaftCapability(
        name="leader_election_failover",
        supported_in_library=True,
        production_default=False,
        tested=True,
        notes="trigger_election under transport isolation in unit tests.",
    ),
    RaftCapability(
        name="networked_multi_host_raft",
        supported_in_library=False,
        production_default=False,
        tested=False,
        notes="Not a production default. Do not claim multi-host HA from atlas alone.",
    ),
    RaftCapability(
        name="cross_region_partition_wal_replicate",
        supported_in_library=False,
        production_default=False,
        tested=False,
        notes="PartitionWALReplicator is a stub; Frontier journal relay is non-authority (I36).",
    ),
)


def default_deployment_mode() -> RaftDeploymentMode:
    """Production/CLI default is single-node quorum-1."""
    return RaftDeploymentMode.SINGLE_NODE_QUORUM_1


def raft_capability_report() -> dict[str, Any]:
    """Serialize the matrix for diagnostics / atlas generators."""
    return {
        "default_mode": default_deployment_mode().value,
        "capabilities": [
            {
                "name": c.name,
                "supported_in_library": c.supported_in_library,
                "production_default": c.production_default,
                "tested": c.tested,
                "notes": c.notes,
            }
            for c in RAFT_CAPABILITY_MATRIX
        ],
        "warning": (
            "Library multi-node tests do not imply production multi-node HA. "
            "Atlas must label MultiNodeRaftCluster as lab/test unless networked mode is enabled."
        ),
    }


def assert_production_raft_claim(claim: str) -> None:
    """Refuse over-claims that the default deployment cannot satisfy."""
    lowered = str(claim or "").strip().lower()
    forbidden = (
        "multi-host ha",
        "networked multi-node production",
        "active-active raft",
        "cross-region partitionwal authority",
    )
    for item in forbidden:
        if item in lowered:
            raise RuntimeError(
                f"Raft claim refused for production default (quorum-1): {claim!r}. "
                f"See raft_capability_report()."
            )
