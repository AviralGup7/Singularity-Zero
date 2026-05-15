"""Helper utilities for PipelineOrchestrator extracted to keep orchestrator small.

Contains small pure functions for building dynamic parallel graphs and
dependency checks. These were pulled out of `orchestrator.py` to reduce
file size and group related logic.
"""

from ..pipeline_helpers import (
    extract_feedback_urls,
    finding_identity,
)
from ._constants import PARALLEL_STAGE_GROUPS, STAGE_DEPS


def build_parallel_graph() -> dict[str, list[str]]:
    """Build a parallel execution graph from STAGE_DEPS.

    For each stage, identify other stages that share the same dependencies
    and can therefore run in parallel after the dependency is satisfied.
    Returns a map: trigger_stage -> [parallel_candidates].
    """
    graph: dict[str, list[str]] = {}

    # After `urls` completes: `parameters` depends on {urls},
    # `ranking` depends on {urls, parameters} -> partial parallelism:
    # parameters can start immediately after urls; ranking waits for parameters
    graph["urls"] = ["parameters"]

    # After `passive_scan`: nuclei + access_control (already in PARALLEL_STAGE_GROUPS)
    graph["passive_scan"] = []  # handled by PARALLEL_STAGE_GROUPS

    # Additional dynamic entries could be added here in future.

    return graph


def resolve_parallel_group(
    stage_name: str, nuclei_available: bool, remaining_stages: list[str]
) -> list[str] | None:
    """Resolve which stages can run in parallel after the given stage."""
    for trigger, paral_stages in PARALLEL_STAGE_GROUPS:
        if stage_name == trigger:
            return [
                s
                for s in paral_stages
                if s in remaining_stages and (s != "nuclei" or nuclei_available)
            ]
    return None


def all_deps_met(stage: str, completed: set[str], graph: dict[str, list[str]]) -> bool:
    deps = STAGE_DEPS.get(stage, set())
    return deps.issubset(completed)


"""Helper functions for pipeline orchestration."""



__all__ = [
    "finding_identity",
    "extract_feedback_urls",
]
