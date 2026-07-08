"""Resume strategies with dependency-aware cache invalidation.

Fixes Chain Bug #18: when an upstream stage is re-run, all downstream
stages that depend on its output must also be re-run even if their
cache flag says ``USE_CACHED``.  Without this, changed subdomains would
be silently ignored because live_hosts/urls/ranking/nuclei reuse stale
artifacts.

Bug #30 fix: _RESUME_STAGE_ORDER is now derived from the pipeline graph
(the single source of truth) instead of being hardcoded. This prevents
stage order drift when new stages are added to the pipeline.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


def _build_resume_stage_order() -> tuple[str, ...]:
    """Derive resume stage order from the pipeline graph (single source of truth).

    Falls back to a hardcoded tuple only if the graph cannot be loaded,
    ensuring new stages added to the pipeline are automatically included
    in resume planning.
    """
    try:
        from src.pipeline.services.pipeline_orchestrator._constants import STAGE_ORDER

        return tuple(STAGE_ORDER)
    except Exception:
        logger.warning(
            "Could not load STAGE_ORDER from pipeline graph; "
            "using hardcoded fallback. New pipeline stages will be missing.",
            exc_info=True,
        )
        return (
            "subdomains",
            "subdomain_takeover",
            "live_hosts",
            "waf",
            "urls",
            "git_diff_crawl",
            "parameters",
            "ranking",
            "passive_scan",
            "active_scan",
            "semgrep",
            "nuclei",
            "access_control",
            "validation",
            "intelligence",
            "threat_modeling",
            "reporting",
            "sarif_export",
        )


_RESUME_STAGE_ORDER: tuple[str, ...] = _build_resume_stage_order()


class ResumePolicy(StrEnum):
    FULL = "full"
    FROM_CACHE = "from_cache"
    FROM_STAGE = "from_stage"


class StageResumeBehavior(StrEnum):
    MUST_RE_RUN = "must_re_run"
    USE_CACHED = "use_cached"
    USE_PREVIOUS = "use_previous"
    IDEMPOTENT_MERGE = "idempotent_merge"


RESUME_BEHAVIORS: dict[str, StageResumeBehavior] = {
    "subdomains": StageResumeBehavior.USE_CACHED,
    "live_hosts": StageResumeBehavior.USE_CACHED,
    "urls": StageResumeBehavior.USE_CACHED,
    "parameters": StageResumeBehavior.USE_CACHED,
    "ranking": StageResumeBehavior.USE_CACHED,
    "passive_scan": StageResumeBehavior.USE_CACHED,
    "nuclei": StageResumeBehavior.USE_CACHED,
    "semgrep": StageResumeBehavior.USE_CACHED,
    "active_scan": StageResumeBehavior.USE_CACHED,
    "sca_scan": StageResumeBehavior.USE_CACHED,
    "container_scan": StageResumeBehavior.USE_CACHED,
    "iac_scan": StageResumeBehavior.USE_CACHED,
    "git_secret_scan": StageResumeBehavior.USE_CACHED,
    "access_control": StageResumeBehavior.IDEMPOTENT_MERGE,
    "validation": StageResumeBehavior.MUST_RE_RUN,
    "sbom_generate": StageResumeBehavior.USE_PREVIOUS,
    "sbom_diff": StageResumeBehavior.IDEMPOTENT_MERGE,
    "reporting": StageResumeBehavior.MUST_RE_RUN,
    "scope_parser": StageResumeBehavior.IDEMPOTENT_MERGE,
    "session_provisioning": StageResumeBehavior.USE_CACHED,
}

# ------------------------------------------------------------------
# Dependency graph: which stages consume the output of which.
# When a parent is re-run, every child that was going to use cached
# data must also be re-run (Chain Bug #18).
# ------------------------------------------------------------------
_STAGE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "live_hosts": ("subdomains",),
    "urls": ("subdomains", "live_hosts"),
    "parameters": ("subdomains", "live_hosts", "urls"),
    "ranking": ("subdomains", "live_hosts", "urls", "parameters"),
    "passive_scan": ("subdomains", "live_hosts", "urls", "parameters", "ranking"),
    "active_scan": ("subdomains", "live_hosts", "urls", "parameters", "ranking", "passive_scan"),
    "semgrep": ("urls", "parameters"),
    "nuclei": (
        "subdomains", "live_hosts", "urls", "parameters",
        "ranking", "passive_scan", "active_scan",
    ),
    "access_control": ("urls", "parameters", "active_scan"),
    "intelligence": ("subdomains", "live_hosts", "urls"),
    "threat_modeling": ("subdomains", "urls", "parameters"),
    "reporting": (
        "subdomains", "live_hosts", "urls", "parameters",
        "ranking", "passive_scan", "active_scan", "nuclei",
    ),
    "sarif_export": (
        "subdomains", "live_hosts", "urls", "parameters",
        "ranking", "passive_scan", "active_scan", "nuclei",
    ),
}

# Stages that are leaf consumers – no downstream dependents.
_LEAF_STAGES: frozenset[str] = frozenset({
    "reporting", "sarif_export", "sbom_generate", "sbom_diff",
})


def _propagate_invalidations(
    planned: list[str],
) -> list[str]:
    """Force re-run of downstream stages when an upstream stage is re-run.

    If stage ``A`` is in *planned* (meaning it will execute rather than
    use cached output) then every stage ``B`` that lists ``A`` as a
    dependency **and** is currently *not* in *planned* (i.e. it would
    have used cached data) must be added to the plan.

    Returns the augmented stage list preserving original ordering.
    """
    running_set: set[str] = set(planned)
    invalidated: set[str] = set()

    # Walk the stage order so we propagate in topological order.
    for stage in _RESUME_STAGE_ORDER:
        if stage in running_set:
            # This stage is already planned – nothing to invalidate.
            continue
        deps = _STAGE_DEPENDENCIES.get(stage)
        if deps is None:
            continue
        # If ANY dependency is being re-run, this stage is stale.
        if any(dep in running_set or dep in invalidated for dep in deps):
            invalidated.add(stage)
            running_set.add(stage)  # so transitive deps of *this* stage also trigger.

    if invalidated:
        logger.info(
            "Dependency invalidation forced re-run of: %s",
            ", ".join(sorted(invalidated)),
        )

    # Rebuild the list in canonical order, appending invalidated stages
    # that were not already present.
    result = list(planned)
    existing = set(planned)
    for stage in _RESUME_STAGE_ORDER:
        if stage in invalidated and stage not in existing:
            result.append(stage)
    return result


# ------------------------------------------------------------------
# Bug #22: Validate alignment between _RESUME_STAGE_ORDER and
# RESUME_BEHAVIORS so stage name drift is caught early.
# ------------------------------------------------------------------
_STAGE_ORDER_SET = frozenset(_RESUME_STAGE_ORDER)
_BEHAVIOR_ONLY = _STAGE_ORDER_SET.symmetric_difference(frozenset(RESUME_BEHAVIORS))
if _BEHAVIOR_ONLY:
    logger.warning(
        "Stage name drift detected – stages in RESUME_BEHAVIORS but not in "
        "_RESUME_STAGE_ORDER (resume ordering will fall back to "
        "IDEMPOTENT_MERGE for these): %s",
        ", ".join(sorted(_BEHAVIOR_ONLY)),
    )
# Also warn about stages in _RESUME_STAGE_ORDER that lack an explicit behavior,
# so maintainers notice when adding new pipeline stages.
_ORDER_ONLY = _STAGE_ORDER_SET - frozenset(RESUME_BEHAVIORS)
if _ORDER_ONLY:
    logger.debug(
        "Stages in _RESUME_STAGE_ORDER without explicit RESUME_BEHAVIORS "
        "(defaulting to IDEMPOTENT_MERGE): %s",
        ", ".join(sorted(_ORDER_ONLY)),
    )


class PartialResumePlanner:
    def __init__(
        self, checkpoint_mgr: Any, resume_policy: ResumePolicy = ResumePolicy.FROM_CACHE
    ) -> None:
        self.checkpoint_mgr = checkpoint_mgr
        self.resume_policy = resume_policy

    def plan_resume(
        self, failed_stage: str | None = None, force_from_stage: str | None = None
    ) -> list[str]:
        if self.resume_policy == ResumePolicy.FULL:
            return list(_RESUME_STAGE_ORDER)

        if self.resume_policy == ResumePolicy.FROM_STAGE or force_from_stage:
            start = force_from_stage or failed_stage
            if start and start in _RESUME_STAGE_ORDER:
                idx = _RESUME_STAGE_ORDER.index(start)
                return list(_RESUME_STAGE_ORDER[idx:])
            return list(_RESUME_STAGE_ORDER)

        completed = set()
        if hasattr(self.checkpoint_mgr, "completed_stages"):
            completed = set(self.checkpoint_mgr.completed_stages)

        # Bug #23: remove stages from "completed" if their artifacts
        # are corrupted or missing so they will be re-run.
        if hasattr(self.checkpoint_mgr, "get_stages_with_corrupted_artifacts"):
            corrupted_stages = set(self.checkpoint_mgr.get_stages_with_corrupted_artifacts())
            if corrupted_stages:
                logger.warning(
                    "Stages with corrupted/missing artifacts forcing re-run: %s",
                    ", ".join(sorted(corrupted_stages)),
                )
                completed -= corrupted_stages

        planned: list[str] = []
        for stage in _RESUME_STAGE_ORDER:
            behavior = RESUME_BEHAVIORS.get(stage, StageResumeBehavior.IDEMPOTENT_MERGE)
            if stage in completed:
                if behavior == StageResumeBehavior.MUST_RE_RUN:
                    planned.append(stage)
                elif behavior == StageResumeBehavior.USE_CACHED:
                    continue
                elif behavior == StageResumeBehavior.USE_PREVIOUS:
                    continue
                elif behavior == StageResumeBehavior.IDEMPOTENT_MERGE:
                    planned.append(stage)
                else:
                    planned.append(stage)
            else:
                planned.append(stage)

        # Chain Bug #18: invalidate downstream caches when upstream stages
        # are re-run, preventing silent false-negative scan results.
        planned = _propagate_invalidations(planned)
        return planned
