from enum import StrEnum


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


class PartialResumePlanner:
    def __init__(self, checkpoint_mgr, resume_policy: ResumePolicy = ResumePolicy.FROM_CACHE):
        self.checkpoint_mgr = checkpoint_mgr
        self.resume_policy = resume_policy

    def plan_resume(self, failed_stage: str | None = None, force_from_stage: str | None = None) -> list[str]:
        from src.pipeline.services.pipeline_orchestrator._constants import STAGE_ORDER

        if self.resume_policy == ResumePolicy.FULL:
            return list(STAGE_ORDER)

        if self.resume_policy == ResumePolicy.FROM_STAGE or force_from_stage:
            start = force_from_stage or failed_stage
            if start and start in STAGE_ORDER:
                idx = STAGE_ORDER.index(start)
                return list(STAGE_ORDER[idx:])
            return list(STAGE_ORDER)

        completed = set()
        if hasattr(self.checkpoint_mgr, "completed_stages"):
            completed = set(self.checkpoint_mgr.completed_stages)

        planned: list[str] = []
        for stage in STAGE_ORDER:
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
        return planned
