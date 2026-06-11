from typing import Any

from src.analysis.automation.access_control import AccessControlAnalyzer, EnforcementResult
from src.analysis.automation.auto_filters import (
    AutoFilterEngine,
    FilterRule,
    create_default_security_filters,
)
from src.analysis.automation.manual_queue import (
    MANUAL_QUEUE_CATEGORIES,
    attach_queue_replay_links,
    build_automation_tasks,
    build_review_brief,
    derive_endpoint_type,
)
from src.analysis.automation.remediation_candidates import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    RemediationCandidate,
    attach_remediation_candidates_to_delta,
    build_remediation_candidate,
    build_remediation_candidates,
)
from src.analysis.automation.task_executor import (
    SUPPORTED_TASK_KINDS,
    AutomationTaskExecutor,
    TaskExecutionResult,
    execute_queue_tasks,
    results_to_json,
)
from src.analysis.automation.ticket_creators import (
    TICKET_CREATOR,
    BugcrowdTicketCreator,
    HackerOneTicketCreator,
    JiraTicketCreator,
    TicketCreatorBase,
    TicketResult,
    create_ticket_creators_from_config,
    register_default_ticket_creators,
)
from src.analysis.automation.workflow import (
    All,
    AlwaysTrue,
    AnyOf,
    AutomationTask,
    ConfidenceAtLeast,
    FieldEquals,
    FieldMatches,
    HasSignal,
    Not,
    SeverityAtLeast,
    Workflow,
    apply_workflow_to_findings,
    default_workflow,
    evaluate_workflow,
    expression_to_dict,
)
from src.analysis.automation.workflow import (
    from_dict as workflow_from_dict,
)


def __getattr__(name: str) -> Any:
    """Lazy re-exports of the pipeline-stage helpers.

    These names live in :mod:`src.pipeline.services.pipeline_orchestrator.stages`
    and importing them eagerly would introduce a circular import via
    :mod:`src.pipeline.services.pipeline_orchestrator.__init__`.  This
    module-level ``__getattr__`` keeps the public surface stable while
    deferring the actual import until the caller needs the symbol.
    """
    if name in {"ReportDistributor", "DistributionRecord", "run_report_distribution"}:
        from src.pipeline.services.pipeline_orchestrator.stages.report_distribution import (
            DistributionRecord,
            ReportDistributor,
            run_report_distribution,
        )

        mapping = {
            "ReportDistributor": ReportDistributor,
            "DistributionRecord": DistributionRecord,
            "run_report_distribution": run_report_distribution,
        }
        return mapping[name]
    if name in {"RevalidationEntry", "revalidate_resolved_findings", "run_finding_revalidation"}:
        from src.pipeline.services.pipeline_orchestrator.stages.finding_revalidation import (
            RevalidationEntry,
            revalidate_resolved_findings,
            run_finding_revalidation,
        )

        mapping = {
            "RevalidationEntry": RevalidationEntry,
            "revalidate_resolved_findings": revalidate_resolved_findings,
            "run_finding_revalidation": run_finding_revalidation,
        }
        return mapping[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "AccessControlAnalyzer",
    "All",
    "AlwaysTrue",
    "AnyOf",
    "AutoFilterEngine",
    "AutomationTask",
    "AutomationTaskExecutor",
    "BugcrowdTicketCreator",
    "ConfidenceAtLeast",
    "DistributionRecord",
    "EnforcementResult",
    "FieldEquals",
    "FieldMatches",
    "FilterRule",
    "HackerOneTicketCreator",
    "JiraTicketCreator",
    "MANUAL_QUEUE_CATEGORIES",
    "Not",
    "RemediationCandidate",
    "ReportDistributor",
    "RevalidationEntry",
    "SUPPORTED_TASK_KINDS",
    "TICKET_CREATOR",
    "SeverityAtLeast",
    "TaskExecutionResult",
    "TicketCreatorBase",
    "TicketResult",
    "Workflow",
    "apply_workflow_to_findings",
    "attach_queue_replay_links",
    "attach_remediation_candidates_to_delta",
    "build_automation_tasks",
    "build_remediation_candidate",
    "build_remediation_candidates",
    "build_review_brief",
    "create_default_security_filters",
    "create_ticket_creators_from_config",
    "default_workflow",
    "derive_endpoint_type",
    "evaluate_workflow",
    "execute_queue_tasks",
    "expression_to_dict",
    "register_default_ticket_creators",
    "results_to_json",
    "revalidate_resolved_findings",
    "run_finding_revalidation",
    "run_report_distribution",
    "workflow_from_dict",
]
