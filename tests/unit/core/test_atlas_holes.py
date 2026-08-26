"""Atlas holes closed in code: reporting join, I31 receipt, I35, lattice, QoS."""

from __future__ import annotations

from types import SimpleNamespace

from src.core.contracts.finding_lifecycle import (
    FindingLifecycleState,
    FindingTicketStatus,
    filter_report_surface,
    is_report_surface,
    normalize_lifecycle_state,
    normalize_ticket_status,
)
from src.core.frontier.event_delivery import dispatch_committed_findings, reset_delivery_ledger
from src.core.frontier.lease_status import LeaseStatus, is_terminal
from src.core.frontier.settlement_receipt import stamp_finding_receipt, verify_finding_receipt
from src.core.frontier.state_authority import SettlementResult
from src.jobs.run_outcome import EXIT_OK, EXIT_PARTIAL, EXIT_POLICY_VIOLATION, derive_job_and_exit
from src.jobs.status import JobStatus, can_transition_job
from src.realtime.prioritized_broker import QoSClass
from src.realtime.qos_admit import QoSDecision, qos_admit


def test_reporting_needs_every_finding_producer() -> None:
    from src.pipeline.services.pipeline_orchestrator.graph_builder import build_pipeline_graph

    graph = build_pipeline_graph()
    reporting = graph.require("reporting")
    for producer in ("semgrep", "subdomain_takeover", "active_scan", "sca_scan", "git_secret_scan"):
        assert producer in reporting.needs, producer
    assert "reporting" not in reporting.needs


def test_open_is_ticket_not_lifecycle() -> None:
    assert normalize_lifecycle_state("open") is FindingLifecycleState.CANDIDATE
    assert normalize_ticket_status("open") is FindingTicketStatus.OPEN
    assert normalize_ticket_status("closed") is FindingTicketStatus.CLOSED
    validated = {"lifecycle_state": "validated", "title": "x"}
    assert is_report_surface(validated) is False
    reportable = {"lifecycle_state": "reportable", "title": "y"}
    assert is_report_surface(reportable) is True
    unstamped = {"title": "already in reportable bucket"}
    assert is_report_surface(unstamped) is True
    filtered = filter_report_surface([validated, reportable, unstamped])
    titles = {item["title"] for item in filtered}
    assert titles == {"y", "already in reportable bucket"}


def test_qos_admit_sheds_p3_at_92_p4_at_85() -> None:
    assert qos_admit(QoSClass.P4_DEBUG, 85.0) is QoSDecision.DROP
    assert qos_admit(QoSClass.P3_TELEMETRY, 85.0) is QoSDecision.ADMIT
    assert qos_admit(QoSClass.P3_TELEMETRY, 92.0) is QoSDecision.DROP
    assert qos_admit(QoSClass.P4_DEBUG, 92.0) is QoSDecision.DROP
    assert qos_admit(QoSClass.P0_CONTROL, 99.0) is QoSDecision.ADMIT
    assert qos_admit(QoSClass.P2_FINDINGS, 92.0) is QoSDecision.COALESCE


def test_derive_job_and_exit_lattice() -> None:
    clean = derive_job_and_exit({"recon": "COMPLETED"}, [])
    assert clean.job_status is JobStatus.COMPLETED
    assert clean.exit_code == EXIT_OK

    policy = derive_job_and_exit(
        {"recon": "COMPLETED"},
        [{"title": "crit"}],
        policy_violated=True,
    )
    assert policy.job_status is JobStatus.COMPLETED
    assert policy.exit_code == EXIT_POLICY_VIOLATION

    degraded = derive_job_and_exit({"urls": "DEGRADED", "reporting": "COMPLETED"}, [])
    assert degraded.exit_code == EXIT_PARTIAL
    assert degraded.job_status is JobStatus.COMPLETED

    skipped_failed = derive_job_and_exit({"nuclei": "SKIPPED_FAILED"}, [])
    assert skipped_failed.exit_code == EXIT_PARTIAL

    cancelled = derive_job_and_exit({}, [], cancel=True)
    assert cancelled.job_status is JobStatus.STOPPED
    assert cancelled.exit_code == 130


def test_pending_cannot_go_stopping() -> None:
    assert can_transition_job("pending", "stopping") is False
    assert can_transition_job("pending", "stopped") is True
    assert can_transition_job("running", "stopping") is True


def test_expired_lease_is_not_terminal() -> None:
    assert is_terminal(LeaseStatus.EXPIRED) is False
    assert is_terminal(LeaseStatus.COMPENSATED) is True
    assert is_terminal(LeaseStatus.CONSUMED) is True


def test_self_attested_authoritative_flag_is_not_a_receipt() -> None:
    assert verify_finding_receipt({"wal_id": "wal_1", "authoritative": True}) is False
    receipt = stamp_finding_receipt(wal_id="wal_1", settlement_id="stl", command_id="cmd")
    assert verify_finding_receipt(receipt) is True


def test_outbox_append_failure_does_not_notify_bus(tmp_path) -> None:
    reset_delivery_ledger()
    seen: list[dict] = []

    class _BoomOutbox:
        def append_events(self, envelopes, sync=True):  # noqa: ANN001
            raise RuntimeError("disk full")

        def read_all_events(self):
            return []

    def emit(*_a, **_k):
        seen.append({})

    n = dispatch_committed_findings(
        settle_res=SettlementResult(execution_id="e", status="COMMITTED", wal_id="wal_x"),
        stage_name="nuclei",
        findings=({"title": "x"},),
        emit=emit,
        event_type=SimpleNamespace(value="finding_created"),
        outbox=_BoomOutbox(),
    )
    assert n == 1
    assert seen == []


def test_hunt_budget_fenced_and_breaker_refuse_reserve() -> None:
    from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer

    class _Fenced:
        def is_fenced(self, partition_id: str) -> bool:
            return True

        def current_revision(self, partition_id: str) -> str:
            return "arev_fenced"

    enforcer = HuntBudgetEnforcer(
        HuntBudget(max_requests=10),
        label="fence",
        placement=_Fenced(),
    )
    assert enforcer.reserve_with_identity(1) is None

    open_enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=10), label="brk")
    open_enforcer.set_reserve_gate(lambda: False)
    assert open_enforcer.reserve_with_identity(1) is None
    open_enforcer.set_reserve_gate(lambda: True)
    assert open_enforcer.reserve_with_identity(1) is not None
