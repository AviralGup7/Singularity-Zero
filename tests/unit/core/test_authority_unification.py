"""Live-path authority: settlement writer, I15 CRC, I13 HMAC receipts, I27 Merkle, I29 sandbox."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.contracts.command_envelope import CommandEnvelope
from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.events import EventBus, EventType, PipelineEvent
from src.core.frontier.receipt_crypto import sign_receipt, verify_receipt_signature
from src.core.frontier.replicated_log import (
    PartitionWAL,
    ReplicatedPartitionLog,
    WALCorruptionError,
)
from src.core.frontier.state_authority import (
    SettlementCoordinator,
    SettlementResult,
    StateAuthority,
)
from src.core.models.stage_result import PipelineContext, StageResult
from src.core.security.merkle import merkle_root_from_leaf_hashes
from src.core.storage.cas_store import CASStore
from src.decision.models import ScopeToken
from src.pipeline.services.pipeline_orchestrator.orchestrator import PipelineOrchestrator
from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter
from src.sandbox.process_sandbox import ProcessSandbox, SandboxResourceLimits


def test_merge_emits_only_committed_dict_findings() -> None:
    bus = EventBus()
    seen: list[PipelineEvent] = []
    bus.subscribe(EventType.FINDING_CREATED, seen.append)
    orch = PipelineOrchestrator(event_bus=bus)

    committed = SettlementResult(
        execution_id="subdomains",
        status="COMMITTED",
        wal_id="wal_1",
        committed_findings=(
            {"title": "real", "severity": "low"},
            "not-a-dict",  # type: ignore[arg-type]
        ),
    )
    orch._settlement_coordinator_instance = SimpleNamespace(
        settle_stage_output=lambda *a, **k: committed
    )

    ctx = PipelineContext(result=StageResult())
    output = StageOutput(
        stage_name="subdomains",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=0.1,
        state_delta={"reportable_findings": [{"title": "real"}, "ghost"]},
    )
    orch._merge_stage_output(ctx, "subdomains", output)

    assert len(seen) == 1
    assert seen[0].source == "settlement.subdomains"
    assert seen[0].data["finding"]["title"] == "real"
    assert seen[0].data["wal_id"] == "wal_1"


def test_merge_does_not_emit_when_settlement_rejects() -> None:
    bus = EventBus()
    seen: list[PipelineEvent] = []
    bus.subscribe(EventType.FINDING_CREATED, seen.append)
    orch = PipelineOrchestrator(event_bus=bus)
    orch._settlement_coordinator_instance = SimpleNamespace(
        settle_stage_output=lambda *a, **k: SettlementResult(
            execution_id="x",
            status="REJECTED",
            error="nope",
            committed_findings=({"title": "should-not-emit"},),
        )
    )
    ctx = PipelineContext(result=StageResult())
    output = StageOutput(
        stage_name="subdomains",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=0.1,
        state_delta={"reportable_findings": [{"title": "should-not-emit"}]},
    )
    orch._merge_stage_output(ctx, "subdomains", output)
    assert seen == []


def test_commit_stage_output_returns_dict_findings_only() -> None:
    auth = StateAuthority()
    coord = SettlementCoordinator(state_authority=auth)
    ctx = PipelineContext(result=StageResult())
    output = StageOutput(
        stage_name="subdomains",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=0.1,
        state_delta={
            "reportable_findings": [
                {"title": "ok", "severity": "info"},
                "skip-me",
            ]
        },
    )
    result = coord.settle_stage_output(ctx, "subdomains", output)
    assert result.status == "COMMITTED"
    assert len(result.committed_findings) == 1
    assert result.committed_findings[0]["title"] == "ok"
    assert result.committed_findings[0]["severity"] == "info"


def test_partition_wal_crc_mismatch_fail_closed(tmp_path: Path) -> None:
    wal = PartitionWAL("P-0001", "node-1", wal_dir=tmp_path)
    cmd = CommandEnvelope(
        command_id="cmd_crc",
        command_type="AllocateSubLeaseCommand",
        aggregate_id="sl",
        payload={"sublease_id": "sl", "units_allocated": 1, "run_id": "R"},
        correlation_id="c",
        causation_id="x",
    )
    log = ReplicatedPartitionLog(
        partition_id="P-0001",
        node_id="node-1",
        fsm=None,
        wal_dir=tmp_path,
    )
    log.propose_and_commit(cmd)
    path = wal.wal_path
    assert path is not None and path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    record["crc64"] = "000000000000dead"
    lines[-1] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(WALCorruptionError):
        PartitionWAL("P-0001", "node-1", wal_dir=tmp_path).load_all_entries()

    with pytest.raises(WALCorruptionError):
        ReplicatedPartitionLog(partition_id="P-0001", node_id="node-1", wal_dir=tmp_path)


def test_receipt_hmac_binds_and_rejects_sha256_digest() -> None:
    cmd = CommandEnvelope(
        command_id="cmd_rcpt",
        command_type="AllocateSubLeaseCommand",
        aggregate_id="sl_r",
        payload={"sublease_id": "sl_r", "units_allocated": 3, "run_id": "R"},
        correlation_id="c",
        causation_id="x",
    )
    log = ReplicatedPartitionLog(partition_id="P-0001", is_leader=True)
    receipt, _ = log.propose_and_commit(cmd)
    assert receipt.signer_key_id != "K-2026-A"
    assert receipt.verify_signature() is True

    payload = receipt.bind_payload()
    fake_sha = hashlib.sha256(b"not-a-mac").hexdigest()
    assert verify_receipt_signature(payload, fake_sha) is False
    assert sign_receipt(payload) == receipt.cryptographic_signature


def test_cas_merkle_uses_canonical_binary_algorithm() -> None:
    cas = CASStore()
    h1 = cas.store_blob(b"evidence-one")
    h2 = cas.store_blob(b"evidence-two")
    root = cas.compute_merkle_root([h1, h2])
    assert root == merkle_root_from_leaf_hashes([h1, h2])
    assert cas.verify_merkle_root([h1, h2], root)
    old = hashlib.sha256(f"{h1}:{h2}".encode()).hexdigest()
    assert root != old


def test_process_sandbox_blocks_metadata_destination() -> None:
    token = ScopeToken(scope_hash="h", allowed_domains=("api.example.com",))
    filt = NetworkEgressFilter.from_scope_token(token)
    sandbox = ProcessSandbox(
        limits=SandboxResourceLimits(timeout_seconds=2.0),
        egress_filter=filt,
    )
    with pytest.raises(EgressViolationError):
        sandbox.run(["true"], destination_host="169.254.169.254")
    sandbox.check_egress("api.example.com")
