"""Tests for multi-objective bidding and dispatch ordering."""

import time

import pytest

from src.core.contracts.task_envelope import TaskEnvelope
from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget
from src.infrastructure.execution_engine._scheduler import _DAGScheduler
from src.infrastructure.execution_engine.models import Task, TaskPriority
from src.infrastructure.queue.job_queue import JobQueue
from src.infrastructure.queue.redis_client import RedisClient
from src.infrastructure.scheduling.bidding import bid_from_mapping, score_with_runtime_contention


def test_bid_balances_security_business_sla_and_saturation() -> None:
    now = time.time()
    urgent = bid_from_mapping(
        metadata={
            "exploitability": 0.95,
            "business_criticality": 0.9,
            "analyst_sla_deadline": now - 1,
            "bloom_mesh_saturation": 0.1,
            "historical_scan_velocity": 0.8,
        },
        priority=7,
        created_at=now - 30,
        now=now,
    )
    noisy = bid_from_mapping(
        metadata={
            "exploitability": 0.2,
            "business_criticality": 0.2,
            "bloom_mesh_saturation": 0.95,
            "resource_contention": 0.9,
            "historical_scan_velocity": 0.2,
        },
        priority=10,
        created_at=now - 30,
        now=now,
    )

    assert urgent.score > noisy.score


def test_correlation_queue_orders_by_bid_not_plain_priority() -> None:
    queue = CorrelationPriorityQueue(
        [
            ScanTarget(
                url="https://app.example.com/admin",
                base_priority=4,
                current_priority=4,
                metadata={"exploitability": 0.95, "business_criticality": 0.95},
            ),
            ScanTarget(
                url="https://static.example.com/health",
                base_priority=8,
                current_priority=8,
                metadata={"bloom_mesh_saturation": 0.95, "resource_contention": 0.95},
            ),
        ]
    )

    first = queue.pop()
    assert first is not None
    assert first.url.endswith("/admin")


def test_dag_scheduler_uses_multi_objective_bid_inside_ready_layer() -> None:
    def dummy() -> None:
        return None

    low_value = Task(
        id="low",
        name="low",
        fn=dummy,
        priority=TaskPriority.CRITICAL,
        metadata={"exploitability": 0.1, "business_criticality": 0.1},
    )
    critical_finding = Task(
        id="critical",
        name="critical",
        fn=dummy,
        priority=TaskPriority.NORMAL,
        metadata={"exploitability": 1.0, "business_criticality": 1.0, "analyst_sla_seconds": 1},
    )

    layers = _DAGScheduler([low_value, critical_finding]).get_layers()

    assert [task.id for task in layers[0]][0] == "critical"


def test_runtime_resource_saturation_penalizes_contentious_bid() -> None:
    bid = bid_from_mapping(priority=8, resource_types=["network"])

    unsaturated = score_with_runtime_contention(bid, resource_saturation={"network": 0.0})
    saturated = score_with_runtime_contention(bid, resource_saturation={"network": 1.0})

    assert saturated < unsaturated


@pytest.mark.asyncio
async def test_job_queue_claims_highest_bid_with_fallback_redis() -> None:
    queue = JobQueue(RedisClient(), queue_name="bid-test", enable_scheduler=False)

    low_id = await queue.enqueue(
        TaskEnvelope(
            type="port_probe",
            payload={"target": "slow.example"},
            metadata={"exploitability": 0.1, "business_criticality": 0.1},
        ),
        priority=10,
    )
    high_id = await queue.enqueue(
        TaskEnvelope(
            type="dom_xss",
            payload={"target": "critical.example"},
            metadata={"exploitability": 1.0, "business_criticality": 1.0},
        ),
        priority=5,
    )

    claimed = await queue.claim_job("worker-1")

    assert claimed is not None
    assert claimed.id == high_id
    assert claimed.id != low_id
