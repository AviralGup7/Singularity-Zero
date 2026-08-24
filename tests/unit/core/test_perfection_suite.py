"""Comprehensive unit test suite for the Architectural Perfection Suite."""

import asyncio
from dataclasses import FrozenInstanceError

# Pillar 1: Monadic Result Types & Failure Domains
from src.core.types.result import Ok, Err, Result
from src.core.types.failure import DomainFailure, FailureDomain


class TestResultMonad:
    def test_ok_mapping_and_unwrap(self):
        res: Result[int, str] = Ok(10)
        assert res.is_ok() is True
        assert res.is_err() is False
        assert res.unwrap() == 10
        assert res.unwrap_or(0) == 10
        mapped = res.map(lambda x: x * 2)
        assert mapped.unwrap() == 20
        bound = res.and_then(lambda x: Ok(str(x)))
        assert bound.unwrap() == "10"

    def test_err_mapping_and_unwrap(self):
        fail: Result[int, DomainFailure] = Err(DomainFailure.transient("Connection reset", retry_after=1.5))
        assert fail.is_ok() is False
        assert fail.is_err() is True
        assert fail.unwrap_or(42) == 42
        err = fail.unwrap_err()
        assert err.domain == FailureDomain.TRANSIENT_NETWORK
        assert err.retryable is True
        assert err.retry_after_seconds == 1.5


# Pillar 2: Typestate Automaton
from src.core.state.typestate import (
    TargetState,
    TargetTypestate,
    FindingState,
    FindingTypestate,
    InvalidStateTransitionError,
)


class TestTypestateAutomaton:
    def test_valid_target_transitions(self):
        t = TargetTypestate(url="https://example.com/api")
        assert t.state == TargetState.ENQUEUED
        leased = t.transition_to(TargetState.LEASED, reason="Worker 1 claimed")
        assert leased.state == TargetState.LEASED
        probing = leased.transition_to(TargetState.PROBING)
        assert probing.state == TargetState.PROBING
        evaluating = probing.transition_to(TargetState.EVALUATING)
        completed = evaluating.transition_to(TargetState.COMPLETED)
        assert completed.state == TargetState.COMPLETED
        assert completed.is_terminal() is True

    def test_invalid_target_transition_raises_error(self):
        t = TargetTypestate(url="https://example.com/api")
        threw = False
        try:
            t.transition_to(TargetState.COMPLETED)  # Cannot jump enqueued -> completed directly
        except InvalidStateTransitionError:
            threw = True
        assert threw is True


# Pillar 3: Bayesian Bandit & Pareto Scheduling
from src.decision.bayesian_bandit import BayesianParameterBandit, BetaBinomialArm, ParetoObjective


class TestBayesianBanditAndPareto:
    def test_beta_binomial_bayesian_updates(self):
        arm = BetaBinomialArm(alpha=1.0, beta_param=3.0)
        initial_mean = arm.expected_value()
        arm.record_outcome(found_vulnerability=True, weight=2.0)
        assert arm.alpha == 3.0
        assert arm.expected_value() > initial_mean

    def test_bandit_scoring(self):
        bandit = BayesianParameterBandit()
        score = bandit.score_target(archetypes=["user_id", "auth_token"], base_priority=10.0)
        assert score >= 10.0
        bandit.update(["user_id"], found_vulnerability=True)
        new_score = bandit.score_target(archetypes=["user_id"], base_priority=10.0)
        assert new_score > 10.0

    def test_pareto_objective(self):
        obj = ParetoObjective(exploitability=9.0, business_impact=9.0, latency_cost_ms=100.0, bayesian_prob=0.8)
        score = obj.pareto_score()
        assert score > 0


# Pillar 4: Reactive Event Bus & Event Store
from src.core.events.events import (
    TargetEnqueuedEvent,
    TargetDispatchedEvent,
    FindingDiscoveredEvent,
    TargetBoostedEvent,
)
from src.core.events.store import EventStore
from src.core.events.bus import EventBus


class TestEventStoreAndBus:
    def test_event_store_append_and_projection(self):
        store = EventStore()
        ev1 = TargetEnqueuedEvent(url="https://example.com/a", priority=10.0)
        ev2 = TargetDispatchedEvent(url="https://example.com/a", worker_id="w-1")
        ev3 = FindingDiscoveredEvent(url="https://example.com/a", category="ssrf", severity="high", confidence=0.9)
        store.append(ev1)
        store.append(ev2)
        store.append(ev3)

        assert store.count() == 3

        def count_findings(accum: int, ev):
            if ev.event_type == "finding_discovered":
                return accum + 1
            return accum

        findings_count = store.project(0, count_findings)
        assert findings_count == 1

    async def test_event_bus_pubsub(self):
        bus = EventBus()
        received = []

        async def on_finding(ev):
            received.append(ev.category)

        bus.subscribe("finding_discovered", on_finding)
        await bus.publish(FindingDiscoveredEvent(url="https://a.com", category="idor"))
        assert received == ["idor"]


# Pillar 5: Symbolic Attack DAG Solver
from src.decision.attack_dag import AttackDAG, AttackNode, AttackEdge


class TestAttackDAGSolver:
    def test_dag_reachability_and_pruning(self):
        dag = AttackDAG("auth_chain", "Multi-step Auth Bypass")
        node1 = AttackNode(
            node_id="step1",
            action="extract_token",
            required_facts=(),
            emitted_facts=("has_token",),
            goal="Get session token",
        )
        node2 = AttackNode(
            node_id="step2",
            action="cross_tenant_access",
            required_facts=("has_token", "multi_tenant_env"),
            emitted_facts=("tenant_leaked",),
            goal="Access other tenant",
        )
        dag.add_node(node1)
        dag.add_node(node2)
        dag.add_edge("step1", "step2")

        # Case A: multi_tenant_env is NOT in known facts -> step2 should be pruned
        path_a = dag.solve_reachability(known_facts=set())
        assert len(path_a) == 1
        assert path_a[0].node_id == "step1"

        # Case B: multi_tenant_env IS in known facts -> both step1 and step2 are executable
        path_b = dag.solve_reachability(known_facts={"multi_tenant_env"})
        assert len(path_b) == 2
        assert [n.node_id for n in path_b] == ["step1", "step2"]


# Pillar 6: Cryptographic Merkle Tree Evidence
from src.core.security.merkle import MerkleTree, MerkleProof


class TestMerkleEvidenceTree:
    def test_merkle_tree_construction_and_verification(self):
        evidence_items = [
            {"request": "GET /api/user/1", "timestamp": 12345},
            {"response_sha256": "abcdef123456", "status": 200},
            {"diff_state": "privilege_escalation_detected"},
            {"probe_id": "probe_idor_01"},
        ]
        tree = MerkleTree(evidence_items)
        assert len(tree.root) == 64  # Valid SHA-256 hex string

        # Generate and verify proof for leaf 1
        proof = tree.generate_proof(1)
        assert proof.verify() is True

        # Tampered leaf should fail verification
        tampered_proof = MerkleProof(
            leaf_hash="0" * 64,
            audit_path=proof.audit_path,
            root_hash=proof.root_hash,
        )
        assert tampered_proof.verify() is False
