from dataclasses import FrozenInstanceError
from typing import Any

try:
    import pytest
except ImportError:
    class _PytestMock:
        @staticmethod
        def raises(expected_exc):
            class _RaisesContext:
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc_val, exc_tb):
                    if exc_type is None or not issubclass(exc_type, expected_exc):
                        raise AssertionError(f"Expected exception {expected_exc}, got {exc_type}")
                    return True
            return _RaisesContext()
    pytest = _PytestMock()  # type: ignore[assignment]

from src.decision.models import (
    AttackPlan,
    AttackStep,
    BudgetSnapshot,
    Finding,
    FindingDecision,
    ScanPlan,
    ScanResult,
    ScanTarget,
    StageRequest,
    StageResult,
)
from src.decision.attack_selection import select_validation_attack_plans
from src.decision.adaptive_scan import AdaptiveScanCoordinator


class TestFindingDecision:
    def test_immutability(self):
        decision = FindingDecision(decision="HIGH", reason="Confirmed SQLi")
        with pytest.raises(FrozenInstanceError):
            decision.decision = "LOW"  # type: ignore[misc]

    def test_serialization_round_trip(self):
        raw = {
            "decision": "HIGH",
            "reason": "Differential auth bypass",
            "confidence_factors": {"signal": 0.9, "history": 0.8},
            "diff_score": 5,
            "diff_classification": "auth_bypass_indicator",
            "suppress_reason": "",
            "thresholds_used": {"low": 0.45, "medium": 0.58, "high": 0.72},
            "reportable": True,
        }
        obj = FindingDecision.from_dict(raw)
        assert obj.decision == "HIGH"
        assert obj.diff_score == 5
        assert obj.reportable is True
        d = obj.to_dict()
        assert d["decision"] == "HIGH"
        assert d["diff_score"] == 5
        assert d["confidence_factors"]["signal"] == 0.9


class TestAttackPlanAndStep:
    def test_attack_step_immutability(self):
        step = AttackStep(order=1, action="token_replay_check", goal="Verify token reuse")
        with pytest.raises(FrozenInstanceError):
            step.order = 2  # type: ignore[misc]

    def test_attack_plan_round_trip(self):
        step1 = AttackStep(order=1, action="token_replay_check", goal="Capture token")
        step2 = AttackStep(order=2, action="auth_boundary_probe", goal="Verify boundary")
        plan = AttackPlan(
            rule_id="tenant_chain",
            score=6,
            reason="Multi-step bypass",
            prerequisites=("token_replay_check", "auth_boundary_probe"),
            required_sessions=("user_a", "user_b"),
            stop_conditions=("stop_on_bypass",),
            steps=(step1, step2),
        )
        with pytest.raises(FrozenInstanceError):
            plan.score = 10  # type: ignore[misc]

        d = plan.to_dict()
        assert d["rule_id"] == "tenant_chain"
        assert len(d["steps"]) == 2
        assert d["steps"][0]["action"] == "token_replay_check"

        restored = AttackPlan.from_dict(d)
        assert restored.rule_id == "tenant_chain"
        assert len(restored.steps) == 2
        assert restored.steps[1].goal == "Verify boundary"

    def test_select_validation_attack_plans(self):
        plans = select_validation_attack_plans(
            url="https://example.com/api/tenant/1/users?user_id=1",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint", "identifier_access"],
            scope_hosts={"example.com"},
        )
        assert isinstance(plans, tuple)
        assert len(plans) > 0
        assert all(isinstance(p, AttackPlan) for p in plans)
        rule_ids = {p.rule_id for p in plans}
        assert "tenant_identifier_access_chain" in rule_ids
        assert "auth_bypass_idor_chain" in rule_ids


class TestFinding:
    def test_finding_immutability(self):
        f = Finding(
            category="idor",
            title="IDOR on /users",
            url="https://example.com/users",
            severity="high",
            confidence=0.85,
            score=70,
            evidence=(("diff", {"status_changed": True}),),
            signals=("identifier_access",),
        )
        with pytest.raises(FrozenInstanceError):
            f.confidence = 0.95  # type: ignore[misc]

    def test_finding_round_trip(self):
        raw = {
            "category": "ssrf",
            "title": "SSRF in webhook",
            "url": "https://example.com/webhook",
            "severity": "critical",
            "confidence": 0.92,
            "score": 100,
            "evidence": {"callback_received": True},
            "signals": ["internal_host_reference"],
            "decision": {
                "decision": "HIGH",
                "reason": "OOB callback verified",
                "diff_score": 4,
                "reportable": True,
            },
        }
        f = Finding.from_dict(raw)
        assert f.category == "ssrf"
        assert f.severity == "critical"
        assert f.decision is not None
        assert f.decision.decision == "HIGH"

        d = f.to_dict()
        assert d["category"] == "ssrf"
        assert d["evidence"]["callback_received"] is True
        assert d["decision"]["decision"] == "HIGH"


class TestScanResult:
    def test_scan_result_immutability(self):
        finding = Finding(
            category="info",
            title="Banner",
            url="https://example.com",
            severity="info",
            confidence=1.0,
        )
        res = ScanResult(
            target="https://example.com",
            success=True,
            findings=(finding,),
            duration_ms=45.2,
        )
        with pytest.raises(FrozenInstanceError):
            res.success = False  # type: ignore[misc]

        d = res.to_dict()
        assert d["target"] == "https://example.com"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["title"] == "Banner"

        restored = ScanResult.from_dict(d)
        assert restored.target == "https://example.com"
        assert len(restored.findings) == 1


class TestBudgetSnapshot:
    def test_budget_snapshot_immutability(self):
        snap = BudgetSnapshot(
            elapsed_seconds=12.5,
            requests_emitted=42,
            productive_findings=3,
            high_confidence_findings=1,
            exhausted_axes=("requests",),
            terminated_early=True,
        )
        with pytest.raises(FrozenInstanceError):
            snap.requests_emitted = 50  # type: ignore[misc]

        d = snap.to_dict()
        assert d["elapsed_seconds"] == 12.5
        assert d["requests_emitted"] == 42
        assert d["exhausted_axes"] == ["requests"]
        assert d["terminated_early"] is True

        restored = BudgetSnapshot.from_dict(d)
        assert restored.requests_emitted == 42
        assert restored.terminated_early is True


class TestScanPlan:
    def test_scan_plan_and_coordinator_from_plan(self):
        plan = ScanPlan(
            targets=("https://example.com/a", "https://example.com/b"),
            batch_size=10,
            concurrency=2,
            boost_factor=3.0,
        )
        with pytest.raises(FrozenInstanceError):
            plan.batch_size = 20  # type: ignore[misc]

        d = plan.to_dict()
        assert d["targets"] == ["https://example.com/a", "https://example.com/b"]
        assert d["batch_size"] == 10

        restored = ScanPlan.from_dict(d)
        assert restored.targets == ("https://example.com/a", "https://example.com/b")
        assert restored.batch_size == 10

        async def dummy_probe(url):
            return []

        coord = AdaptiveScanCoordinator.from_plan(plan, dummy_probe)
        assert coord._batch_size == 10
        assert coord._concurrency == 2
        assert coord._queue.total == 2


class TestScanTargetModel:
    def test_scan_target_immutability(self):
        target = ScanTarget(
            url="https://example.com/api",
            base_priority=10.0,
            current_priority=20.0,
            effective_priority=19.5,
            bid_score=15.2,
            findings_count=1,
            boost_factors=("param_overlap",),
        )
        with pytest.raises(FrozenInstanceError):
            target.current_priority = 50.0  # type: ignore[misc]

        d = target.to_dict()
        assert d["url"] == "https://example.com/api"
        assert d["boost_factors"] == ["param_overlap"]

        restored = ScanTarget.from_dict(d)
        assert restored.url == "https://example.com/api"
        assert restored.findings_count == 1


class TestStageRequestAndResult:
    def test_stage_request(self):
        req = StageRequest(
            stage_name="active_scan",
            targets=("https://example.com",),
            parameters=(("timeout", 10),),
            timeout_seconds=60.0,
            context_id="ctx-123",
        )
        with pytest.raises(FrozenInstanceError):
            req.stage_name = "scope"  # type: ignore[misc]

        d = req.to_dict()
        assert d["stage_name"] == "active_scan"
        assert d["parameters"]["timeout"] == 10
        assert d["context_id"] == "ctx-123"

        restored = StageRequest.from_dict(d)
        assert restored.stage_name == "active_scan"
        assert restored.context_id == "ctx-123"

    def test_stage_result(self):
        finding = Finding(
            category="xss",
            title="Reflected XSS",
            url="https://example.com/search",
            severity="medium",
            confidence=0.8,
        )
        res = StageResult(
            stage_name="active_scan",
            outcome="completed",
            duration_seconds=14.2,
            metrics=(("targets_scanned", 10),),
            findings=(finding,),
            state_delta=(("scanned_count", 10),),
        )
        with pytest.raises(FrozenInstanceError):
            res.outcome = "failed"  # type: ignore[misc]

        d = res.to_dict()
        assert d["stage_name"] == "active_scan"
        assert d["outcome"] == "completed"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["title"] == "Reflected XSS"

        restored = StageResult.from_dict(d)
        assert restored.stage_name == "active_scan"
        assert len(restored.findings) == 1
