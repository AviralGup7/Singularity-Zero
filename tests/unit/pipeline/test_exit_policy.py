"""Tests for ExitConditionPolicy (CI/CD exit-code taxonomy)."""

from __future__ import annotations

import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.pipeline.services.ci import (
    DEFAULT_POLICY,
    ExitConditionPolicy,
    PolicyLoadError,
    SeverityThresholds,
    evaluate_policy,
    load_policy,
)
from src.pipeline.services.pipeline_orchestrator._run_execution import (
    EXIT_INFRA_FAILURE,
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_POLICY_VIOLATION,
    resolve_pipeline_exit_code,
)


def _finding(severity: str, *, category: str = "xss", fp: bool = False) -> dict:
    out = {"severity": severity, "category": category, "url": "https://x"}
    if fp:
        out["lifecycle_state"] = "FALSE_POSITIVE"
    return out


class TestPolicyLoading:
    def test_load_policy_none_returns_default(self) -> None:
        assert load_policy(None) is DEFAULT_POLICY

    def test_load_policy_minimal_toml(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.toml"
        path.write_text(
            textwrap.dedent(
                """
                [on_findings]
                max_critical = 0
                max_high = 3
                """
            ),
            encoding="utf-8",
        )
        policy = load_policy(path)
        assert policy.findings.thresholds.critical == 0
        assert policy.findings.thresholds.high == 3
        assert policy.findings.thresholds.medium == 50  # default
        assert policy.findings.allow_false_positive is True
        assert policy.infra.fatal_stages == frozenset({"live_hosts"})
        assert policy.infra.degraded_stages == frozenset({"subdomains", "urls"})

    def test_load_policy_full_toml(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.toml"
        path.write_text(
            textwrap.dedent(
                """
                [on_findings]
                max_critical = 0
                max_high = 5
                max_medium = 50
                max_low = 1000
                allow_false_positive = true
                exclude_categories = ["info-disclosure", "fingerprint"]
                branch_glob = "main"

                [on_infra]
                fatal_stages = ["subdomains", "urls"]
                degraded_stages = ["live_hosts"]

                [on_failure]
                retryable_only = false
                treat_partial_as = 4
                """
            ),
            encoding="utf-8",
        )
        policy = load_policy(path)
        assert policy.findings.thresholds.critical == 0
        assert policy.findings.exclude_categories == frozenset(
            {"info-disclosure", "fingerprint"}
        )
        assert policy.findings.branch_glob == "main"
        assert policy.infra.fatal_stages == frozenset({"subdomains", "urls"})
        assert policy.infra.degraded_stages == frozenset({"live_hosts"})
        assert policy.on_failure.treat_partial_as == 4

    def test_load_policy_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyLoadError):
            load_policy(tmp_path / "does-not-exist.toml")

    def test_load_policy_invalid_toml_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.toml"
        path.write_text("not = valid toml ===", encoding="utf-8")
        with pytest.raises(PolicyLoadError):
            load_policy(path)

    def test_load_policy_wrong_type_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.toml"
        path.write_text(
            textwrap.dedent(
                """
                [on_findings]
                max_critical = "zero"
                """
            ),
            encoding="utf-8",
        )
        with pytest.raises(PolicyLoadError, match="max_critical"):
            load_policy(path)

    def test_load_policy_negative_count_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.toml"
        path.write_text(
            textwrap.dedent(
                """
                [on_findings]
                max_high = -1
                """
            ),
            encoding="utf-8",
        )
        with pytest.raises(PolicyLoadError, match="non-negative"):
            load_policy(path)

    def test_load_policy_partial_exit_must_be_0_2_or_4(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.toml"
        path.write_text(
            textwrap.dedent(
                """
                [on_failure]
                treat_partial_as = 3
                """
            ),
            encoding="utf-8",
        )
        with pytest.raises(PolicyLoadError, match="treat_partial_as"):
            load_policy(path)


class TestSeverityThresholds:
    def test_critical_breach(self) -> None:
        t = SeverityThresholds(critical=0, high=5, medium=50, low=1000)
        assert t.violations({"critical": 1, "high": 0, "medium": 0, "low": 0}) == [
            "critical=1 > max_critical=0"
        ]

    def test_high_inclusive_of_critical(self) -> None:
        t = SeverityThresholds(critical=0, high=5, medium=50, low=1000)
        v = t.violations({"critical": 3, "high": 3, "medium": 0, "low": 0})
        assert any("high+critical=6 > max_high=5" in s for s in v)

    def test_no_breach(self) -> None:
        t = SeverityThresholds(critical=0, high=5, medium=50, low=1000)
        assert t.violations({"critical": 0, "high": 2, "medium": 10, "low": 50}) == []


class TestEvaluatePolicy:
    def test_pass_when_no_findings(self) -> None:
        result = evaluate_policy(DEFAULT_POLICY, findings=[], failed_stages={})
        assert result.exit_code == EXIT_OK
        assert result.outcome == "pass"
        assert result.violations == []

    def test_policy_violation_on_critical(self) -> None:
        result = evaluate_policy(
            DEFAULT_POLICY,
            findings=[_finding("critical")],
            failed_stages={},
        )
        assert result.exit_code == EXIT_POLICY_VIOLATION
        assert result.outcome == "policy_violation"
        assert any("critical" in v for v in result.violations)

    def test_false_positive_excluded_by_default(self) -> None:
        result = evaluate_policy(
            DEFAULT_POLICY,
            findings=[_finding("critical", fp=True)],
            failed_stages={},
        )
        assert result.exit_code == EXIT_OK

    def test_infra_failure_takes_precedence(self) -> None:
        result = evaluate_policy(
            DEFAULT_POLICY,
            findings=[_finding("low")],
            failed_stages={
                "live_hosts": {"status": "failed", "fatal": True},
            },
        )
        assert result.exit_code == EXIT_INFRA_FAILURE
        assert result.outcome == "infra_failure"
        assert result.failed_stages == ("live_hosts",)

    def test_degraded_stage_failure_downgraded_to_partial(self) -> None:
        """Degraded stages (subdomains/urls by default) should not abort
        the run with ``infra_failure`` when their failure is salvaged.
        """
        result = evaluate_policy(
            DEFAULT_POLICY,
            findings=[_finding("low")],
            failed_stages={
                "subdomains": {
                    "status": "failed",
                    "fatal": True,
                    "degraded": True,
                    "degraded_salvaged_by": "urls",
                },
            },
        )
        assert result.exit_code == EXIT_PARTIAL
        assert result.outcome == "partial"
        assert result.partial is True
        assert result.degraded_stages == ("subdomains",)
        assert result.failed_stages == ()

    def test_degraded_stage_without_salvage_is_partial(self) -> None:
        """Degraded stages without downstream salvage are still treated
        as partial failures, not infra failures.  The stage metrics
        must NOT carry the ``degraded`` flag because the policy
        evaluator treats ``fatal=True`` as an explicit override that
        promotes the failure to ``infra_failure`` regardless of the
        policy's ``degraded_stages`` set.  When a stage runner / retry
        handler decides the failure is fatal, that decision is
        honoured; the degraded path is opt-in via the explicit
        ``degraded=True`` metric set by
        ``resolve_pipeline_exit_code``.
        """
        result = evaluate_policy(
            DEFAULT_POLICY,
            findings=[],
            failed_stages={
                "subdomains": {"status": "failed"},
            },
        )
        assert result.exit_code == EXIT_PARTIAL
        assert result.outcome == "partial"
        assert result.partial is True

    def test_partial_when_non_fatal_fails(self) -> None:
        result = evaluate_policy(
            DEFAULT_POLICY,
            findings=[],
            failed_stages={
                "semgrep": {"status": "failed", "fatal": False},
            },
        )
        assert result.exit_code == EXIT_PARTIAL
        assert result.outcome == "partial"
        assert result.partial is True

    def test_exclude_categories(self) -> None:
        policy = ExitConditionPolicy(
            findings=__import__(
                "src.pipeline.services.ci.policy", fromlist=["FindingsRule"]
            ).FindingsRule(
                thresholds=SeverityThresholds(critical=0, high=5, medium=50, low=1000),
                exclude_categories=frozenset({"info-disclosure"}),
            )
        )
        result = evaluate_policy(
            policy,
            findings=[_finding("critical", category="info-disclosure")],
            failed_stages={},
        )
        assert result.exit_code == EXIT_OK

    def test_branch_glob_mismatch_skips_findings_check(self) -> None:
        policy = ExitConditionPolicy(
            findings=__import__(
                "src.pipeline.services.ci.policy", fromlist=["FindingsRule"]
            ).FindingsRule(
                thresholds=SeverityThresholds(critical=0, high=5, medium=50, low=1000),
                branch_glob="main",
            )
        )
        # Critical finding on a feature branch: branch_glob is "main", not match.
        result = evaluate_policy(
            policy,
            findings=[_finding("critical")],
            failed_stages={},
            branch="feature/x",
        )
        assert result.exit_code == EXIT_OK
        # Same finding on main: policy applies.
        result_main = evaluate_policy(
            policy,
            findings=[_finding("critical")],
            failed_stages={},
            branch="main",
        )
        assert result_main.exit_code == EXIT_POLICY_VIOLATION

    def test_to_dict_round_trip(self) -> None:
        snapshot = DEFAULT_POLICY.to_dict()
        assert snapshot["on_findings"]["max_critical"] == 0
        assert "live_hosts" in snapshot["on_infra"]["fatal_stages"]
        assert "subdomains" in snapshot["on_infra"]["degraded_stages"]
        assert "urls" in snapshot["on_infra"]["degraded_stages"]


class TestResolvePipelineExitCodeIntegration:
    """Test the orchestrator-facing exit-code resolver."""

    def _ctx(self) -> SimpleNamespace:
        from src.core.models.stage_result import PipelineContext

        return PipelineContext()

    def test_pass_when_clean(self) -> None:
        from src.core.events import reset_event_bus

        reset_event_bus()
        ctx = self._ctx()
        exit_code = resolve_pipeline_exit_code(
            SimpleNamespace(),
            ctx=ctx,
            config=SimpleNamespace(target_name="example.com"),
            started_at=0.0,
            progress_emitter=lambda *_a, **_k: None,
            args=SimpleNamespace(),
        )
        assert exit_code == EXIT_OK

    def test_infra_failure_emits_event(self) -> None:
        from src.core.events import EventType, get_event_bus, reset_event_bus

        reset_event_bus()
        bus = get_event_bus()
        received: list[object] = []
        bus.subscribe(EventType.INGRESS_POLICY_RESULT, lambda evt: received.append(evt))

        class _Ctx:
            class result:  # noqa: N801 — mirrors PipelineContext.result
                reportable_findings: list = []
                stage_status = {"live_hosts": "FAILED"}
                module_metrics = {"live_hosts": {"fatal": True, "status": "failed"}}
                cancel_requested = False

        ctx = _Ctx()
        exit_code = resolve_pipeline_exit_code(
            SimpleNamespace(),
            ctx=ctx,
            config=SimpleNamespace(target_name="x"),
            started_at=0.0,
            progress_emitter=lambda *_a, **_k: None,
            args=SimpleNamespace(),
        )
        assert exit_code == EXIT_INFRA_FAILURE
        assert len(received) == 1

    def test_policy_violation_path(self) -> None:
        from src.core.events import reset_event_bus

        reset_event_bus()
        ctx = self._ctx()
        ctx.reportable_findings = [_finding("critical")]
        exit_code = resolve_pipeline_exit_code(
            SimpleNamespace(),
            ctx=ctx,
            config=SimpleNamespace(target_name="x"),
            started_at=0.0,
            progress_emitter=lambda *_a, **_k: None,
            args=SimpleNamespace(),
        )
        assert exit_code == EXIT_POLICY_VIOLATION

    def test_legacy_exit_codes_collapses_to_1(self) -> None:
        from src.core.events import reset_event_bus

        reset_event_bus()
        ctx = self._ctx()
        ctx.reportable_findings = [_finding("critical")]
        exit_code = resolve_pipeline_exit_code(
            SimpleNamespace(),
            ctx=ctx,
            config=SimpleNamespace(target_name="x"),
            started_at=0.0,
            progress_emitter=lambda *_a, **_k: None,
            args=SimpleNamespace(legacy_exit_codes=True),
        )
        assert exit_code == 1

    def test_cancel_returns_130(self) -> None:
        from src.core.events import reset_event_bus

        reset_event_bus()
        ctx = self._ctx()
        ctx.result.cancel_requested = True
        exit_code = resolve_pipeline_exit_code(
            SimpleNamespace(),
            ctx=ctx,
            config=SimpleNamespace(target_name="x"),
            started_at=0.0,
            progress_emitter=lambda *_a, **_k: None,
            args=SimpleNamespace(),
        )
        assert exit_code == 130
