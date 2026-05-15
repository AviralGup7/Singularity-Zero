from types import SimpleNamespace

import pytest

from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_orchestrator.stages import enrichment as enrichment_stage


class _DummyLearningClient:
    def emit_feedback_events(self, _ctx: dict, _findings: list[dict]) -> None:
        return None


class _DummyLearningIntegration:
    @staticmethod
    def get_or_create(_ctx: dict) -> _DummyLearningClient:
        return _DummyLearningClient()


class _DummyCVESyncClient:
    def __init__(self, _config: object) -> None:
        pass

    async def __aenter__(self) -> _DummyCVESyncClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def search_cves(self, keyword: str) -> object:
        return SimpleNamespace(entries=[])


class _DummyMitreAttackMapper:
    def __init__(self, _config: object) -> None:
        pass

    async def __aenter__(self) -> _DummyMitreAttackMapper:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def get_techniques_by_tactic(self, _category: str) -> list[object]:
        return []


class _CountingCVESyncClient(_DummyCVESyncClient):
    calls: list[str] = []

    async def search_cves(self, keyword: str, **_kwargs: object) -> object:
        self.calls.append(keyword)
        return SimpleNamespace(entries=[])


class _CountingMitreAttackMapper(_DummyMitreAttackMapper):
    calls: list[str] = []

    async def get_techniques_by_tactic(self, category: str) -> list[object]:
        self.calls.append(category)
        return []


@pytest.mark.asyncio
async def test_enrichment_findings_are_added_to_merged_and_reportable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_finding = {
        "module": "api_security",
        "category": "api_security",
        "title": "Public debug endpoint exposed",
        "url": "https://example.com/debug",
        "severity": "high",
        "confidence": 0.9,
        "evidence": {"signals": ["debug_endpoint"]},
    }

    monkeypatch.setattr(
        enrichment_stage, "enrich_findings_with_cvss", lambda findings: list(findings)
    )
    monkeypatch.setattr(
        enrichment_stage, "api_security_analyzer", lambda _responses: [dict(api_finding)]
    )
    monkeypatch.setattr(enrichment_stage, "dns_security_analyzer", lambda _domains: [])
    monkeypatch.setattr(enrichment_stage, "correlate_findings", lambda findings: findings)
    monkeypatch.setattr(enrichment_stage, "detect_multi_vector_endpoints", lambda _findings: [])
    monkeypatch.setattr(enrichment_stage, "calculate_compound_risk", lambda _findings: {})
    monkeypatch.setattr(
        enrichment_stage,
        "annotate_finding_decisions",
        lambda findings, target_profile=None: [{**item, "decision": "KEEP"} for item in findings],
    )
    monkeypatch.setattr(
        enrichment_stage,
        "apply_lifecycle",
        lambda findings: [{**item, "lifecycle_state": "detected"} for item in findings],
    )
    monkeypatch.setattr(
        enrichment_stage, "filter_reportable_findings", lambda findings: list(findings)
    )
    monkeypatch.setattr("src.learning.integration.LearningIntegration", _DummyLearningIntegration)
    monkeypatch.setattr(enrichment_stage, "CVESyncClient", _DummyCVESyncClient)
    monkeypatch.setattr(enrichment_stage, "MitreAttackMapper", _DummyMitreAttackMapper)

    def _mock_resolve_plugin(*_args, **_kwargs):
        raise KeyError()

    monkeypatch.setattr(enrichment_stage, "resolve_plugin", _mock_resolve_plugin)

    ctx = PipelineContext()
    ctx.result.merged_findings = [
        {
            "module": "baseline",
            "category": "idor",
            "title": "Existing finding",
            "url": "https://example.com/users/1",
            "severity": "medium",
            "confidence": 0.6,
            "evidence": {},
        }
    ]
    ctx.result.reportable_findings = list(ctx.result.merged_findings)
    ctx.result.analysis_results = {}
    ctx.result.live_records = [{"url": "https://example.com/debug", "status_code": 200}]
    ctx.result.subdomains = {"example.com"}

    output = await enrichment_stage.run_post_analysis_enrichments(
        args=SimpleNamespace(),
        config=SimpleNamespace(),
        ctx=ctx,
    )

    assert "api_security" in output.state_delta["analysis_results"]
    assert len(output.state_delta["analysis_results"]["api_security"]) == 1

    merged_titles = {item.get("title") for item in output.state_delta["merged_findings"]}
    reportable_titles = {item.get("title") for item in output.state_delta["reportable_findings"]}
    assert "Public debug endpoint exposed" in merged_titles
    assert "Public debug endpoint exposed" in reportable_titles


@pytest.mark.asyncio
async def test_threat_intel_budget_limits_feed_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _CountingCVESyncClient.calls = []
    _CountingMitreAttackMapper.calls = []

    monkeypatch.setattr(
        enrichment_stage, "enrich_findings_with_cvss", lambda findings: list(findings)
    )
    monkeypatch.setattr(enrichment_stage, "api_security_analyzer", lambda _responses: [])
    monkeypatch.setattr(enrichment_stage, "dns_security_analyzer", lambda _domains: [])
    monkeypatch.setattr(enrichment_stage, "correlate_findings", lambda _findings: [])
    monkeypatch.setattr(enrichment_stage, "detect_multi_vector_endpoints", lambda _findings: [])
    monkeypatch.setattr(enrichment_stage, "calculate_compound_risk", lambda _findings: {})
    monkeypatch.setattr(
        enrichment_stage,
        "annotate_finding_decisions",
        lambda findings, target_profile=None: findings,
    )
    monkeypatch.setattr(enrichment_stage, "apply_lifecycle", lambda findings: findings)
    monkeypatch.setattr(
        enrichment_stage, "filter_reportable_findings", lambda findings: list(findings)
    )
    monkeypatch.setattr("src.learning.integration.LearningIntegration", _DummyLearningIntegration)
    monkeypatch.setattr(enrichment_stage, "CVESyncClient", _CountingCVESyncClient)
    monkeypatch.setattr(enrichment_stage, "MitreAttackMapper", _CountingMitreAttackMapper)

    reportable_findings = [
        {
            "module": "access_control",
            "category": "auth_bypass_no_auth",
            "title": f"Authorization bypass candidate {idx}",
            "url": f"https://example.com/path/{idx}",
            "severity": "high",
            "confidence": 0.9,
            "evidence": {},
        }
        for idx in range(8)
    ]

    ctx = PipelineContext()
    ctx.result.merged_findings = list(reportable_findings)
    ctx.result.reportable_findings = list(reportable_findings)
    ctx.result.analysis_results = {}

    output = await enrichment_stage.run_post_analysis_enrichments(
        args=SimpleNamespace(),
        config=SimpleNamespace(
            analysis={
                "threat_intel_max_findings": 3,
                "threat_intel_max_feed_concurrency": 1,
                "threat_intel_per_finding_timeout_seconds": 3,
                "threat_intel_cve_timeout_seconds": 3,
                "threat_intel_cve_max_retries": 0,
            }
        ),
        ctx=ctx,
    )

    metrics = output.metrics.get("threat_intel", {})
    assert metrics.get("candidate_findings") == 3
    assert metrics.get("total_reportable_findings") == 8
    assert metrics.get("skipped_findings") == 5
    assert len(_CountingCVESyncClient.calls) == 3
    assert len(_CountingMitreAttackMapper.calls) == 3
    assert len(_CountingMitreAttackMapper.calls) == 3
