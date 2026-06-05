"""Unit tests for StagePlanner and BudgetAllocator."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from src.pipeline.services.pipeline_orchestrator.stage_planner import StagePlanner
from src.learning.integration import LearningIntegration


class DummyConfig:
    def __init__(self):
        self.estimated_time_budget = 3600
        self.output_dir = "."


class DummyResult:
    def __init__(self):
        self.urls = []
        self.reportable_findings = []
        self.scope_entries = []
        self.subdomains = []
        self.live_hosts = []
        self.stage_status = {}
        self.module_metrics = {}


class DummyContext:
    def __init__(self):
        self.result = DummyResult()


def test_stage_planner_semgrep_js_insertion():
    config = DummyConfig()
    ctx = DummyContext()
    ctx.result.urls = ["http://example.com/static/main.js", "http://example.com/app.js"]

    learning = MagicMock()
    learning.predict_stage_value.return_value = 0.8  # high value

    planner = StagePlanner(config, ctx, learning)
    remaining = ["active_scan", "reporting"]
    
    final_stages, resources = planner.plan_stages(remaining)
    
    assert "semgrep" in final_stages
    assert resources["httpx_concurrency"] == 10  # light workload concurrency
    assert resources["katana_depth"] == 2


def test_stage_planner_subdomain_takeover_insertion():
    config = DummyConfig()
    ctx = DummyContext()
    ctx.result.scope_entries = ["*.example.com"]
    ctx.result.subdomains = ["sub1.example.com", "sub2.example.com"]

    learning = MagicMock()
    learning.predict_stage_value.return_value = 0.8

    planner = StagePlanner(config, ctx, learning)
    remaining = ["active_scan", "reporting"]
    
    final_stages, resources = planner.plan_stages(remaining)
    
    assert "subdomain_takeover" in final_stages


def test_stage_planner_threat_modeling_injection_on_high_findings():
    config = DummyConfig()
    ctx = DummyContext()
    ctx.result.reportable_findings = [dict(title=f"Finding {i}", score=60) for i in range(50)]

    learning = MagicMock()
    learning.predict_stage_value.return_value = 0.9

    planner = StagePlanner(config, ctx, learning)
    remaining = ["reporting"]
    
    final_stages, resources = planner.plan_stages(remaining)
    
    assert "threat_modeling" in final_stages
    assert final_stages.index("threat_modeling") < final_stages.index("reporting")
    assert resources["expand_report_details"] is True


def test_stage_planner_heavy_concurrency_calibration():
    config = DummyConfig()
    ctx = DummyContext()
    ctx.result.urls = [f"http://example.com/{i}" for i in range(50000)]

    learning = MagicMock()
    learning.predict_stage_value.return_value = 0.8

    planner = StagePlanner(config, ctx, learning)
    remaining = ["active_scan"]
    
    final_stages, resources = planner.plan_stages(remaining)
    
    assert resources["httpx_concurrency"] == 150
    assert resources["katana_depth"] == 5
    assert resources["rate_limit_delay"] == 0.5


def test_stage_planner_probabilistic_waf_skipping():
    config = DummyConfig()
    ctx = DummyContext()
    ctx.result.live_hosts = [f"192.168.1.{i}" for i in range(20)]

    learning = MagicMock()
    learning.predict_stage_value.return_value = 0.8

    planner = StagePlanner(config, ctx, learning)
    remaining = ["waf", "active_scan"]
    
    final_stages, resources = planner.plan_stages(remaining)
    
    # waf is removed from final_stages due to 0 sample detections
    assert "waf" not in final_stages
    assert ctx.result.stage_status["waf"] == "SKIPPED"


def test_stage_planner_budget_allocation_skipping():
    config = DummyConfig()
    ctx = DummyContext()

    learning = MagicMock()
    # Mock low predicted value for active_scan
    learning.predict_stage_value.side_effect = lambda s, c: 0.1 if s == "active_scan" else 0.8

    planner = StagePlanner(config, ctx, learning)
    remaining = ["active_scan", "reporting"]
    
    final_stages, resources = planner.plan_stages(remaining)
    
    # active_scan should be skipped because value (0.1) < threshold (0.3)
    assert "active_scan" not in final_stages
    assert ctx.result.stage_status["active_scan"] == "SKIPPED"
