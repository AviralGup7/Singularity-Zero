import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_orchestrator.stages.semgrep import run_semgrep_stage


def test_semgrep_stage_parses_and_merges(tmp_path: Path):
    """Integration-style test: write a sample `semgrep.json` and run the stage.

    This test verifies the stage reads the file, parses findings, and
    marks the stage complete while populating module metrics and
    analysis results.
    """

    sample = {
        "results": [
            {
                "check_id": "SAMPLE1",
                "path": "src/example.py",
                "extra": {
                    "message": "Example semgrep issue",
                    "metadata": {"severity": "warning"},
                    "lines": 'print("insecure")',
                    "metavars": {},
                },
                "start": {"line": 10},
                "end": {"line": 10},
            }
        ]
    }

    run_dir = tmp_path
    (run_dir / "semgrep.json").write_text(json.dumps(sample), encoding="utf-8")

    ctx = PipelineContext()
    ctx.output_store = SimpleNamespace(run_dir=run_dir)
    # Assign to the underlying StageResult fields when setters are not provided
    ctx.result.previous_run = None
    ctx.result.analysis_results = {}
    ctx.result.selected_priority_items = []
    ctx.result.target_profile = {}
    ctx.result.validation_summary = {}

    config = SimpleNamespace(mode="default")
    args = None

    # Run the async stage helper
    output = asyncio.run(run_semgrep_stage(args, config, ctx))

    assert "semgrep" in output.state_delta["analysis_results"]
    assert output.metrics.get("status") == "ok"
    assert output.outcome.value == "completed"
    assert len(output.state_delta["analysis_results"]["semgrep"]) == 1
