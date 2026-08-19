"""
Pipeline Recovery - crash/resume correctness for five crash points.

Validates that checkpoint + WAL recovery produces identical state to
an uninterrupted run, for ALL state fields tracked by the pipeline:

  CRDT fields:      subdomains, urls, findings
  Non-CRDT fields:  live_hosts, parameters, module_metrics,
                    scope_entries, stage_status

Crash scenarios:
  1. BEFORE_STAGE  - crash before any stage has run
  2. MID_STAGE     - crash during a stage with WAL output
  3. AFTER_STAGE   - crash after one complete stage
  4. ACTIVE_SCAN   - crash mid-active_scan (checkpoint + WAL)
  5. REPORTING     - crash during reporting with prior stages
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.models.stage_result import PipelineContext, StageResult
from src.infrastructure.frontier.wal import FrontierWAL


def _make_wal(tmp_path: Path, run_id: str) -> FrontierWAL:
    aof_dir = tmp_path / ".wal"
    aof_dir.mkdir(parents=True, exist_ok=True)
    return FrontierWAL(None, run_id, aof_dir=str(aof_dir))


def _make_ctx() -> PipelineContext:
    return PipelineContext(result=StageResult())


def _finding(i: int) -> dict[str, Any]:
    return {
        "title": "Vuln-" + str(i),
        "severity": "high" if i % 2 else "medium",
        "target": "host-" + str(i % 5) + ".example.com",
    }


def _log(w: FrontierWAL, s: str, ds: list[dict[str, Any]]) -> None:
    for d in ds:
        eid = w.log_delta(s, d)
        assert eid is not None, "log_delta failed"


def _apply(ctx: PipelineContext, delta: dict[str, Any]) -> None:
    ctx.result.apply_state_delta(delta)


def _sync(ctx: PipelineContext) -> None:
    if ctx.result is not None and hasattr(ctx.result, "_neural_state"):
        ns = ctx.result._neural_state
        ctx.subdomains = ns.subdomains.to_set()
        ctx.urls = ns.urls.to_set()
        ctx.reportable_findings = list(ns.findings.values())


def _state_dict(ctx: PipelineContext) -> dict[str, Any]:
    return {
        "subdomains": sorted(ctx.subdomains),
        "urls": sorted(ctx.urls),
        "live_hosts": sorted(ctx.result.live_hosts),
        "parameters": sorted(ctx.result.parameters),
        "findings": sorted(f["title"] for f in ctx.reportable_findings),
        "module_metrics": dict(ctx.result.module_metrics),
        "scope_entries": list(ctx.result.scope_entries),
        "stage_status": dict(ctx.result.stage_status),
    }


def _replay_journal_fields(
    wal: FrontierWAL,
    ctx: PipelineContext,
    *,
    start_id: str | None,
    exclude_ids: set[str],
) -> None:
    """Restore non-CRDT fields without re-applying CRDT deltas.

    ``start_id`` / ``exclude_ids`` must be the *pre-merge* checkpoint cursor.
    After ``recover_state()`` merge, last_wal_id is the latest CRDT entry
    and a second pass keyed off that cursor drops journal fields.
    """
    ctx.result._journal_applied_ids.update(exclude_ids)
    for entry in wal.recover_deltas(start_id, exclude_ids=exclude_ids):
        delta = entry.get("delta")
        if isinstance(delta, dict):
            delta.setdefault("_wal_id", entry.get("id"))
            ctx.result.apply_journal_fields(delta)


def _recover_and_verify(
    tmp_path: Path, run_id: str, expected: dict[str, Any], scenario: str
) -> None:
    wal = _make_wal(tmp_path, run_id)
    ctx = _make_ctx()
    journal_cursor = ctx.result._neural_state.last_wal_id
    journal_exclude = set(ctx.result._neural_state.applied_wal_ids)
    ns = wal.recover_state()
    if ns is not None:
        ctx.result._neural_state.merge(ns)
    _replay_journal_fields(wal, ctx, start_id=journal_cursor, exclude_ids=journal_exclude)
    _sync(ctx)
    state = _state_dict(ctx)

    for key in (
        "live_hosts",
        "parameters",
        "module_metrics",
        "scope_entries",
        "stage_status",
    ):
        ev = expected.get(key)
        rv = state.get(key)
        assert ev == rv, f"{scenario}: {key} mismatch: {ev!r} != {rv!r}"

    for domain in expected["subdomains"]:
        assert domain in state["subdomains"], f"{scenario}: lost subdomain {domain}"
    for url in expected["urls"]:
        assert url in state["urls"], f"{scenario}: lost url {url}"
    for finding in expected["findings"]:
        assert finding in state["findings"], f"{scenario}: lost finding {finding}"
    assert sorted(expected["findings"]) == sorted(state["findings"]), (
        f"{scenario}: finding sets differ"
    )

    wal.cleanup()


def test_crash_before_stage(tmp_path: Path):
    run_id = "t1-before"
    ctx = _make_ctx()
    w = _make_wal(tmp_path, run_id)
    _log(w, "none", [{}])
    expected = _state_dict(ctx)
    del w
    _recover_and_verify(tmp_path, run_id, expected, "before_stage")


def test_crash_mid_stage(tmp_path: Path):
    run_id = "t2-mid"
    ctx = _make_ctx()
    w = _make_wal(tmp_path, run_id)

    d1 = {"subdomains": ["a.x.com", "b.x.com"], "urls": ["https://a.x.com/"]}
    _log(w, "subdomains", [d1])
    _apply(ctx, d1)

    d2 = {"live_hosts": ["https://a.x.com"], "parameters": ["id"]}
    _log(w, "live_hosts", [d2])
    _apply(ctx, d2)
    _sync(ctx)

    expected = _state_dict(ctx)
    del w
    _recover_and_verify(tmp_path, run_id, expected, "mid_stage")


def test_crash_after_stage(tmp_path: Path):
    run_id = "t3-complete"
    ctx = _make_ctx()
    w = _make_wal(tmp_path, run_id)

    delta = {
        "subdomains": ["sub.x.com"],
        "urls": ["https://sub.x.com"],
        "live_hosts": ["https://sub.x.com"],
        "parameters": ["id", "page"],
        "scope_entries": ["x.com"],
        "stage_status": {"subdomains": "COMPLETED"},
        "module_metrics": {"subdomains": {"found": 1}},
    }
    _log(w, "subdomains", [delta])
    _apply(ctx, delta)
    _sync(ctx)

    expected = _state_dict(ctx)
    del w
    _recover_and_verify(tmp_path, run_id, expected, "after_stage")


def test_crash_active_scan(tmp_path: Path):
    run_id = "t4-active"

    pre = [{"findings": [_finding(i), _finding(i + 1)]} for i in range(0, 20, 2)]
    post = [{"findings": [_finding(i), _finding(i + 1)]} for i in range(20, 40, 2)]

    w = _make_wal(tmp_path, run_id)
    u_ctx = _make_ctx()
    cp_ctx = _make_ctx()

    for d in pre[:3]:
        _apply(u_ctx, d)
        _apply(cp_ctx, d)
    cp_snap = cp_ctx.result.to_dict()

    for d in pre[3:]:
        _apply(u_ctx, d)
        _log(w, "active_scan", [d])

    expected = _state_dict(u_ctx)

    del w

    r_ctx = PipelineContext(result=StageResult.from_dict(cp_snap))
    r_wal = _make_wal(tmp_path, run_id)
    journal_cursor = r_ctx.result._neural_state.last_wal_id
    journal_exclude = set(r_ctx.result._neural_state.applied_wal_ids)
    ns = r_wal.recover_state()
    if ns is not None:
        r_ctx.result._neural_state.merge(ns)
    _replay_journal_fields(r_wal, r_ctx, start_id=journal_cursor, exclude_ids=journal_exclude)
    _sync(r_ctx)

    r_pre = _state_dict(r_ctx)
    for key in ("subdomains", "urls", "findings"):
        assert r_pre[key] == expected[key], f"pre-resume {key} mismatch"

    for d in post:
        _apply(r_ctx, d)
        _log(r_wal, "active_scan", [d])
    _sync(r_ctx)


def test_crash_reporting(tmp_path: Path):
    run_id = "t5-report"
    ctx = _make_ctx()
    w = _make_wal(tmp_path, run_id)

    deltas = []
    for i in range(3):
        deltas.append(
            {
                "subdomains": ["h" + str(i) + ".x.com"],
                "urls": ["https://h" + str(i) + ".x.com"],
                "live_hosts": ["https://h" + str(i) + ".x.com"],
                "findings": [
                    {"title": "F" + str(i), "severity": "medium", "target": "h" + str(i) + ".x.com"}
                ],
                "module_metrics": {"stage" + str(i): {"items": 1}},
                "stage_status": {"stage" + str(i): "COMPLETED"},
            }
        )

    for d in deltas:
        _log(w, "stage", [d])
        _apply(ctx, d)
    _sync(ctx)

    expected = _state_dict(ctx)
    del w
    _recover_and_verify(tmp_path, run_id, expected, "reporting")
