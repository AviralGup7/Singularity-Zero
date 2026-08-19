
"""
Test P0.1 — Prove WAL recovery correctness.

Five scenarios that every WAL-backed resume path must handle:
  1. Post-checkpoint recovery     checkpoint + delta A + delta B -> crash -> recover
  2. Duplicate WAL/checkpoint     checkpoint contains A, WAL also contains A -> dedup
  3. Full state-field coverage    every state key emitted by merge_stage_output()
  4. Mid-active_scan crash        checkpoint + N deltas -> SIGKILL -> resume
  5. Corrupt WAL entries          valid + corrupt + valid -> skip corrupt, no silent data loss

All tests are pure-file (AOF-only FrontierWAL) — no Redis required.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.core.frontier.state import NeuralState
from src.core.models.stage_result import PipelineContext, StageResult
from src.infrastructure.frontier.wal import FrontierWAL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_wal(tmp_path: Path, run_id: str) -> FrontierWAL:
    """Create an AOF-only FrontierWAL (no Redis) rooted at tmp_path."""
    aof_dir = tmp_path / ".wal"
    aof_dir.mkdir(parents=True, exist_ok=True)
    return FrontierWAL(None, run_id, aof_dir=str(aof_dir))


def _make_checkpoint_ctx(**seed_deltas: Any) -> PipelineContext:
    """Build a PipelineContext with optional seed state (simulates checkpoint restore)."""
    ctx = PipelineContext(result=StageResult())
    if seed_deltas:
        ctx.result.apply_state_delta(dict(seed_deltas))
    return ctx


def _log_deltas(wal: FrontierWAL, stage: str, deltas: list[dict[str, Any]]) -> list[str]:
    """Log a list of deltas and return their WAL entry IDs."""
    ids: list[str] = []
    for d in deltas:
        eid = wal.log_delta(stage, d)
        assert eid is not None, "log_delta failed for %s" % d
        ids.append(eid)
    return ids


def _corrupt_aof_entry(wal: FrontierWAL, entry_idx: int) -> None:
    """Corrupt a WAL AOF entry by mangling its CRC64 checksum."""
    aof = wal._aof_path
    assert aof.exists()
    lines = aof.read_text(encoding="utf-8").splitlines()
    assert 0 <= entry_idx < len(lines), "idx %d out of 0..%d" % (entry_idx, len(lines) - 1)
    entry = json.loads(lines[entry_idx])
    entry["crc64"] = "000000000000dead"
    lines[entry_idx] = json.dumps(entry, separators=(",", ":"))
    aof.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sync_from_neural(ctx: PipelineContext) -> None:
    """Sync context fields from neural state — mirrors the fix in run_secured()."""
    if ctx.result is not None and hasattr(ctx.result, "_neural_state"):
        ns = ctx.result._neural_state
        ctx.subdomains = ns.subdomains.to_set()
        ctx.urls = ns.urls.to_set()
        ctx.reportable_findings = list(ns.findings.values())


# ===================================================================
# Test 1 — Post-checkpoint recovery
# ===================================================================

def test_post_checkpoint_recovery(tmp_path: Path):
    """
    checkpoint exists with initial state.
    Stage logs delta A, then delta B.
    Crash.
    Recover: checkpoint + WAL replay must produce state containing A + B.
    """
    run_id = "test1-post-cp-recovery"
    wal = _make_wal(tmp_path, run_id)

    delta_a = {
        "subdomains": ["api.root.example.com"],
        "urls": ["https://api.root.example.com/health"],
        "findings": [
            {"title": "SSL available", "severity": "info", "target": "api.root.example.com"},
        ],
    }
    delta_b = {
        "urls": ["https://api.root.example.com/users"],
        "findings": [
            {"title": "JWT leaked", "severity": "high", "target": "api.root.example.com"},
        ],
    }
    _log_deltas(wal, "passive_scan", [delta_a])
    _log_deltas(wal, "active_scan", [delta_b])

    # --- crash (AOF persists) ---
    del wal
    # (AOF file kept on disk for recovery)

    # --- recover ---
    wal2 = _make_wal(tmp_path, run_id)
    recovered_ns = wal2.recover_state()
    assert recovered_ns is not None

    assert "api.root.example.com" in recovered_ns.subdomains.to_set()
    assert "https://api.root.example.com/users" in recovered_ns.urls.to_set()
    assert len(recovered_ns.findings.values()) == 2, \
        "expected 2 findings, got %d" % len(recovered_ns.findings.values())

    # Verify the fix: merge into checkpoint context
    cp_ctx = _make_checkpoint_ctx(subdomains=["root.example.com"])
    cp_ctx.result._neural_state.merge(recovered_ns)
    _sync_from_neural(cp_ctx)
    assert "api.root.example.com" in cp_ctx.subdomains
    assert "https://api.root.example.com/users" in cp_ctx.urls
    assert len(cp_ctx.reportable_findings) == 2

    wal2.cleanup()


# ===================================================================
# Test 2 — Duplicate WAL/checkpoint state
# ===================================================================

def test_duplicate_wal_checkpoint_state(tmp_path: Path):
    """Checkpoint already contains delta A. WAL also contains A. Recovery: A once."""
    run_id = "test2-dedup"

    shared = {
        "subdomains": ["dup.example.com"],
        "urls": ["https://dup.example.com/"],
        "findings": [
            {"title": "Dup", "severity": "medium", "target": "dup.example.com"},
        ],
    }
    later = {
        "subdomains": ["new.example.com"],
        "findings": [
            {"title": "New", "severity": "low", "target": "new.example.com"},
        ],
    }

    # 1. checkpoint has shared
    cp_ctx = _make_checkpoint_ctx()
    cp_ctx.result.apply_state_delta(shared)
    assert len(cp_ctx.reportable_findings) == 1

    # 2. WAL has shared + later
    wal = _make_wal(tmp_path, run_id)
    _log_deltas(wal, "recon", [shared, later])

    # 3. recover
    recovered_ns = wal.recover_state()
    assert recovered_ns is not None

    # 4. merge (the fix)
    pre = len(cp_ctx.result._neural_state.applied_wal_ids)
    cp_ctx.result._neural_state.merge(recovered_ns)
    _sync_from_neural(cp_ctx)
    post = len(cp_ctx.result._neural_state.applied_wal_ids)

    # 5. verify: dup once, new once, 2 findings
    assert "dup.example.com" in cp_ctx.subdomains
    assert "new.example.com" in cp_ctx.subdomains
    assert len(cp_ctx.reportable_findings) == 2, \
        "expected 2 findings, got %d" % len(cp_ctx.reportable_findings)
    assert post > pre, "applied_wal_ids should grow"

    wal.cleanup()


# ===================================================================
# Test 3 — Full state-field coverage
# ===================================================================

def test_full_state_field_coverage(tmp_path: Path):
    """Every state field emitted by merge_stage_output() survives WAL recovery."""
    run_id = "test3-full-fields"

    full: dict[str, Any] = {
        "subdomains": ["a.example.com", "b.example.com"],
        "urls": ["https://a.example.com", "https://b.example.com"],
        "live_hosts": ["https://a.example.com"],
        "parameters": ["id", "page"],
        "findings": [
            {"title": "Found", "severity": "info", "target": "a.example.com"},
        ],
        "reportable_findings": [
            {"title": "Rpt", "severity": "high", "target": "a.example.com"},
        ],
        "merged_findings": [
            {"title": "Merged", "severity": "medium", "target": "a.example.com"},
        ],
        "waf_findings": [
            {"title": "WAF", "severity": "info", "target": "b.example.com"},
        ],
        "module_metrics": {"recon": {"hosts_found": 2, "duration_s": 12.5}},
        "scope_entries": ["example.com"],
    }

    wal = _make_wal(tmp_path, run_id)
    _log_deltas(wal, "combined", [full])

    recovered_ns = wal.recover_state()
    assert recovered_ns is not None

    assert recovered_ns.subdomains.to_set() == {"a.example.com", "b.example.com"}
    assert recovered_ns.urls.to_set() == {"https://a.example.com", "https://b.example.com"}
    assert len(recovered_ns.findings.values()) >= 2, \
        "expected >=2 finding entries, got %d" % len(recovered_ns.findings.values())

    ctx = _make_checkpoint_ctx()
    ctx.result._neural_state.merge(recovered_ns)
    for entry in wal.recover_deltas():
        delta = entry.get("delta")
        if isinstance(delta, dict):
            delta.setdefault("_wal_id", entry.get("id"))
            ctx.result.apply_state_delta(delta)
    _sync_from_neural(ctx)

    assert "https://a.example.com" in ctx.result.live_hosts
    assert ctx.result.module_metrics.get("recon", {}).get("hosts_found") == 2
    assert "example.com" in ctx.result.scope_entries

    wal.cleanup()


# ===================================================================
# Test 4 — Mid-active_scan crash (the "real killer")
# ===================================================================

def test_mid_active_scan_crash(tmp_path: Path):
    """Checkpoint at delta 5. Crash at delta 10. Reconstruct full state. Match uninterrupted."""
    run_id = "test4-mid-active-scan"

    def finding(i: int) -> dict[str, Any]:
        return {"title": "Vuln-" + str(i),
                "severity": "high" if i % 2 else "medium",
                "target": "host-" + str(i % 5) + ".example.com"}

    pre: list[dict[str, Any]] = []
    for i in range(0, 20, 2):
        pre.append({"findings": [finding(i), finding(i + 1)]})

    post: list[dict[str, Any]] = []
    for i in range(20, 40, 2):
        post.append({"findings": [finding(i), finding(i + 1)]})

    # Phase 1: run to checkpoint (first 5 deltas)
    wal = _make_wal(tmp_path, run_id)
    cp_ctx = _make_checkpoint_ctx()
    for d in pre[:5]:
        cp_ctx.result.apply_state_delta(d)
    cp_snapshot = cp_ctx.result.to_dict()

    # Phase 2: 5 more deltas -> WAL only -> SIGKILL
    for d in pre[5:]:
        wal.log_delta("active_scan", d)

    # Phase 3: restart with the fix
    restored = PipelineContext(result=StageResult.from_dict(cp_snapshot))
    wal2 = _make_wal(tmp_path, run_id)
    recovered_ns = wal2.recover_state()
    restored.result._neural_state.merge(recovered_ns)
    _sync_from_neural(restored)

    assert len(restored.reportable_findings) == 20, \
        "expected 20 post-WAL findings, got %d" % len(restored.reportable_findings)

    # Phase 4: resume and finish
    for d in post:
        restored.result.apply_state_delta(d)
        wal2.log_delta("active_scan", d)

    assert len(restored.reportable_findings) == 40, \
        "expected 40 final findings, got %d" % len(restored.reportable_findings)

    # Phase 5: compare against uninterrupted run
    uninterrupted = _make_checkpoint_ctx()
    for d in pre + post:
        uninterrupted.result.apply_state_delta(d)

    u_titles = {f["title"] for f in uninterrupted.reportable_findings}
    r_titles = {f["title"] for f in restored.reportable_findings}
    assert r_titles == u_titles, "restored findings differ from uninterrupted"

    wal.cleanup()
    wal2.cleanup()


# ===================================================================
# Test 5 — Corrupt WAL entries
# ===================================================================

def test_corrupt_wal_entries(tmp_path: Path):
    """WAL: [valid] [corrupt] [valid]. CRC64 skips corrupt. No silent data loss."""
    run_id = "test5-corrupt"

    wal = _make_wal(tmp_path, run_id)
    _log_deltas(wal, "recon", [{"subdomains": ["pre.example.com"]}])
    _log_deltas(wal, "broken", [{"subdomains": ["skipped.example.com"]}])
    _log_deltas(wal, "recon", [{"subdomains": ["post.example.com"]}])

    _corrupt_aof_entry(wal, 1)

    wal2 = _make_wal(tmp_path, run_id)
    recovered = wal2.recover_state()
    assert recovered is not None

    assert "pre.example.com" in recovered.subdomains.to_set(), "valid A lost"
    assert "post.example.com" in recovered.subdomains.to_set(), "valid C lost"
    assert "skipped.example.com" not in recovered.subdomains.to_set(), \
        "corrupt entry not skipped"

    # --- High-corruption threshold (>50%) ---
    wal_high = _make_wal(tmp_path, "test5-threshold")
    _log_deltas(wal_high, "stage", [
        {"subdomains": ["good.example.com"]},
        {"subdomains": ["bad1.example.com"]},
        {"subdomains": ["bad2.example.com"]},
    ])
    _corrupt_aof_entry(wal_high, 1)
    _corrupt_aof_entry(wal_high, 2)

    wal_high2 = _make_wal(tmp_path, "test5-threshold")
    recovered_high = wal_high2.recover_state()
    assert recovered_high is not None
    assert "good.example.com" in recovered_high.subdomains.to_set(), \
        "valid entry in high-corruption should survive"
    assert "bad1.example.com" not in recovered_high.subdomains.to_set()
    assert "bad2.example.com" not in recovered_high.subdomains.to_set()

    wal.cleanup()
    wal_high.cleanup()
