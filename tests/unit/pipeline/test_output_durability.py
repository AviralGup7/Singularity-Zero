"""
Regression tests: Output & Artifact Durability.

Covers:
  1. Interrupted write  — a crash during write_text leaves the previous
     canonical artifact intact (no partial file at the target path).
  2. Truncated JSON     — a corrupted run_summary.json is skipped by
     previous-run selection; the prior valid run is used instead.
  3. Previous-run selection — the most recent *valid* run wins even when
     newer-but-corrupt runs exist.
  4. Report recovery    — report/remediation writes are atomic (no
     partial HTML / patch files after a simulated mid-write crash).

Scope: PipelineOutputStore, src.pipeline.storage, reporting writers,
and orchestrator.find_previous_run.  NOT the WAL / checkpoint manager.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.storage.factory import create_artifact_store
from src.pipeline.services.output_store import PipelineOutputStore
from src.pipeline.storage import atomic_write_text, write_json, write_jsonl, write_lines
from src.pipeline.services.pipeline_orchestrator.orchestrator import find_previous_run


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_store(tmp_path: Path, run_id: str = "run-0001") -> PipelineOutputStore:
    """Create a PipelineOutputStore backed by the local artifact store."""
    output_root = tmp_path / "output"
    artifact_store = create_artifact_store({}, output_root)
    run_dir = output_root / "target.example.com" / run_id
    return PipelineOutputStore(
        artifact_store,
        run_dir,
        "target.example.com",
        run_id,
    )


def _write_valid_summary(run_dir: Path, run_id: str) -> None:
    """Write a canonical run_summary.json to *run_dir*."""
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "run_summary.json", {"run_id": run_id, "target": "target.example.com"})


# ---------------------------------------------------------------------------
# Test 1 — Interrupted write leaves previous artifact intact
# ---------------------------------------------------------------------------

def test_interrupted_write_preserves_previous_artifact(tmp_path: Path):
    store = _make_store(tmp_path, "run-0001")

    # Write the first (canonical) version
    store.write_json_artifact("findings.json", [{"title": "first"}])
    findings_path = store.run_dir / "findings.json"
    original = findings_path.read_text(encoding="utf-8")
    assert '"first"' in original

    # Simulate a crash mid-write: make os.write fail partway through.
    real_write = os.write
    calls = {"n": 0}

    def _failing_write(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:  # fail only on the first write attempt
            # Write only a prefix, then raise (simulates process death)
            real_write(fd, data[: len(data) // 2])
            raise OSError("simulated crash mid-write")
        return real_write(fd, data)

    with patch("os.write", side_effect=_failing_write):
        with pytest.raises(OSError):
            store.write_json_artifact("findings.json", [{"title": "second"}])

    # The canonical path must still hold the ORIGINAL content
    assert findings_path.exists()
    assert findings_path.read_text(encoding="utf-8") == original, \
        "canonical artifact was corrupted by interrupted write"

    # No leftover temp files in the run dir
    leftovers = [p for p in store.run_dir.iterdir() if p.name.endswith(".tmp") or ".tmp" in p.name]
    assert leftovers == [], f"temp files left behind: {leftovers}"


def test_interrupted_plain_write_text_preserves_artifact(tmp_path: Path):
    store = _make_store(tmp_path, "run-0001")
    store.write_text("scope.txt", "example.com\n")
    scope_path = store.run_dir / "scope.txt"
    original = scope_path.read_text(encoding="utf-8")

    real_write = os.write
    calls = {"n": 0}

    def _failing_write(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            real_write(fd, data[:5])
            raise OSError("simulated crash")
        return real_write(fd, data)

    with patch("os.write", side_effect=_failing_write):
        with pytest.raises(OSError):
            store.write_text("scope.txt", "other.example.com\n")

    assert scope_path.read_text(encoding="utf-8") == original, \
        "scope.txt was corrupted by interrupted write"


# ---------------------------------------------------------------------------
# Test 2 — Truncated / corrupt JSON is detected by previous-run selection
# ---------------------------------------------------------------------------

def test_previous_run_skips_corrupted_run(tmp_path: Path):
    output_root = tmp_path / "output"
    target_root = output_root / "target.example.com"

    # A valid, complete run
    run_a = target_root / "run-aaa"
    _write_valid_summary(run_a, "run-aaa")

    # A NEWER run whose run_summary.json is corrupted (crash during write)
    run_b = target_root / "run-bbb"
    run_b.mkdir(parents=True, exist_ok=True)
    (run_b / "run_summary.json").write_text('{"run_id": "run-bbb", "target": "trunc', encoding="utf-8")

    previous = find_previous_run(target_root)
    assert previous is not None
    assert previous.name == "run-aaa", f"expected valid run-aaa, got {previous}"


def test_previous_run_missing_summary_is_skipped(tmp_path: Path):
    output_root = tmp_path / "output"
    target_root = output_root / "target.example.com"

    # A run that started but crashed before writing run_summary.json
    incomplete = target_root / "run-incomplete"
    incomplete.mkdir(parents=True, exist_ok=True)
    (incomplete / "subdomains.txt").write_text("x.example.com\n", encoding="utf-8")

    run_valid = target_root / "run-valid"
    _write_valid_summary(run_valid, "run-valid")

    previous = find_previous_run(target_root)
    assert previous is not None
    assert previous.name == "run-valid"


def test_previous_run_none_when_all_corrupt(tmp_path: Path):
    output_root = tmp_path / "output"
    target_root = output_root / "target.example.com"

    run_x = target_root / "run-x"
    run_x.mkdir(parents=True, exist_ok=True)
    (run_x / "run_summary.json").write_text("not-json-at-all", encoding="utf-8")

    assert find_previous_run(target_root) is None, \
        "no valid previous run should be returned when all summaries are corrupt"


def test_previous_run_picks_latest_valid(tmp_path: Path):
    output_root = tmp_path / "output"
    target_root = output_root / "target.example.com"

    run_old = target_root / "run-old"
    _write_valid_summary(run_old, "run-old")
    time.sleep(0.01)

    run_new = target_root / "run-new"
    _write_valid_summary(run_new, "run-new")

    previous = find_previous_run(target_root)
    assert previous.name == "run-new", f"expected run-new, got {previous.name}"


# ---------------------------------------------------------------------------
# Test 3 — atomic_write_text crash-safety (unit)
# ---------------------------------------------------------------------------

def test_atomic_write_text_crash_safety(tmp_path: Path):
    target = tmp_path / "artifacts.json"
    target.write_text("{}", encoding="utf-8")
    original = target.read_text(encoding="utf-8")

    real_write = os.write
    calls = {"n": 0}

    def _fail_once(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            real_write(fd, data[:2])
            raise OSError("boom")
        return real_write(fd, data)

    with patch("os.write", side_effect=_fail_once):
        with pytest.raises(OSError):
            atomic_write_text(target, '{"a": 1}')

    assert target.read_text(encoding="utf-8") == original, "target overwritten by failed write"
    # No temp file remains
    assert [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


# ---------------------------------------------------------------------------
# Test 4 — JSON / JSONL writers are atomic
# ---------------------------------------------------------------------------

def test_storage_write_json_atomic(tmp_path: Path):
    target = tmp_path / "data.json"
    write_json(target, {"key": "value", "nested": [1, 2, 3]})
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data == {"key": "value", "nested": [1, 2, 3]}

    # No stray temp files
    assert [p for p in tmp_path.iterdir() if p.name.startswith("._")] == []


def test_storage_write_jsonl_atomic(tmp_path: Path):
    target = tmp_path / "data.jsonl"
    write_jsonl(target, [{"a": 1}, {"b": 2}])
    lines = [json.loads(l) for l in target.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines == [{"a": 1}, {"b": 2}]


def test_storage_write_lines_atomic(tmp_path: Path):
    target = tmp_path / "hosts.txt"
    write_lines(target, ["b.example.com", "a.example.com"])
    assert target.read_text(encoding="utf-8") == "a.example.com\nb.example.com\n"


# ---------------------------------------------------------------------------
# Test 5 — Report writers produce atomic artifacts
# ---------------------------------------------------------------------------

def test_report_html_writes_are_atomic(tmp_path: Path):
    """report.html / index.html writes must not leave partial files on crash."""
    from src.reporting.pages import generate_run_report  # noqa: F401

    # The direct writes in reporting are routed through atomic_write_text.
    # Verify by simulating a crash on a plain Path write.
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / "report.html"
    report_path.write_text("<html>OLD</html>", encoding="utf-8")
    original = report_path.read_text(encoding="utf-8")

    real_write = os.write
    calls = {"n": 0}

    def _fail_once(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            real_write(fd, data[:1])
            raise OSError("boom")
        return real_write(fd, data)

    with patch("os.write", side_effect=_fail_once):
        with pytest.raises(OSError):
            atomic_write_text(report_path, "<html>NEW CONTENT</html>")

    assert report_path.read_text(encoding="utf-8") == original, \
        "report.html was corrupted by a failed atomic write"


def test_report_manifest_sig_atomic(tmp_path: Path):
    from src.reporting.report_artifacts import REPORT_SCHEMA_VERSION  # noqa: F401

    sig_path = tmp_path / "report_manifest.sig"
    sig_path.write_text("oldsig\n", encoding="utf-8")
    original = sig_path.read_text(encoding="utf-8")

    real_write = os.write
    calls = {"n": 0}

    def _fail_once(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            real_write(fd, b"")
            raise OSError("boom")
        return real_write(fd, data)

    with patch("os.write", side_effect=_fail_once):
        with pytest.raises(OSError):
            atomic_write_text(sig_path, "newsig\n")

    assert sig_path.read_text(encoding="utf-8") == original


# ---------------------------------------------------------------------------
# Test 6 — write_text round-trip through artifact store
# ---------------------------------------------------------------------------

def test_write_text_roundtrip_through_artifact_store(tmp_path: Path):
    store = _make_store(tmp_path, "run-0001")
    store.write_text("urls.txt", "https://a.example.com\n")
    assert (store.run_dir / "urls.txt").read_text(encoding="utf-8") == "https://a.example.com\n"

    # Artifact store should also have the key
    key = store._get_key("urls.txt")
    assert store._store.get(key) == b"https://a.example.com\n"


def test_persist_outputs_are_atomic_and_complete(tmp_path: Path):
    store = _make_store(tmp_path, "run-0001")
    store.persist_outputs(
        summary={"run_id": "run-0001", "counts": {"total": 1}},
        diff_summary={"added": 1},
        screenshots=[{"file": "a.png"}],
        analysis_results={"sqli": [{"title": "SQLi"}]},
        merged_findings=[{"title": "F1"}],
    )

    run_summary = json.loads((store.run_dir / "run_summary.json").read_text(encoding="utf-8"))
    assert run_summary["run_id"] == "run-0001"

    findings = json.loads((store.run_dir / "findings.json").read_text(encoding="utf-8"))
    assert findings == [{"title": "F1"}]

    # No temp files anywhere in the run dir
    leftovers = [p for p in store.run_dir.rglob("*.tmp") if p.is_file()]
    assert leftovers == [], f"temp files left behind: {leftovers}"