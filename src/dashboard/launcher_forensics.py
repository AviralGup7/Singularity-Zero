from __future__ import annotations

import argparse
import json
import sqlite3
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from src.core.utils.stderr_classification import classify_stderr_lines
from src.dashboard.registry import PROGRESS_PREFIX, STAGE_LABELS
from src.dashboard.services.query_service_log_parsing import (
    last_entered_stage_from_file,
    last_progress_payload_from_file,
    read_all_lines,
)
from src.dashboard.services.query_service_recovery import recover_job_from_launcher

SQUARE_WARNING_ESCALATION_JOB_IDS = ("a0b71b8e", "3ed7c0ee", "5e20a0db")
SQUARE_LIVE_HOST_REGRESSION_JOB_IDS = ("70771cc8",)
SQUARE_REFERENCE_JOB_ID = "59d5e72d"
SQUARE_BASELINE_JOB_IDS = (
    *SQUARE_WARNING_ESCALATION_JOB_IDS,
    *SQUARE_LIVE_HOST_REGRESSION_JOB_IDS,
    SQUARE_REFERENCE_JOB_ID,
)

_TRUTH_COMPARISON_FIELDS = (
    "status",
    "stage",
    "failed_stage",
    "failure_reason_code",
    "warning_count",
    "fatal_signal_count",
    "target_href",
)
_RECONCILED_FIELDS = (
    "status",
    "stage",
    "stage_label",
    "status_message",
    "progress_percent",
    "returncode",
    "error",
    "failed_stage",
    "failure_reason_code",
    "failure_step",
    "failure_reason",
    "warnings",
    "stderr_warning_lines",
    "stderr_fatal_lines",
    "timeout_events",
    "degraded_providers",
    "configured_timeout_seconds",
    "effective_timeout_seconds",
    "warning_count",
    "fatal_signal_count",
    "latest_logs",
    "target_href",
    "started_at",
    "updated_at",
    "finished_at",
)


def default_output_root(workspace_root: Path | None = None) -> Path:
    base = workspace_root or Path.cwd()
    return (base / "src" / "dashboard" / "output").resolve()


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return int(value or 0)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _coerce_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value or 0.0)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _dedupe_lines(lines: Iterable[object], *, limit: int = 80) -> list[str]:
    deduped: list[str] = []
    for raw_line in lines:
        line = str(raw_line or "").strip()
        if not line or line in deduped:
            continue
        deduped.append(line)
    return deduped[-limit:]


def _relative_to(base: Path, candidate: Path) -> str:
    try:
        return candidate.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return ""


def _normalize_path_string(path_value: str) -> str:
    """Normalize Windows-style paths to posix-style if they look like absolute Windows paths."""
    text = str(path_value or "").strip()
    if not text:
        return ""
    # Heuristic for Windows absolute paths (e.g. C:\... or D:\...)
    if len(text) > 3 and text[1:3] == ":\\" and text[0].isalpha():
        # If we find 'output' in the path, try to make it relative to output
        text_lower = text.lower()
        if "src\\dashboard\\output\\" in text_lower:
            return text_lower.split("src\\dashboard\\output\\", 1)[1].replace("\\", "/")
        if "output\\" in text_lower:
            return text_lower.split("output\\", 1)[1].replace("\\", "/")
        # Otherwise just convert backslashes
        return text.replace("\\", "/")
    return text


def _output_href(output_root: Path, path_value: str) -> str:
    text = _normalize_path_string(path_value)
    if not text:
        return ""
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = (output_root / candidate).resolve()
    else:
        candidate = candidate.resolve()
    relative = _relative_to(output_root, candidate)
    if not relative:
        return ""
    return f"/{relative}"


def _read_json_mapping(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _read_scope_entries(path: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def _load_persisted_job(output_root: Path, job_id: str) -> dict[str, Any] | None:
    db_path = output_root / "jobs.db"
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT data FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None

    if not row:
        return None
    try:
        parsed = json.loads(str(row[0]))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _summarize_job(job: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(job, Mapping):
        return None
    degraded_providers = job.get("degraded_providers", [])
    warnings = job.get("warnings", [])
    normalized_warnings = _dedupe_lines(warnings, limit=10)
    return {
        "status": str(job.get("status", "") or "").strip(),
        "stage": str(job.get("stage", "") or "").strip(),
        "failed_stage": str(job.get("failed_stage", "") or "").strip(),
        "failure_reason_code": str(job.get("failure_reason_code", "") or "").strip(),
        "failure_reason": str(job.get("failure_reason", "") or "").strip(),
        "warning_count": _coerce_int(job.get("warning_count")),
        "fatal_signal_count": _coerce_int(job.get("fatal_signal_count")),
        "degraded_providers": [
            str(item).strip() for item in degraded_providers if str(item).strip()
        ],
        "progress_percent": _coerce_int(job.get("progress_percent")),
        "target_href": str(job.get("target_href", "") or "").strip(),
        "warnings": normalized_warnings,
        "warning_set": sorted(set(normalized_warnings)),
    }


def _extract_output_paths(stdout_lines: list[str], output_root: Path) -> dict[str, Any]:
    artifacts_path = ""
    report_path = ""
    dashboard_index_path = ""
    for line in stdout_lines:
        if line.startswith("Artifacts written to:"):
            artifacts_path = line.split(":", 1)[1].strip()
        elif line.startswith("Run report:"):
            report_path = line.split(":", 1)[1].strip()
        elif line.startswith("Dashboard index:"):
            dashboard_index_path = line.split(":", 1)[1].strip()

    def _record(path_value: str, *, is_dir: bool = False, default_name: str = "") -> dict[str, Any]:
        text = _normalize_path_string(path_value)
        candidate = Path(text) if text else None
        if candidate is not None and not candidate.is_absolute():
            candidate = (output_root / candidate).resolve()
        elif candidate is not None:
            candidate = candidate.resolve()
        exists = bool(candidate and candidate.exists())
        relative = _relative_to(output_root, candidate) if candidate else ""
        href = f"/{relative}" if relative else ""
        payload: dict[str, Any] = {
            "raw": text,
            "relative": relative,
            "href": href,
            "exists": exists,
        }
        if candidate is not None:
            payload["absolute"] = str(candidate)
            if is_dir:
                analyzer = candidate / default_name
                payload["state_transition_analyzer"] = {
                    "relative": _relative_to(output_root, analyzer),
                    "href": f"/{_relative_to(output_root, analyzer)}"
                    if _relative_to(output_root, analyzer)
                    else "",
                    "exists": analyzer.exists(),
                    "absolute": str(analyzer),
                }
        return payload

    return {
        "artifacts_dir": _record(
            artifacts_path,
            is_dir=True,
            default_name="state_transition_analyzer.json",
        ),
        "report_html": _record(report_path),
        "dashboard_index": _record(dashboard_index_path),
    }


def _completion_markers(stdout_lines: list[str]) -> list[str]:
    markers: list[str] = []
    for line in stdout_lines:
        text = str(line or "").strip()
        if not text:
            continue
        if (
            text == "Run complete"
            or text.startswith("Artifacts written to:")
            or text.startswith("Run report:")
            or text.startswith("Dashboard index:")
            or text.startswith("Finalizing run")
            or text.startswith("Deduplicated findings:")
        ) and text not in markers:
            markers.append(text)
    return markers


def compare_truth_sources(
    recovered_job: Mapping[str, Any],
    persisted_job: Mapping[str, Any] | None,
) -> dict[str, Any]:
    recovered_summary = _summarize_job(recovered_job) or {}
    persisted_summary = _summarize_job(persisted_job) or {}
    if not persisted_summary:
        return {
            "persisted_job_present": False,
            "mismatched_fields": [],
            "status_aligned": None,
            "stage_aligned": None,
            "failure_reason_code_aligned": None,
            "warning_count_aligned": None,
            "fatal_signal_count_aligned": None,
            "warning_set_aligned": None,
        }

    mismatched_fields = [
        field
        for field in _TRUTH_COMPARISON_FIELDS
        if recovered_summary.get(field) != persisted_summary.get(field)
    ]
    warning_set_aligned = set(recovered_summary.get("warning_set", []) or []) == set(
        persisted_summary.get("warning_set", []) or []
    )
    if not warning_set_aligned and "warnings" not in mismatched_fields:
        mismatched_fields.append("warnings")
    return {
        "persisted_job_present": True,
        "mismatched_fields": mismatched_fields,
        "status_aligned": recovered_summary.get("status") == persisted_summary.get("status"),
        "stage_aligned": recovered_summary.get("stage") == persisted_summary.get("stage"),
        "failure_reason_code_aligned": recovered_summary.get("failure_reason_code")
        == persisted_summary.get("failure_reason_code"),
        "warning_count_aligned": recovered_summary.get("warning_count")
        == persisted_summary.get("warning_count"),
        "fatal_signal_count_aligned": recovered_summary.get("fatal_signal_count")
        == persisted_summary.get("fatal_signal_count"),
        "warning_set_aligned": warning_set_aligned,
    }


def build_launcher_replay_manifest(
    output_root: Path,
    job_id: str,
    *,
    persisted_job: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    launcher_dir = output_root / "_launcher" / job_id
    if not launcher_dir.exists():
        raise FileNotFoundError(f"Launcher artifacts not found for job {job_id}")

    config_path = launcher_dir / "config.json"
    scope_path = launcher_dir / "scope.txt"
    stdout_path = launcher_dir / "stdout.txt"
    stderr_path = launcher_dir / "stderr.txt"

    config = _read_json_mapping(config_path)
    scope_entries = _read_scope_entries(scope_path)
    stdout_lines = read_all_lines(stdout_path)
    stderr_lines = read_all_lines(stderr_path)
    stderr_classification = classify_stderr_lines(stderr_lines)
    last_progress = last_progress_payload_from_file(stdout_path, progress_prefix=PROGRESS_PREFIX)
    last_stage = last_entered_stage_from_file(
        stdout_path,
        progress_prefix=PROGRESS_PREFIX,
        stage_labels=STAGE_LABELS,
    )
    recovered_job = recover_job_from_launcher(
        output_root=output_root,
        job_id=job_id,
        stage_labels=STAGE_LABELS,
        progress_prefix=PROGRESS_PREFIX,
        path_to_output_href=lambda value: _output_href(output_root, value),
    )
    if recovered_job is None:
        raise FileNotFoundError(f"Unable to recover launcher job {job_id}")

    persisted = (
        dict(persisted_job)
        if isinstance(persisted_job, Mapping)
        else _load_persisted_job(output_root, job_id)
    )
    output_paths = _extract_output_paths(stdout_lines, output_root)
    completion_markers = _completion_markers(stdout_lines)

    return {
        "schema_version": 1,
        "job_id": job_id,
        "generated_at_epoch": time.time(),
        "launcher_artifacts": {
            "launcher_dir": str(launcher_dir),
            "relative_launcher_dir": _relative_to(output_root, launcher_dir),
            "config_exists": config_path.exists(),
            "scope_exists": scope_path.exists(),
            "stdout_exists": stdout_path.exists(),
            "stderr_exists": stderr_path.exists(),
        },
        "config_summary": {
            "base_url": str(config.get("base_url", "") or "").strip(),
            "target_name": str(config.get("target_name", "") or "").strip(),
            "mode": str(config.get("mode", "") or "").strip(),
            "enabled_modules": list(config.get("enabled_modules", []) or []),
            "scope_entries": scope_entries,
        },
        "runtime_signal_truth": {
            "stdout_line_count": len(stdout_lines),
            "stderr_line_count": len(stderr_lines),
            "last_progress_stage": str(last_progress.get("stage", "") or "").strip(),
            "last_entered_stage": last_stage,
            "last_progress_status": str(
                last_progress.get("status") or last_progress.get("stage_status") or ""
            ).strip(),
            "last_progress_percent": _coerce_int(last_progress.get("percent")),
            "completion_markers": completion_markers,
            "has_completion_markers": bool(completion_markers),
            "best_warning_line": stderr_classification.best_warning_line,
            "best_fatal_line": stderr_classification.best_fatal_line,
            "warning_count": stderr_classification.warning_count,
            "fatal_signal_count": stderr_classification.fatal_signal_count,
            "degraded_providers": list(recovered_job.get("degraded_providers", []) or []),
        },
        "output_paths": output_paths,
        "artifact_recovery_truth": _summarize_job(recovered_job),
        "persisted_job_truth": _summarize_job(persisted),
        "truth_parity": compare_truth_sources(recovered_job, persisted),
    }


def compare_launcher_replay_manifests(
    reference_manifest: Mapping[str, Any],
    candidate_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    reference_truth = dict(reference_manifest.get("artifact_recovery_truth", {}) or {})
    candidate_truth = dict(candidate_manifest.get("artifact_recovery_truth", {}) or {})
    reference_warning_set = set(reference_truth.get("warning_set", []) or [])
    candidate_warning_set = set(candidate_truth.get("warning_set", []) or [])
    reference_providers = set(reference_truth.get("degraded_providers", []) or [])
    candidate_providers = set(candidate_truth.get("degraded_providers", []) or [])
    reference_markers = set(
        reference_manifest.get("runtime_signal_truth", {}).get("completion_markers", []) or []
    )
    candidate_markers = set(
        candidate_manifest.get("runtime_signal_truth", {}).get("completion_markers", []) or []
    )
    reference_analyzer = bool(
        reference_manifest.get("output_paths", {})
        .get("artifacts_dir", {})
        .get("state_transition_analyzer", {})
        .get("exists")
    )
    candidate_analyzer = bool(
        candidate_manifest.get("output_paths", {})
        .get("artifacts_dir", {})
        .get("state_transition_analyzer", {})
        .get("exists")
    )
    changed_fields = [
        field
        for field in _TRUTH_COMPARISON_FIELDS
        if reference_truth.get(field) != candidate_truth.get(field)
    ]
    return {
        "reference_job_id": str(reference_manifest.get("job_id", "") or "").strip(),
        "candidate_job_id": str(candidate_manifest.get("job_id", "") or "").strip(),
        "changed_fields": changed_fields,
        "status_changed": reference_truth.get("status") != candidate_truth.get("status"),
        "stage_changed": reference_truth.get("stage") != candidate_truth.get("stage"),
        "failure_reason_code_changed": reference_truth.get("failure_reason_code")
        != candidate_truth.get("failure_reason_code"),
        "warning_count_delta": _coerce_int(candidate_truth.get("warning_count"))
        - _coerce_int(reference_truth.get("warning_count")),
        "fatal_signal_count_delta": _coerce_int(candidate_truth.get("fatal_signal_count"))
        - _coerce_int(reference_truth.get("fatal_signal_count")),
        "warning_set_changed": reference_warning_set != candidate_warning_set,
        "warning_lines_added": sorted(candidate_warning_set - reference_warning_set),
        "warning_lines_removed": sorted(reference_warning_set - candidate_warning_set),
        "degraded_providers_added": sorted(candidate_providers - reference_providers),
        "degraded_providers_removed": sorted(reference_providers - candidate_providers),
        "completion_markers_added": sorted(candidate_markers - reference_markers),
        "completion_markers_removed": sorted(reference_markers - candidate_markers),
        "state_transition_analyzer_gained": candidate_analyzer and not reference_analyzer,
        "state_transition_analyzer_lost": reference_analyzer and not candidate_analyzer,
    }


def build_launcher_forensic_catalog(
    output_root: Path,
    job_ids: Iterable[str],
) -> dict[str, Any]:
    manifests = [build_launcher_replay_manifest(output_root, job_id) for job_id in job_ids]
    status_counts: dict[str, int] = {}
    failure_reason_counts: dict[str, int] = {}
    parity_drift_job_ids: list[str] = []
    persisted_job_count = 0
    for manifest in manifests:
        truth = manifest.get("artifact_recovery_truth", {}) or {}
        status = str(truth.get("status", "") or "").strip() or "unknown"
        failure_reason_code = str(truth.get("failure_reason_code", "") or "").strip() or "<none>"
        status_counts[status] = status_counts.get(status, 0) + 1
        failure_reason_counts[failure_reason_code] = (
            failure_reason_counts.get(failure_reason_code, 0) + 1
        )
        parity = manifest.get("truth_parity", {}) or {}
        if parity.get("persisted_job_present"):
            persisted_job_count += 1
        if parity.get("mismatched_fields"):
            parity_drift_job_ids.append(str(manifest.get("job_id", "") or "").strip())

    return {
        "schema_version": 1,
        "generated_at_epoch": time.time(),
        "output_root": str(Path(output_root).resolve()),
        "job_ids": [str(job_id) for job_id in job_ids],
        "summary": {
            "job_count": len(manifests),
            "status_counts": status_counts,
            "failure_reason_code_counts": failure_reason_counts,
            "persisted_job_count": persisted_job_count,
            "parity_drift_job_ids": parity_drift_job_ids,
        },
        "jobs": manifests,
    }


def build_square_launcher_baseline(output_root: Path) -> dict[str, Any]:
    catalog = build_launcher_forensic_catalog(output_root, SQUARE_BASELINE_JOB_IDS)
    manifests_by_job_id = {
        str(item.get("job_id", "") or "").strip(): item
        for item in catalog.get("jobs", [])
        if isinstance(item, Mapping)
    }
    reference_manifest = manifests_by_job_id[SQUARE_REFERENCE_JOB_ID]
    comparisons = [
        compare_launcher_replay_manifests(reference_manifest, manifests_by_job_id[job_id])
        for job_id in SQUARE_BASELINE_JOB_IDS
        if job_id != SQUARE_REFERENCE_JOB_ID
    ]
    return {
        **catalog,
        "label": "square.com launcher forensic baseline",
        "reference_job_id": SQUARE_REFERENCE_JOB_ID,
        "warning_escalation_job_ids": list(SQUARE_WARNING_ESCALATION_JOB_IDS),
        "live_host_regression_job_ids": list(SQUARE_LIVE_HOST_REGRESSION_JOB_IDS),
        "comparisons_to_reference": comparisons,
    }


def write_launcher_manifest(destination: Path, manifest: Mapping[str, Any]) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(dict(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def capture_launcher_replay_manifest(
    output_root: Path,
    job_id: str,
    *,
    persisted_job: Mapping[str, Any] | None = None,
    destination: Path | None = None,
) -> Path:
    manifest = build_launcher_replay_manifest(
        output_root,
        job_id,
        persisted_job=persisted_job,
    )
    manifest_path = destination or (
        Path(output_root).resolve() / "_launcher" / job_id / "forensic_manifest.json"
    )
    return write_launcher_manifest(manifest_path, manifest)


def persisted_job_has_truth_drift(
    persisted_job: Mapping[str, Any],
    recovered_job: Mapping[str, Any],
) -> bool:
    return bool(compare_truth_sources(recovered_job, persisted_job).get("mismatched_fields"))


def merge_persisted_job_with_recovered_truth(
    persisted_job: Mapping[str, Any],
    recovered_job: Mapping[str, Any],
) -> dict[str, Any]:
    merged: dict[str, Any] = dict(persisted_job)
    for field in _RECONCILED_FIELDS:
        if field in recovered_job:
            merged[field] = recovered_job[field]

    merged["process"] = None
    merged["stop_requested"] = False
    merged["warnings"] = _dedupe_lines(
        [
            *persisted_job.get("warnings", []),  # type: ignore[arg-type]
            *recovered_job.get("warnings", []),  # type: ignore[arg-type]
        ],
        limit=10,
    )
    merged["latest_logs"] = _dedupe_lines(
        [
            *persisted_job.get("latest_logs", []),  # type: ignore[arg-type]
            *recovered_job.get("latest_logs", []),  # type: ignore[arg-type]
        ]
    )

    persisted_telemetry = persisted_job.get("progress_telemetry")
    recovered_telemetry = recovered_job.get("progress_telemetry")
    merged_telemetry: dict[str, Any] = {}
    if isinstance(persisted_telemetry, Mapping):
        merged_telemetry.update(dict(persisted_telemetry))
    if isinstance(recovered_telemetry, Mapping):
        merged_telemetry.update(dict(recovered_telemetry))
    merged_event_triggers = _dedupe_lines(
        [
            *(
                persisted_telemetry.get("event_triggers", [])
                if isinstance(persisted_telemetry, Mapping)
                else []
            ),  # type: ignore[arg-type]
            *(
                recovered_telemetry.get("event_triggers", [])
                if isinstance(recovered_telemetry, Mapping)
                else []
            ),  # type: ignore[arg-type]
            "artifact_recovery",
            "persisted_job_reconciled",
        ],
        limit=20,
    )
    merged_telemetry["event_triggers"] = merged_event_triggers
    if "active_task_count" not in merged_telemetry:
        merged_telemetry["active_task_count"] = 0
    merged["progress_telemetry"] = merged_telemetry
    return merged


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture launcher forensic manifests.")
    parser.add_argument(
        "--output-root",
        default=str(default_output_root()),
        help="Dashboard output root containing _launcher artifacts and jobs.db",
    )
    parser.add_argument(
        "--job-id",
        dest="job_ids",
        action="append",
        default=[],
        help="Launcher job id to capture. Can be repeated.",
    )
    parser.add_argument(
        "--square-baseline",
        action="store_true",
        help="Capture the canonical square.com baseline artifact set.",
    )
    parser.add_argument(
        "--write",
        type=Path,
        default=None,
        help="Optional destination JSON path for the captured manifest.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    output_root = Path(args.output_root).resolve()
    if args.square_baseline:
        manifest = build_square_launcher_baseline(output_root)
    elif args.job_ids:
        manifest = build_launcher_forensic_catalog(output_root, args.job_ids)
    else:
        raise SystemExit("Specify --square-baseline or at least one --job-id.")

    if args.write is not None:
        write_launcher_manifest(args.write, manifest)
    else:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
