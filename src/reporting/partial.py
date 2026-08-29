"""Partial report emission on abort / cancel / crash / OOM."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PartialReportResult:
    directory: Path
    findings_emitted: int = 0
    files: list[str] = field(default_factory=list)


def _collect_findings(
    ctx: Any | None, run_id: str, output_dir: Path | None
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(item: Any) -> None:
        if not isinstance(item, dict):
            return
        token = str(item.get("event_id") or item.get("spill_id") or item.get("id") or id(item))
        if token in seen:
            return
        seen.add(token)
        findings.append(item)

    if ctx is not None:
        result = getattr(ctx, "result", ctx)
        for attr in ("findings", "reportable_findings", "active_scan_findings", "vulnerabilities"):
            value = getattr(result, attr, None)
            if isinstance(value, list):
                for item in value:
                    _add(item)
            elif isinstance(value, (tuple, set, frozenset)):
                for item in value:
                    _add(item)
    try:
        from src.core.findings.spill import FindingSpill

        root = output_dir
        spill = FindingSpill.for_run(run_id, root)
        for item in spill.findings():
            _add(item)
    except Exception:  # noqa: BLE001
        logger.debug("spill collect skipped", exc_info=True)
    return findings


def _dag_state(ctx: Any | None) -> dict[str, Any]:
    if ctx is None:
        return {}
    result = getattr(ctx, "result", ctx)
    stage_status = getattr(result, "stage_status", {}) or {}
    try:
        status_map = dict(stage_status)
    except Exception:
        status_map = {}
    return {
        "stage_status": {str(k): str(v) for k, v in status_map.items()},
        "run_id": str(getattr(ctx, "run_id", "") or ""),
    }


def emit_partial_report(
    run_id: str,
    reason: str,
    *,
    output_dir: Path | str | None = None,
    ctx: Any | None = None,
    include_findings: bool = True,
    include_dag_state: bool = True,
) -> PartialReportResult:
    """Write report_partial.{json,html,sarif} under output/run_id/partial/."""
    root = Path(output_dir) if output_dir else Path("output")
    directory = root / str(run_id or "unknown") / "partial"
    directory.mkdir(parents=True, exist_ok=True)
    findings = _collect_findings(ctx, str(run_id or "unknown"), root) if include_findings else []
    payload: dict[str, Any] = {
        "run_id": str(run_id or "unknown"),
        "reason": reason,
        "partial": True,
        "findings_emitted_at_shutdown": len(findings),
        "findings": findings,
    }
    if include_dag_state:
        payload["dag"] = _dag_state(ctx)

    written: list[str] = []
    json_path = directory / "report_partial.json"
    _atomic_write(json_path, json.dumps(payload, indent=2, default=str))
    written.append(str(json_path))

    html_path = directory / "report_partial.html"
    _atomic_write(
        html_path,
        "<html><body><h1>Partial report</h1>"
        f"<p>run={run_id} reason={reason} findings={len(findings)}</p></body></html>\n",
    )
    written.append(str(html_path))

    try:
        from src.reporting.sarif_exporter import export_findings_to_sarif

        sarif = export_findings_to_sarif(findings)
        sarif_path = directory / "report_partial.sarif"
        _atomic_write(sarif_path, json.dumps(sarif.document, indent=2, default=str))
        written.append(str(sarif_path))
    except Exception as exc:  # noqa: BLE001
        logger.debug("partial SARIF skipped: %s", exc)

    logger.warning(
        "partial report written run_id=%s reason=%s findings=%d dir=%s",
        run_id,
        reason,
        len(findings),
        directory,
    )
    return PartialReportResult(directory=directory, findings_emitted=len(findings), files=written)


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


__all__ = ["PartialReportResult", "emit_partial_report"]
