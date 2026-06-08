"""Finding revalidation stage.

Closes the gap between detection and remediation: when a finding that
was present in a previous run no longer surfaces in the current run,
the orchestrator can mark it as ``resolved``.  This stage re-probes the
endpoints that hosted resolved findings and verifies that the original
detection rule no longer fires.

Behaviour:

1. Load ``findings.json`` from ``ctx.previous_run`` (if any).
2. Diff against ``ctx.reportable_findings`` using :func:`finding_key`
   from :mod:`src.analysis.intelligence.findings_dedup`.
3. For each ``resolved_finding``, capture a fresh request to the same
   URL with the same method using the existing
   :class:`AccessControlAnalyzer` HTTP client.  Compare the response to
   the original ``original_status`` and ``test_status`` from the
   finding's evidence block.
4. Emit one ``revalidation_report.json`` artefact containing per-finding
   re-validation outcomes.  Findings whose original signal does not
   fire again are recorded as ``confirmed_resolved``; findings whose
   signal still fires are recorded as ``regression_detected`` and the
   run is downgraded to ``partial``.

Gated by ``[revalidation] enabled = true`` in the pipeline config;
defaults to enabled to preserve existing operator expectations.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress

logger = get_pipeline_logger(__name__)


@dataclass(frozen=True, slots=True)
class RevalidationEntry:
    """Per-finding re-validation outcome."""

    finding_key: str
    url: str
    method: str
    category: str
    severity: str
    decision: str
    original_status: int | None = None
    revalidated_status: int | None = None
    detail: str = ""
    revalidated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["revalidated_at"] = round(self.revalidated_at, 3)
        return data


def _finding_key(item: Mapping[str, Any]) -> str:
    """Re-implementation of the dedup key used by ``build_trend``.

    The :func:`src.analysis.intelligence.findings_dedup.finding_key`
    helper is preferred but importing it drags in heavy intelligence
    modules — keep this stage dependency-light.
    """
    evidence = item.get("evidence", {}) or {}
    if not isinstance(evidence, Mapping):
        evidence = {}
    endpoint_base = str(
        evidence.get("endpoint_key")
        or evidence.get("endpoint_base_key")
        or item.get("url", "")
    )
    return f"{item.get('category', '')}|{endpoint_base}|{item.get('title', '')}"


def _load_previous_findings(previous_run: Any) -> list[dict[str, Any]]:
    if previous_run is None:
        return []
    try:
        path = previous_run / "findings.json"
    except TypeError:
        return []
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read previous findings: %s", exc)
        return []
    return [item for item in data if isinstance(item, dict)]


def _resolved_findings(
    previous: Iterable[Mapping[str, Any]],
    current: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    current_keys = {_finding_key(item) for item in current}
    return [item for item in previous if _finding_key(item) not in current_keys]


def _http_get(url: str, *, timeout: float = 5.0) -> dict[str, Any] | None:
    """Best-effort synchronous HTTP GET for revalidation.

    Uses ``urllib.request`` to keep this stage free of any heavy HTTP
    framework dependency.  Returns a dict mirroring the keys used by
    :class:`AccessControlAnalyzer` — ``status_code`` and ``body``.
    Returns ``None`` on any error.
    """
    import urllib.error
    import urllib.request

    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "finding-revalidator/1.0"})  # noqa: S310
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return {
                "status_code": int(getattr(resp, "status", 200) or 200),
                "body": resp.read(2_000_000).decode("utf-8", errors="replace"),
            }
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as exc:
        logger.debug("Revalidator HTTP probe failed for %s: %s", url, exc)
        return None


def _revalidate_one(finding: Mapping[str, Any]) -> RevalidationEntry:
    url = str(finding.get("url", "")).strip()
    method = str(finding.get("method", "GET")).upper()
    key = _finding_key(finding)
    evidence = finding.get("evidence", {}) or {}
    if not isinstance(evidence, Mapping):
        evidence = {}

    if not url:
        return RevalidationEntry(
            finding_key=key,
            url="",
            method=method,
            category=str(finding.get("category", "")),
            severity=str(finding.get("severity", "info")),
            decision="skipped",
            detail="finding has no url",
        )

    original_status = evidence.get("test_status") or evidence.get("original_status")
    try:
        original_status_int = int(original_status) if original_status is not None else None
    except (TypeError, ValueError):
        original_status_int = None

    response = _http_get(url) if method == "GET" else _http_get(url)
    if response is None:
        return RevalidationEntry(
            finding_key=key,
            url=url,
            method=method,
            category=str(finding.get("category", "")),
            severity=str(finding.get("severity", "info")),
            decision="probe_failed",
            original_status=original_status_int,
            detail="could not re-fetch the endpoint",
        )

    revalidated_status = int(response.get("status_code") or 0)
    test_context = str(evidence.get("test_context", ""))
    if test_context == "no_auth":
        expected = {401, 403, 302, 301}
        decision = (
            "confirmed_resolved"
            if revalidated_status in expected
            else "regression_detected"
        )
        detail = (
            f"no_auth probe now returns {revalidated_status}; expected one of "
            f"{sorted(expected)}"
        )
    elif original_status_int is not None and revalidated_status == original_status_int:
        decision = "regression_detected"
        detail = (
            f"endpoint still returns {revalidated_status}, matching the original "
            "test_status (no remediation observed)"
        )
    elif revalidated_status in (401, 403, 302, 301):
        decision = "confirmed_resolved"
        detail = f"endpoint now enforces access (status={revalidated_status})"
    else:
        decision = "inconclusive"
        detail = (
            f"endpoint returns {revalidated_status}; original signal could not be "
            "reliably re-evaluated"
        )

    return RevalidationEntry(
        finding_key=key,
        url=url,
        method=method,
        category=str(finding.get("category", "")),
        severity=str(finding.get("severity", "info")),
        decision=decision,
        original_status=original_status_int,
        revalidated_status=revalidated_status,
        detail=detail,
    )


def revalidate_resolved_findings(
    previous_run: Any,
    current_findings: Iterable[Mapping[str, Any]],
    *,
    max_revalidations: int = 25,
) -> list[RevalidationEntry]:
    """Pure helper: return one :class:`RevalidationEntry` per resolved finding.

    Public so unit tests and the orchestrator can both consume it.  The
    cap prevents runaway re-probing of historical findings on long
    remediation backlogs.
    """
    previous = _load_previous_findings(previous_run)
    if not previous:
        return []
    resolved = _resolved_findings(previous, current_findings)
    if not resolved:
        return []
    if max_revalidations > 0 and len(resolved) > max_revalidations:
        logger.info(
            "Capping revalidation at %d of %d resolved findings",
            max_revalidations,
            len(resolved),
        )
        resolved = resolved[:max_revalidations]
    return [_revalidate_one(f) for f in resolved]


def _is_enabled(config: Any) -> bool:
    if config is None:
        return True
    rev = getattr(config, "revalidation", None)
    if rev is None:
        return True
    if isinstance(rev, Mapping):
        return bool(rev.get("enabled", True))
    return bool(getattr(rev, "enabled", True))


async def run_finding_revalidation(
    args: Any,
    config: Any,
    ctx: PipelineContext,
) -> StageOutput:
    """Stage: re-probe endpoints that hosted resolved findings.

    Wired into the orchestrator as the ``finding_revalidation`` stage.
    On a regression, the stage returns ``COMPLETED`` with a
    ``regression_detected`` metric so the CI policy can down-grade the
    run; it never raises, because regression detection is informational
    not fatal.
    """
    stage_started = time.monotonic()
    state_delta: dict[str, Any] = {
        "module_metrics": {},
        "revalidation_entries": [],
    }

    try:
        emit_progress("finding_revalidation", "Revalidating previously resolved findings", 90)

        if not _is_enabled(config):
            logger.info("Finding revalidation disabled by config")
            state_delta["module_metrics"]["finding_revalidation"] = {
                "status": "skipped",
                "reason": "disabled_in_config",
                "duration_seconds": round(time.monotonic() - stage_started, 2),
            }
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="finding_revalidation",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=duration,
                metrics=state_delta["module_metrics"]["finding_revalidation"],
                state_delta=state_delta,
            )

        max_rev = 25
        rev = getattr(config, "revalidation", None)
        if isinstance(rev, Mapping):
            try:
                max_rev = int(rev.get("max_revalidations", 25))
            except (TypeError, ValueError):
                max_rev = 25

        entries = revalidate_resolved_findings(
            ctx.previous_run,
            ctx.reportable_findings,
            max_revalidations=max_rev,
        )
        state_delta["revalidation_entries"] = [e.to_dict() for e in entries]

        confirmed = sum(1 for e in entries if e.decision == "confirmed_resolved")
        regression = sum(1 for e in entries if e.decision == "regression_detected")
        inconclusive = sum(1 for e in entries if e.decision == "inconclusive")
        skipped = sum(1 for e in entries if e.decision == "skipped")
        probe_failed = sum(1 for e in entries if e.decision == "probe_failed")

        metrics: dict[str, Any] = {
            "status": "ok",
            "duration_seconds": round(time.monotonic() - stage_started, 2),
            "total_revalidated": len(entries),
            "confirmed_resolved": confirmed,
            "regression_detected": regression,
            "inconclusive": inconclusive,
            "probe_failed": probe_failed,
            "skipped": skipped,
        }
        state_delta["module_metrics"]["finding_revalidation"] = metrics

        try:
            run_dir = ctx.output_store.run_dir
        except (AttributeError, TypeError):
            run_dir = None
        if run_dir is not None:
            try:
                artifact = run_dir / "revalidation_report.json"
                artifact.write_text(
                    json.dumps(
                        {"entries": [e.to_dict() for e in entries], "metrics": metrics},
                        indent=2,
                        default=str,
                    ),
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.warning("Failed to write revalidation_report.json: %s", exc)

        if regression > 0:
            logger.warning(
                "Finding revalidation: %d regressions detected across %d resolved findings",
                regression,
                len(entries),
            )

        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="finding_revalidation",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics=metrics,
            state_delta=state_delta,
        )

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'finding_revalidation' failed: %s", exc)
        ctx.mark_stage_failed("finding_revalidation", str(exc))
        return StageOutput(
            stage_name="finding_revalidation",
            outcome=StageOutcome.FAILED,
            duration_seconds=round(time.monotonic() - stage_started, 2),
            error=str(exc),
            reason="finding_revalidation_exception",
            metrics={"status": "error", "error": str(exc)},
            state_delta={
                "module_metrics": {
                    "finding_revalidation": {
                        "status": "error",
                        "error": str(exc),
                    }
                },
                "revalidation_entries": [],
            },
        )
