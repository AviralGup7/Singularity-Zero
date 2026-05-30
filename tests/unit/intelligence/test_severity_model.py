from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from src.analysis.intelligence.decision_engine import annotate_finding_decisions
from src.intelligence.severity_model import CalibratedSeverityModel
from src.learning.telemetry_store import TelemetryStore
from src.reporting.export_findings import flatten_finding_for_export


def _insert_feedback(
    store: TelemetryStore,
    *,
    event_id: str,
    category: str,
    severity: str,
    plugin: str,
    validated: bool,
    false_positive: bool,
    confidence: float = 0.82,
) -> None:
    store.insert_feedback_event(
        {
            "event_id": event_id,
            "run_id": "run-1",
            "timestamp": datetime.now(UTC).isoformat(),
            "target_host": "api.example.test",
            "target_endpoint": "https://api.example.test/v1/users?id=1",
            "finding_category": category,
            "finding_severity": severity,
            "finding_confidence": confidence,
            "finding_decision": "HIGH" if validated else "DROP",
            "plugin_name": plugin,
            "parameter_name": "id",
            "parameter_type": "identifier",
            "was_validated": validated,
            "was_false_positive": false_positive,
            "validation_method": "unit",
            "response_delta_score": 4,
            "endpoint_type": "API",
            "tech_stack": "python",
            "scan_mode": "full",
            "feedback_weight": 1.0,
        }
    )


def _store(db_path: Path) -> TelemetryStore:
    store = TelemetryStore(db_path)
    store.initialize()
    store.record_scan_run(
        {
            "run_id": "run-1",
            "target_name": "api.example.test",
            "mode": "full",
            "start_time": datetime.now(UTC).isoformat(),
            "end_time": None,
            "status": "completed",
            "total_urls": 1,
            "total_endpoints": 1,
            "total_findings": 1,
            "validated_findings": 1,
            "false_positives": 0,
            "scan_duration_sec": 1.0,
            "config_hash": "unit",
            "feedback_applied": 1,
        }
    )
    return store


def test_calibrated_model_uses_historical_true_and_false_positive_rates(tmp_path: Path) -> None:
    db_path = tmp_path / "telemetry.db"
    store = _store(db_path)
    for idx in range(12):
        _insert_feedback(
            store,
            event_id=f"tp-{idx}",
            category="idor",
            severity="high",
            plugin="idor_candidate_finder",
            validated=True,
            false_positive=False,
        )
    for idx in range(12):
        _insert_feedback(
            store,
            event_id=f"fp-{idx}",
            category="cdn_noise",
            severity="high",
            plugin="cdn_probe",
            validated=False,
            false_positive=True,
            confidence=0.82,
        )

    model = CalibratedSeverityModel(db_path)
    tp_prediction = model.predict(
        {
            "category": "idor",
            "severity": "high",
            "confidence": 0.82,
            "plugin_name": "idor_candidate_finder",
            "endpoint_type": "API",
            "url": "https://api.example.test/v1/users?id=2",
        }
    )
    fp_prediction = model.predict(
        {
            "category": "cdn_noise",
            "severity": "high",
            "confidence": 0.82,
            "plugin_name": "cdn_probe",
            "endpoint_type": "API",
            "url": "https://api.example.test/v1/users?id=2",
        }
    )

    assert tp_prediction.training_samples >= 24
    assert tp_prediction.true_positive_probability > fp_prediction.true_positive_probability
    assert tp_prediction.score > fp_prediction.score


def test_decision_and_export_emit_model_severity_fields(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "telemetry.db"
    store = _store(db_path)
    _insert_feedback(
        store,
        event_id="tp",
        category="ssrf",
        severity="critical",
        plugin="ssrf_candidate_finder",
        validated=True,
        false_positive=False,
    )
    monkeypatch.setenv("VULN_SEVERITY_DB_PATH", str(db_path))

    finding = {
        "category": "ssrf",
        "severity": "medium",
        "confidence": 0.86,
        "plugin_name": "ssrf_candidate_finder",
        "title": "SSRF candidate",
        "url": "https://api.example.test/fetch?url=http://169.254.169.254",
        "endpoint_type": "API",
    }
    annotated = annotate_finding_decisions([finding])
    exported = flatten_finding_for_export(annotated[0])

    assert annotated[0]["severity_score"] == annotated[0]["score"]
    assert "true_positive_probability" in annotated[0]
    assert "false_positive_probability" in annotated[0]
    assert exported["severity_model"] == "severity-logreg-v1"
    assert exported["severity_score"] != ""
