"""Fixtures for learning subsystem tests."""

import pytest

from src.learning.telemetry_store import TelemetryStore


@pytest.fixture
def tmp_db_path(tmp_path):
    """Provide a temporary database path."""
    return tmp_path / "test_telemetry.db"


@pytest.fixture
def store(tmp_db_path):
    """Provide an initialized telemetry store."""
    s = TelemetryStore(tmp_db_path)
    s.initialize()
    yield s
    s.close()


@pytest.fixture
def sample_run():
    """Provide a sample scan run dict."""
    return {
        "run_id": "test-run-001",
        "target_name": "example.com",
        "mode": "deep",
        "start_time": "2026-04-01T10:00:00",
        "end_time": "2026-04-01T10:15:00",
        "status": "completed",
        "total_urls": 500,
        "total_endpoints": 120,
        "total_findings": 25,
        "validated_findings": 10,
        "false_positives": 5,
        "scan_duration_sec": 900.0,
        "config_hash": "abc123",
        "feedback_applied": False,
    }


@pytest.fixture
def sample_finding():
    """Provide a sample finding dict."""
    return {
        "finding_id": "finding-001",
        "run_id": "test-run-001",
        "category": "idor",
        "title": "IDOR in user profile endpoint",
        "url": "https://api.example.com/api/v1/users/123",
        "severity": "high",
        "confidence": 0.75,
        "score": 8.0,
        "decision": "MEDIUM",
        "lifecycle_state": "DETECTED",
        "cvss_score": 7.5,
        "plugin_name": "idor_candidate_finder",
        "endpoint_base": "https://api.example.com/api/v1/users",
        "host": "api.example.com",
        "parameter_name": "id",
        "parameter_type": "identifier",
        "evidence": "Response contains user data for ID 123",
        "response_status": 200,
        "response_body_hash": "hash123",
    }


@pytest.fixture
def sample_feedback_event():
    """Provide a sample feedback event dict."""
    return {
        "event_id": "fb-abc123",
        "run_id": "test-run-001",
        "timestamp": "2026-04-01T10:10:00",
        "target_host": "api.example.com",
        "target_endpoint": "https://api.example.com/api/v1/users",
        "finding_category": "idor",
        "finding_severity": "high",
        "finding_confidence": 0.75,
        "finding_decision": "MEDIUM",
        "plugin_name": "idor_candidate_finder",
        "parameter_name": "id",
        "parameter_type": "identifier",
        "was_validated": False,
        "was_false_positive": False,
        "validation_method": None,
        "response_delta_score": 2,
        "endpoint_type": "API",
        "tech_stack": '["nginx", "python"]',
        "scan_mode": "deep",
        "feedback_weight": 1.5,
    }
