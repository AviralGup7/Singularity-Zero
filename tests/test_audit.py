import json
import tempfile
from pathlib import Path

import pytest

from src.infrastructure.security.audit import AuditEvent, AuditLogger, AuditSeverity
from src.infrastructure.security.config import SecurityConfig


@pytest.fixture
def temp_audit_log():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.log"
        yield log_path


@pytest.fixture
def audit_logger(temp_audit_log):
    config = SecurityConfig()
    config.audit.log_path = str(temp_audit_log)
    config.audit.tamper_evident = True
    config.audit.hmac_secret = "test-secret"

    logger = AuditLogger(config)
    yield logger
    logger.close()


def test_audit_sqlite_indexing(audit_logger):
    # Log multiple entries
    audit_logger.log(AuditEvent.AUTH_SUCCESS, user_id="user1", details={"ip": "1.1.1.1"})
    audit_logger.log(AuditEvent.AUTH_FAILURE, user_id="user2", severity=AuditSeverity.CRITICAL)
    audit_logger.log(AuditEvent.JOB_CREATE, user_id="user1")

    # Verify SQLite indexing by querying
    entries = audit_logger.get_entries(limit=10)
    assert len(entries) == 3
    # Ordered by ID DESC
    assert entries[0].event == AuditEvent.JOB_CREATE
    assert entries[1].event == AuditEvent.AUTH_FAILURE
    assert entries[2].event == AuditEvent.AUTH_SUCCESS

    # Test filtering by event
    auth_success = audit_logger.get_entries(event=AuditEvent.AUTH_SUCCESS)
    assert len(auth_success) == 1
    assert auth_success[0].user_id == "user1"

    # Test filtering by user_id
    user1_entries = audit_logger.get_entries(user_id="user1")
    assert len(user1_entries) == 2

    # Test filtering by severity
    critical_entries = audit_logger.get_entries(severity=AuditSeverity.CRITICAL)
    assert len(critical_entries) == 1
    assert critical_entries[0].user_id == "user2"


def test_audit_rotation_sync(audit_logger, temp_audit_log):
    # 1. Fill up log to trigger rotation (or just call it manually)
    audit_logger.log(AuditEvent.AUTH_SUCCESS, user_id="pre-rotation")
    entries = audit_logger.get_entries()
    assert len(entries) == 1

    # 2. Trigger rotation
    audit_logger._rotate_log()

    # 3. Verify SQLite is cleared
    assert len(audit_logger.get_entries()) == 0

    # 4. Log post-rotation and verify
    audit_logger.log(AuditEvent.AUTH_SUCCESS, user_id="post-rotation")
    entries = audit_logger.get_entries()
    assert len(entries) == 1
    assert entries[0].user_id == "post-rotation"


def test_audit_integrity_verification(audit_logger):
    audit_logger.log(AuditEvent.AUTH_SUCCESS, user_id="user1")
    audit_logger.log(AuditEvent.AUTH_SUCCESS, user_id="user2")

    is_valid, compromised = audit_logger.verify_integrity()
    assert is_valid
    assert len(compromised) == 0

    # Tamper with the file
    log_path = Path(audit_logger.config.audit.log_path)
    with open(log_path) as f:
        lines = f.readlines()

    # Change user_id in the second entry
    data = json.loads(lines[1])
    data["user_id"] = "hacker"
    lines[1] = json.dumps(data) + "\n"

    with open(log_path, "w") as f:
        f.writelines(lines)

    is_valid, compromised = audit_logger.verify_integrity()
    assert not is_valid
    assert 2 in compromised
