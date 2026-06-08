import unittest

from src.infrastructure.security.audit import AuditEvent, AuditSeverity


class TestAuditEvent(unittest.TestCase):
    def test_event_values(self) -> None:
        assert AuditEvent.AUTH_SUCCESS.value == "auth.success"
        assert AuditEvent.AUTH_FAILURE.value == "auth.failure"
        assert AuditEvent.JOB_CREATE.value == "job.create"
        assert AuditEvent.SYSTEM_START.value == "system.start"

    def test_default_severity(self) -> None:
        assert AuditEvent.AUTH_SUCCESS.default_severity == AuditSeverity.INFO
        assert AuditEvent.AUTH_FAILURE.default_severity == AuditSeverity.WARNING
        assert AuditEvent.AUTHZ_FAILURE.default_severity == AuditSeverity.ERROR
