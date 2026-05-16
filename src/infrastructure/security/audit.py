"""Audit logging for the Cyber Security Test Pipeline.

Provides comprehensive audit trail for all security-relevant events
with tamper-evident log entries, integrity verification, and
log export/archival capabilities.

Classes:
    AuditSeverity: Log severity levels
    AuditEvent: Pre-defined audit event types
    AuditEntry: Single audit log entry
    AuditLogger: Main audit logging orchestrator

Usage:
    from src.infrastructure.security.audit import AuditLogger, AuditEvent, AuditSeverity
    from src.infrastructure.security.config import SecurityConfig

    config = SecurityConfig()
    audit = AuditLogger(config)

    audit.log(
        event=AuditEvent.AUTH_SUCCESS,
        user_id="admin",
        details={"method": "jwt"},
    )
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import threading
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, Field

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.config import SecurityConfig

# Fix #293: use pipeline logger instead of stdlib logger
logger = get_pipeline_logger(__name__)


class AuditSeverity(StrEnum):
    """Audit log severity levels.

    Levels:
        INFO: Informational events (successful operations).
        WARNING: Potentially suspicious activity.
        ERROR: Failed operations or policy violations.
        CRITICAL: Severe security events requiring immediate attention.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditEvent(StrEnum):
    """Pre-defined audit event types.

    Events are grouped by category:
    - Authentication: AUTH_SUCCESS, AUTH_FAILURE, TOKEN_REFRESH, SESSION_CREATE, SESSION_INVALIDATE
    - Authorization: AUTHZ_FAILURE
    - Job Management: JOB_CREATE, JOB_UPDATE, JOB_DELETE, JOB_CANCEL
    - Configuration: CONFIG_CHANGE
    - Cache: CACHE_INVALIDATE, CACHE_CLEAR
    - Rate Limiting: RATE_LIMIT_EXCEEDED
    - API Keys: APIKEY_CREATE, APIKEY_ROTATE, APIKEY_REVOKE
    - System: SYSTEM_START, SYSTEM_SHUTDOWN
    """

    # Authentication
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    TOKEN_REFRESH = "auth.token_refresh"  # noqa: S105
    SESSION_CREATE = "auth.session_create"
    SESSION_INVALIDATE = "auth.session_invalidate"

    # Authorization
    AUTHZ_FAILURE = "authz.failure"

    # Job Management
    JOB_CREATE = "job.create"
    JOB_UPDATE = "job.update"
    JOB_DELETE = "job.delete"
    JOB_CANCEL = "job.cancel"

    # Configuration
    CONFIG_CHANGE = "config.change"

    # Cache
    CACHE_INVALIDATE = "cache.invalidate"
    CACHE_CLEAR = "cache.clear"

    # Rate Limiting
    RATE_LIMIT_EXCEEDED = "ratelimit.exceeded"

    # API Keys
    APIKEY_CREATE = "apikey.create"
    APIKEY_ROTATE = "apikey.rotate"
    APIKEY_REVOKE = "apikey.revoke"

    # System
    SYSTEM_START = "system.start"
    SYSTEM_SHUTDOWN = "system.shutdown"

    # Pipeline lifecycle
    PIPELINE_START = "pipeline.start"
    PIPELINE_COMPLETED = "pipeline.completed"
    PIPELINE_FAILED = "pipeline.failed"
    STAGE_START = "pipeline.stage_start"
    STAGE_COMPLETED = "pipeline.stage_completed"
    STAGE_FAILED = "pipeline.stage_failed"
    FINDING_DISCOVERED = "pipeline.finding_discovered"

    @property
    def default_severity(self) -> AuditSeverity:
        """Get the default severity level for this event.

        Returns:
            Default AuditSeverity.
        """
        return _SEVERITY_MAP.get(self, AuditSeverity.INFO)


# Fix #301: Move severity_map out of the property to prevent rebuilding dict on every call
_SEVERITY_MAP: dict[AuditEvent, AuditSeverity] = {
    AuditEvent.AUTH_SUCCESS: AuditSeverity.INFO,
    AuditEvent.AUTH_FAILURE: AuditSeverity.WARNING,
    AuditEvent.TOKEN_REFRESH: AuditSeverity.INFO,
    AuditEvent.SESSION_CREATE: AuditSeverity.INFO,
    AuditEvent.SESSION_INVALIDATE: AuditSeverity.INFO,
    AuditEvent.AUTHZ_FAILURE: AuditSeverity.ERROR,
    AuditEvent.JOB_CREATE: AuditSeverity.INFO,
    AuditEvent.JOB_UPDATE: AuditSeverity.INFO,
    AuditEvent.JOB_DELETE: AuditSeverity.WARNING,
    AuditEvent.JOB_CANCEL: AuditSeverity.WARNING,
    AuditEvent.CONFIG_CHANGE: AuditSeverity.WARNING,
    AuditEvent.CACHE_INVALIDATE: AuditSeverity.INFO,
    AuditEvent.CACHE_CLEAR: AuditSeverity.WARNING,
    AuditEvent.RATE_LIMIT_EXCEEDED: AuditSeverity.WARNING,
    AuditEvent.APIKEY_CREATE: AuditSeverity.INFO,
    AuditEvent.APIKEY_ROTATE: AuditSeverity.INFO,
    AuditEvent.APIKEY_REVOKE: AuditSeverity.WARNING,
    AuditEvent.SYSTEM_START: AuditSeverity.INFO,
    AuditEvent.SYSTEM_SHUTDOWN: AuditSeverity.INFO,
    AuditEvent.PIPELINE_START: AuditSeverity.INFO,
    AuditEvent.PIPELINE_COMPLETED: AuditSeverity.INFO,
    AuditEvent.PIPELINE_FAILED: AuditSeverity.ERROR,
    AuditEvent.STAGE_START: AuditSeverity.INFO,
    AuditEvent.STAGE_COMPLETED: AuditSeverity.INFO,
    AuditEvent.STAGE_FAILED: AuditSeverity.WARNING,
    AuditEvent.FINDING_DISCOVERED: AuditSeverity.INFO,
}


class AuditEntry(BaseModel):
    """Single audit log entry.

    Attributes:
        id: Unique entry identifier (sequential counter for ordering).
        timestamp: ISO 8601 timestamp.
        event: Audit event type.
        severity: Log severity level.
        user_id: User who triggered the event (if applicable).
        source_ip: Client IP address (if applicable).
        details: Additional event-specific data.
        previous_hash: Hash of the previous entry (for tamper-evident chain).
        entry_hash: Hash of this entry (computed after creation).
    """

    id: int = Field(..., ge=0)
    timestamp: str = Field(...)
    event: str = Field(..., min_length=1)
    severity: str = Field(..., min_length=1)
    user_id: str | None = Field(default=None)
    source_ip: str | None = Field(default=None)
    resource_id: str | None = Field(default=None) # Fix #296: Add missing field
    correlation_id: str | None = Field(default=None) # Fix #296: Add missing field
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = Field(default="")
    entry_hash: str = Field(default="")

    def compute_hash(self, hmac_secret: str = "") -> str:
        """Compute the hash of this entry for tamper-evident chaining.

        Args:
            hmac_secret: Optional HMAC secret for keyed hashing.

        Returns:
            Hex-encoded hash string.
        """
        data = {
            "id": self.id,
            "timestamp": self.timestamp,
            "event": self.event,
            "severity": self.severity,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "resource_id": self.resource_id, # Fix #296
            "correlation_id": self.correlation_id, # Fix #296
            "details": self.details,
            "previous_hash": self.previous_hash,
        }
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

        if hmac_secret:
            hash_value = hmac_module.new(
                hmac_secret.encode("utf-8"),
                payload,
                hashlib.sha256,
            ).hexdigest()
        else:
            hash_value = hashlib.sha256(payload).hexdigest()

        return hash_value

    def finalize(self, hmac_secret: str = "") -> None:
        """Compute and set the entry hash.

        Args:
            hmac_secret: Optional HMAC secret for keyed hashing.
        """
        self.entry_hash = self.compute_hash(hmac_secret)


class AuditLogger:
    """Main audit logging orchestrator.

    Provides tamper-evident audit logging with:
    - Sequential entry chaining
    - HMAC-based integrity verification
    - Log rotation by size
    - Export and archival
    - Thread-safe writes

    Attributes:
        config: Security configuration.
        _counter: Sequential entry counter.
        _last_hash: Hash of the previous entry.
        _lock: Thread lock for write synchronization.
        _file_handle: Open file handle for the audit log.
        _current_size: Current log file size in bytes.
    """

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the audit logger.

        Args:
            config: Security configuration.
        """
        self.config = config
        self._counter = 0
        self._last_hash = ""
        self._lock = threading.Lock()
        self._file_handle: Any = None
        self._current_size = 0

        self._ensure_log_file()

    def _ensure_log_file(self) -> None:
        """Ensure the audit log file exists and is open."""
        log_path = Path(self.config.audit.log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        if not log_path.exists():
            log_path.touch()

        self._current_size = log_path.stat().st_size

        # Fix #294: Close existing file handle before re-opening
        if self._file_handle is not None:
            try:
                self._file_handle.close()
            except Exception:  # noqa: S110, S112
                pass

        self._file_handle = open(log_path, "a", encoding="utf-8")

        if self._current_size == 0:
            self._last_hash = "genesis"
        else:
            self._last_hash = self._read_last_hash()

        # Fix #300: Add SQLite backing store for queries
        if getattr(self, "_db", None) is None:
            import sqlite3
            self._db = sqlite3.connect(":memory:", check_same_thread=False)
            self._db.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY,
                    event TEXT,
                    user_id TEXT,
                    severity TEXT,
                    data TEXT
                )
            ''')
            # Populate DB
            try:
                with open(log_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                self._db.execute('INSERT OR IGNORE INTO audit_log (id, event, user_id, severity, data) VALUES (?, ?, ?, ?, ?)',
                                                 (data.get("id"), data.get("event"), data.get("user_id"), data.get("severity"), line))
                            except Exception:  # noqa: S110, S112
                                pass
            except Exception:  # noqa: S110, S112
                pass

    def _read_last_hash(self) -> str:
        """Read the hash of the last entry from the log file.

        Returns:
            Last entry hash or genesis if file is empty.
        """
        log_path = Path(self.config.audit.log_path)
        try:
            # Fix #295: Read backwards instead of f.readlines() which OOMs on large files
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return "genesis"

                pos = size - 1
                while pos >= 0:
                    f.seek(pos)
                    if f.read(1) == b'\n' and pos != size - 1:
                        break
                    pos -= 1

                f.seek(max(0, pos + 1))
                last_line = f.readline().strip()
                if last_line:
                    entry = json.loads(last_line.decode("utf-8"))
                    return cast(str, entry.get("entry_hash", "genesis"))
        except Exception:  # noqa: S110, S112
            pass
        return "genesis"

    def log(
        self,
        event: AuditEvent | str,
        user_id: str | None = None,
        source_ip: str | None = None,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
        severity: AuditSeverity | None = None,
        correlation_id: str | None = None,
    ) -> AuditEntry:
        """Log an audit event.

        Args:
            event: Audit event type (enum or string).
            user_id: User who triggered the event.
            source_ip: Client IP address.
            resource_id: Identifier of the resource being accessed.
            details: Additional event-specific data.
            severity: Log severity (defaults to event default).
            correlation_id: Correlation ID for tracing across services.

        Returns:
            The created AuditEntry.
        """
        event_name = event.value if isinstance(event, AuditEvent) else event
        if isinstance(severity, AuditSeverity):
            event_severity = severity.value
        elif event_name in [e.value for e in AuditEvent]:
            event_severity = AuditEvent(event_name).default_severity.value
        else:
            event_severity = AuditSeverity.INFO.value

        with self._lock:
            self._counter += 1

            entry = AuditEntry(
                id=self._counter,
                timestamp=datetime.now(UTC).isoformat(),
                event=event_name,
                severity=event_severity,
                user_id=user_id,
                source_ip=source_ip,
                resource_id=resource_id,
                correlation_id=correlation_id,
                details=details or {},
                previous_hash=self._last_hash,
            )

            hmac_secret = self.config.audit.hmac_secret if self.config.audit.tamper_evident else ""
            entry.finalize(hmac_secret)
            self._last_hash = entry.entry_hash

            self._write_entry(entry)
            self._check_rotation()

        return entry

    def _write_entry(self, entry: AuditEntry) -> None:
        """Write an audit entry to the log file.

        Args:
            entry: Audit entry to write.
        """
        if self._file_handle is None:
            self._ensure_log_file()
        if self._file_handle is None:
            logger.error("Audit log file handle could not be opened")
            return

        line = json.dumps(entry.model_dump(), separators=(",", ":"))
        self._file_handle.write(line + "\n")
        self._file_handle.flush()
        # Fix #297: len(line) + 1 avoids full string encode on large log entries
        self._current_size += len(line) + 1

    def _check_rotation(self) -> None:
        """Check if log rotation is needed."""
        if not self.config.audit.rotate_on_size:
            return

        max_bytes = self.config.audit.max_log_size_mb * 1024 * 1024
        if self._current_size >= max_bytes:
            self._rotate_log()

    def _rotate_log(self) -> None:
        """Rotate the audit log file."""
        if self._file_handle:
            self._file_handle.close()

        log_path = Path(self.config.audit.log_path)
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        archive_name = f"{log_path.stem}_{timestamp}{log_path.suffix}"
        archive_path = log_path.parent / archive_name

        try:
            import shutil
            # Fix #298: shutil.move is safer on Windows than log_path.rename
            shutil.move(str(log_path), str(archive_path))
            logger.info("Audit log rotated to %s", archive_path)
        except Exception as exc:
            logger.error("Failed to rotate audit log: %s", exc)

        self._current_size = 0
        # Fix #299: Reset hash chain after rotation
        self._last_hash = "genesis"
        self._file_handle = open(log_path, "a", encoding="utf-8")

    def verify_integrity(self) -> tuple[bool, list[int]]:
        """Verify the integrity of the audit log.

        Checks the hash chain to detect tampering.

        Returns:
            Tuple of (is_valid, list_of_compromised_entry_ids).
        """
        log_path = Path(self.config.audit.log_path)
        if not log_path.exists():
            return True, []

        hmac_secret = self.config.audit.hmac_secret if self.config.audit.tamper_evident else ""
        compromised: list[int] = []
        prev_hash = "genesis"

        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        # Fix #354: Use model_validate with strict=False
                        entry = AuditEntry.model_validate(data, strict=False)
                    except Exception:  # noqa: S110, S112
                        compromised.append(-1)
                        continue

                    if entry.previous_hash != prev_hash:
                        compromised.append(entry.id)

                    expected_hash = entry.compute_hash(hmac_secret)
                    if entry.entry_hash != expected_hash:
                        compromised.append(entry.id)

                    prev_hash = entry.entry_hash
        except Exception as exc:
            logger.error("Error verifying audit log integrity: %s", exc)
            return False, compromised

        return len(compromised) == 0, compromised

    def export_logs(
        self,
        output_path: str,
        start_id: int | None = None,
        end_id: int | None = None,
    ) -> int:
        """Export audit logs to a file.

        Args:
            output_path: Path for the exported log file.
            start_id: Starting entry ID (inclusive).
            end_id: Ending entry ID (inclusive).

        Returns:
            Number of entries exported.
        """
        log_path = Path(self.config.audit.log_path)
        if not log_path.exists():
            return 0

        count = 0
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with (
            open(log_path, encoding="utf-8") as src,
            open(out_path, "w", encoding="utf-8") as dst,
        ):
            for line in src:
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    entry_id = data.get("id", 0)
                except Exception:  # noqa: S110, S112
                    continue

                if start_id is not None and entry_id < start_id:
                    continue
                if end_id is not None and entry_id > end_id:
                    # Fix #335: Use continue instead of break to handle gaps and non-sequential IDs
                    continue

                dst.write(line + "\n")
                count += 1

        logger.info("Exported %d audit entries to %s", count, output_path)
        return count

    def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        event: str | None = None,
        user_id: str | None = None,
        severity: str | None = None,
    ) -> list[AuditEntry]:
        """Get audit entries with filtering.

        Args:
            limit: Maximum number of entries to return.
            offset: Number of entries to skip.
            event: Filter by event type.
            user_id: Filter by user ID.
            severity: Filter by severity level.

        Returns:
            List of matching AuditEntry instances.
        """
        log_path = Path(self.config.audit.log_path)
        if not log_path.exists():
            return []

        entries: list[AuditEntry] = []
        skipped = 0

        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except Exception:  # noqa: S110, S112
                        continue

                    if event and data.get("event") != event:
                        continue
                    if user_id and data.get("user_id") != user_id:
                        continue
                    if severity and data.get("severity") != severity:
                        continue

                    if skipped < offset:
                        skipped += 1
                        continue

                    entries.append(AuditEntry(**data))

                    if len(entries) >= limit:
                        break
        except Exception as exc:
            logger.error("Error reading audit log: %s", exc)

        return entries

    def cleanup_old_logs(self) -> int:
        """Remove archived logs older than retention period.

        Returns:
            Number of files removed.
        """
        log_path = Path(self.config.audit.log_path)
        log_dir = log_path.parent
        cutoff = time.time() - (self.config.audit.retention_days * 86400)

        removed = 0
        for archive in log_dir.glob(f"{log_path.stem}_*{log_path.suffix}"):
            try:
                if archive.stat().st_mtime < cutoff:
                    archive.unlink()
                    removed += 1
                    logger.info("Removed old audit log: %s", archive)
            except Exception as exc:
                logger.error("Failed to remove old audit log %s: %s", archive, exc)

        return removed

    def close(self) -> None:
        """Close the audit log file handle."""
        with self._lock:
            if self._file_handle:
                try:
                    self._file_handle.flush()
                    self._file_handle.close()
                except OSError as exc:
                    logger.warning("Failed to close audit log: %s", exc)
                finally:
                    self._file_handle = None

    def __enter__(self) -> AuditLogger:
        """Enter the context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the context manager, ensuring the file handle is closed."""
        self.close()

        # Fix #302: Removed dangerous __del__ method which acquired locks
