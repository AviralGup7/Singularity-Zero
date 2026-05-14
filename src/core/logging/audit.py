"""Audit logging framework with tamper-evident hash chaining.

Provides structured, append-only audit logging for authentication,
authorization, admin actions, and security events. Each log entry
includes a cryptographic hash of the previous entry to detect tampering.
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
import sys
import threading
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, TextIO




logger = logging.getLogger(__name__)



class AuditEventType(StrEnum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTHZ_DENIAL = "authz_denial"
    ADMIN_ACTION = "admin_action"
    SECURITY_EVENT = "security_event"


class AuditLogger:
    """Thread-safe structured audit logger with tamper-evident hash chaining.

    Each log entry is appended with a hash of the previous entry, creating
    a chain that makes tampering detectable.

    Args:
        log_file: Optional file path to append audit entries to.
        to_stdout: Whether to also emit entries to stdout.
    """

    _instance: AuditLogger | None = None
    _lock = threading.Lock()

    def __init__(
        self,
        log_file: str | Path | None = None,
        to_stdout: bool = True,
    ) -> None:
        self._mutex = threading.Lock()
        self._prev_hash: str = ""
        self._to_stdout = to_stdout
        self._file_handle: TextIO | None = None

        if log_file is not None:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = path.open("a", encoding="utf-8")
            self._load_tail_hash(path)

    @classmethod
    def get_instance(
        cls,
        log_file: str | Path | None = None,
        to_stdout: bool = True,
    ) -> AuditLogger:
        """Return a singleton AuditLogger instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(log_file=log_file, to_stdout=to_stdout)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (useful for testing)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None

    def _load_tail_hash(self, path: Path) -> None:
        """Read the last valid entry from an existing log file to continue the chain."""
        try:
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    self._prev_hash = entry.get("entry_hash", "")
                    break
                except (json.JSONDecodeError, KeyError):
                    continue
        except OSError:
            self._prev_hash = ""

    def _compute_entry_hash(self, payload: dict[str, Any]) -> str:
        """Compute SHA-256 hash of an entry's canonical JSON representation."""
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _build_entry(
        self,
        event_type: AuditEventType,
        source_ip: str,
        user_id: str | None,
        action: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a structured audit log entry."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC).isoformat()

        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "event_id": event_id,
            "event_type": event_type.value,
            "source_ip": source_ip,
            "user_id": user_id or "anonymous",
            "action": action,
            "result": result,
            "prev_hash": self._prev_hash,
        }
        if details:
            payload["details"] = details

        entry_hash = self._compute_entry_hash(payload)
        payload["entry_hash"] = entry_hash
        return payload

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Write an audit entry to configured outputs in a thread-safe manner."""
        line = json.dumps(entry, ensure_ascii=True, separators=(",", ":"))

        with self._mutex:
            if self._file_handle:
                self._file_handle.write(line + "\n")
                self._file_handle.flush()

            if self._to_stdout:
                sys.stdout.write("[AUDIT] " + line + "\n")
                sys.stdout.flush()

            self._prev_hash = entry["entry_hash"]

    def log(
        self,
        event_type: AuditEventType,
        source_ip: str,
        user_id: str | None,
        action: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Emit a generic audit log entry.

        Args:
            event_type: Category of the audit event.
            source_ip: Origin IP address of the event.
            user_id: Identifier of the user associated with the event.
            action: Human-readable action description.
            result: Outcome of the action (e.g., "success", "failure", "denied").
            details: Optional additional context.

        Returns:
            The emitted audit entry dict.
        """
        entry = self._build_entry(event_type, source_ip, user_id, action, result, details)
        self._write_entry(entry)
        return entry

    def log_auth_success(
        self,
        user_id: str,
        source_ip: str,
        method: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log a successful authentication event."""
        detail: dict[str, Any] = {"method": method}
        if details:
            detail.update(details)
        return self.log(
            AuditEventType.AUTH_SUCCESS,
            source_ip,
            user_id,
            "authenticate",
            "success",
            detail,
        )

    def log_auth_failure(
        self,
        user_id: str,
        source_ip: str,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log a failed authentication event."""
        detail: dict[str, Any] = {"reason": reason}
        if details:
            detail.update(details)
        return self.log(
            AuditEventType.AUTH_FAILURE,
            source_ip,
            user_id,
            "authenticate",
            "failure",
            detail,
        )

    def log_authz_denial(
        self,
        user_id: str,
        source_ip: str,
        resource: str,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log an authorization denial event."""
        detail: dict[str, Any] = {"resource": resource, "reason": reason}
        if details:
            detail.update(details)
        return self.log(
            AuditEventType.AUTHZ_DENIAL,
            source_ip,
            user_id,
            "authorize",
            "denied",
            detail,
        )

    def log_admin_action(
        self,
        user_id: str,
        source_ip: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log an administrative action."""
        return self.log(
            AuditEventType.ADMIN_ACTION,
            source_ip,
            user_id,
            action,
            "success",
            details,
        )

    def log_security_event(
        self,
        event_type: str,
        source_ip: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log a security-relevant event."""
        return self.log(
            AuditEventType.SECURITY_EVENT,
            source_ip,
            None,
            event_type,
            "recorded",
            details,
        )

    def __del__(self) -> None:
        """Ensure the file handle is closed when the object is garbage collected."""
        self.close()

    def __enter__(self) -> AuditLogger:
        """Enter the context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the context manager, ensuring the file handle is closed."""
        self.close()

    def close(self) -> None:
        """Close the underlying file handle if open. Idempotent: safe to call multiple times."""
        with self._mutex:
            if self._file_handle is not None:
                try:
                    self._file_handle.flush()
                    self._file_handle.close()
                except OSError as exc:
                    logger.debug("Failed to close audit log file: %s", exc)
                finally:
                    self._file_handle = None


def get_audit_logger() -> AuditLogger:
    """Return the shared AuditLogger singleton, initializing from env if needed.

    Environment variables:
        AUDIT_LOG_FILE: Path to the audit log file.
        AUDIT_LOG_STDOUT: Set to "0" or "false" to disable stdout output.
    """
    log_file = os.environ.get("AUDIT_LOG_FILE")
    to_stdout = os.environ.get("AUDIT_LOG_STDOUT", "1").lower() not in ("0", "false", "no")
    return AuditLogger.get_instance(log_file=log_file, to_stdout=to_stdout)
