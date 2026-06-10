import logging
import os
import sys
from typing import IO

logger = logging.getLogger(__name__)


class ProcessLifespanLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.fd: IO[str] | None = None
        self._pid: int | None = None

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False
        except OSError:
            return False

    def acquire(self) -> bool:
        # Snapshot the existing PID (if any) *before* we truncate the
        # lock file. Opening the file in ``"w"`` mode below empties it,
        # so reading afterwards would always return an empty/None PID
        # and the stale-PID cleanup branch below would never fire.
        existing_pid: int | None = None
        try:
            if os.path.exists(self.lock_path):
                existing_pid = _read_pid_from_lock(self.lock_path)
        except OSError:
            existing_pid = None
        try:
            self._pid = os.getpid()
            self.fd = open(self.lock_path, "w", encoding="utf-8")
            assert self.fd is not None
            self.fd.write(str(self._pid))
            self.fd.flush()
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(self.fd.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (ImportError, OSError):
            if self.fd:
                try:
                    self.fd.close()
                except OSError as close_exc:
                    logger.debug("Process lock fd close failed: %s", close_exc)
                self.fd = None
            try:
                if existing_pid is not None and not self._pid_alive(existing_pid):
                    try:
                        os.unlink(self.lock_path)
                    except OSError as exc:
                        logger.warning(
                            "Operation failed in process_lock.py: %s", exc, exc_info=True
                        )  # noqa: BLE001
            except OSError as exc:
                logger.warning("Operation failed in process_lock.py: %s", exc, exc_info=True)  # noqa: BLE001
            return False

    def release(self) -> None:
        if self.fd:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    self.fd.seek(0)
                    msvcrt.locking(self.fd.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            except (ImportError, OSError, ValueError) as unlock_exc:
                logger.debug("Process lock unlock failed: %s", unlock_exc)
            try:
                self.fd.close()
            except OSError as close_exc:
                logger.debug("Process lock fd close failed: %s", close_exc)
            self.fd = None
        try:
            if os.path.exists(self.lock_path):
                os.unlink(self.lock_path)
        except OSError as exc:
            logger.warning("Operation failed in process_lock.py: %s", exc, exc_info=True)  # noqa: BLE001
        self._pid = None


def _read_pid_from_lock(lock_path: str) -> int | None:
    try:
        with open(lock_path, encoding="utf-8") as f:
            raw = f.read().strip()
        return int(raw) if raw else None
    except (OSError, ValueError):
        return None
