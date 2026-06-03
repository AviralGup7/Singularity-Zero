import os
import sys

class ProcessLifespanLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.fd = None

    def acquire(self) -> bool:
        try:
            self.fd = open(self.lock_path, "w")
            if sys.platform == "win32":
                import msvcrt
                # Lock 1 byte from start of file. LK_NBLCK is non-blocking lock.
                msvcrt.locking(self.fd.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (ImportError, OSError, IOError):
            if self.fd:
                try:
                    self.fd.close()
                except Exception:
                    pass
                self.fd = None
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
            except Exception:
                pass
            try:
                self.fd.close()
            except Exception:
                pass
            self.fd = None
