"""Cyber Security Test Pipeline - Ghost-VFS Mounts
Disk persistence helpers (flush_to_disk, load_from_disk, bundle export/import).
"""

from __future__ import annotations

import os
import pathlib
import tempfile
from typing import TYPE_CHECKING

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.encryption import (
    Argon2idAESGCM,
    sealed_bundle_decrypt,
    sealed_bundle_encrypt,
    secure_wipe,
)

logger = get_pipeline_logger(__name__)

if TYPE_CHECKING:
    from typing import Any

    from src.core.frontier.vfs_isolation import VFSEncryptionPolicy


class VFSMountsMixin:
    """Mixin providing disk persistence and bundle export/import for GhostVFS."""

    def flush_to_disk(self: Any, physical_path: str, master_key: str) -> None:
        self._ensure_active()
        logger.info("Ghost-VFS: Flushing volatile state to %s", physical_path)

        base_abs = os.path.abspath(physical_path)
        count = 0
        for path in self.list_files():
            try:
                path = self._validate_path(path)
                full_path = pathlib.Path(base_abs).joinpath(path).resolve()
                if os.path.commonpath([base_abs, str(full_path)]) != base_abs:
                    logger.error("Ghost-VFS: Path traversal blocked for path: %s", path)
                    continue

                policy: VFSEncryptionPolicy = self._policy_engine
                if not policy.is_allowed(self._principal, "export", path):
                    logger.error("Ghost-VFS: Policy blocked flushing of path: %s", path)
                    continue

                target_dir = os.path.dirname(full_path)
                os.makedirs(target_dir, exist_ok=True)

                with self.lease_file(path) as lease:
                    sealed = Argon2idAESGCM(master_key).encrypt(
                        lease.bytes, f"ghost-vfs:{path}".encode()
                    )

                with self._lock:
                    fd, temp_file_path = tempfile.mkstemp(
                        dir=target_dir, prefix=".vfs_tmp_", suffix=".tmp"
                    )
                    try:
                        with os.fdopen(fd, "wb") as f:
                            f.write(sealed.encode("utf-8"))
                        os.replace(temp_file_path, full_path)
                    except Exception as e:
                        logger.error("Ghost-VFS: Write fallback failed for %s: %s", temp_file_path, e)
                        try:
                            os.close(fd)
                        except OSError as exc:
                            logger.warning("Ghost-VFS: fd close error: %s", exc)
                        if os.path.exists(temp_file_path):
                            try:
                                os.remove(temp_file_path)
                            except Exception as ex:
                                logger.debug("Ghost-VFS: temp remove error: %s", ex)
                        raise

                count += 1
            except Exception as e:
                logger.error("Ghost-VFS: Failed to flush %s to disk: %s", path, e)

        logger.info("Ghost-VFS: Flush complete. %d artifacts persisted to disk.", count)

    def load_from_disk(self: Any, physical_path: str, master_key: str) -> None:
        self._ensure_active()
        logger.info("Ghost-VFS: Loading volatile state from %s", physical_path)

        base_abs = os.path.abspath(physical_path)
        count = 0
        for root, _, files in os.walk(base_abs):
            for file in files:
                full_path = os.path.abspath(os.path.join(root, file))

                if os.path.commonpath([base_abs, full_path]) != base_abs:
                    logger.error("Ghost-VFS: Path traversal blocked during load: %s", full_path)
                    continue

                try:
                    rel_path = self._validate_path(os.path.relpath(full_path, base_abs))
                except ValueError:
                    logger.error("Ghost-VFS: Invalid path during load: %s", full_path)
                    continue

                if not self._policy_engine.is_allowed(self._principal, "import", rel_path):
                    logger.error("Ghost-VFS: Policy blocked load of path: %s", rel_path)
                    continue

                try:
                    with open(full_path, "rb") as f:
                        file_content = f.read()

                    if len(file_content) < 28:
                        logger.error("Ghost-VFS: File %s is too short for crypto format", rel_path)
                        continue

                    decrypted = Argon2idAESGCM(master_key).decrypt(
                        file_content, f"ghost-vfs:{rel_path}".encode()
                    )
                    self.write_file(rel_path, decrypted)
                    secure_wipe(bytearray(decrypted))
                    count += 1
                except Exception as e:
                    logger.error("Ghost-VFS: Failed to load/decrypt %s: %s", rel_path, e)

        logger.info("Ghost-VFS: Load complete. %d files re-hydrated.", count)

    def export_sealed_bundle(
        self: Any, output_path: str, master_key: str, *, name: str = "ghost-vfs"
    ) -> None:
        self._ensure_active()
        records: dict[str, str] = {}
        for path in self.list_files():
            try:
                path = self._validate_path(path)
            except ValueError:
                logger.error("Ghost-VFS: Invalid path blocked during bundle export: %s", path)
                continue

            if not self._policy_engine.is_allowed(self._principal, "export", path):
                logger.error("Ghost-VFS: Policy blocked bundle export of path: %s", path)
                continue

            with self.lease_file(path) as lease:
                records[path] = Argon2idAESGCM(master_key).encrypt(
                    lease.bytes, f"ghost-vfs-bundle:{path}".encode()
                )
        bundle = sealed_bundle_encrypt(
            name, records, master_key, aad=b"csp:ghost-vfs:sealed-bundle"
        )

        target_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(target_dir, exist_ok=True)
        with self._lock:
            fd, temp_file_path = tempfile.mkstemp(
                dir=target_dir, prefix=".bundle_tmp_", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(bundle)
                os.replace(temp_file_path, output_path)
            except Exception as e:
                logger.error("Ghost-VFS: Sealed bundle write fallback failed: %s", e)
                try:
                    os.close(fd)
                except OSError as exc:
                    logger.warning("Ghost-VFS: fd close error after bundle write: %s", exc)
                if os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except Exception as ex:
                        logger.debug("Ghost-VFS: temp remove error: %s", ex)
                raise

        logger.info("Ghost-VFS: Sealed bundle exported to %s with %d files.", output_path, len(records))

    def import_sealed_bundle(self: Any, bundle_path: str, master_key: str) -> None:
        self._ensure_active()
        with open(bundle_path, encoding="utf-8") as fh:
            payload = sealed_bundle_decrypt(
                fh.read(), master_key, aad=b"csp:ghost-vfs:sealed-bundle"
            )
        for path, encrypted in payload["records"].items():
            try:
                cleaned_path = self._validate_path(str(path))
            except ValueError:
                logger.error("Ghost-VFS: Path traversal blocked during bundle import: %s", path)
                continue

            if not self._policy_engine.is_allowed(self._principal, "import", cleaned_path):
                logger.error("Ghost-VFS: Policy blocked bundle import of path: %s", path)
                continue

            decrypted = Argon2idAESGCM(master_key).decrypt(
                str(encrypted), f"ghost-vfs-bundle:{cleaned_path}".encode()
            )
            try:
                self.write_file(cleaned_path, decrypted)
            finally:
                secure_wipe(bytearray(decrypted))
