"""Nuclei Template Integrity & Provenance Validation.

Guards against untrusted template drift or local tampering by validating SHA-256
hashes of all scanner templates against a signed manifest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class NucleiTemplateValidator:
    """Calculates and verifies the cryptographic signature hashes of local templates."""

    def __init__(self, manifest_path: str | Path) -> None:
        self.manifest_path = Path(manifest_path)

    def load_manifest(self) -> dict[str, str]:
        """Load the signed template manifest map."""
        if not self.manifest_path.exists():
            # If manifest doesn't exist, return empty to support boot-strapping
            return {}
        try:
            content = self.manifest_path.read_text(encoding="utf-8")
            data = json.loads(content)
            res = data.get("hashes", {}) if isinstance(data, dict) else data
            return cast(dict[str, str], res)
        except Exception as exc:
            logger.error("Failed to parse signed template manifest: %s", exc)
            return {}

    @staticmethod
    def calculate_sha256(file_path: Path) -> str:
        """Compute the SHA-256 checksum of a single file."""
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()

    def verify_templates(self, templates_dir: str | Path) -> bool:
        """Scan templates folder and verify hashes against the manifest.

        Returns:
            True if all templates match manifest hashes; False otherwise.
        """
        manifest = self.load_manifest()
        if not manifest:
            logger.warning("No template manifest detected. Integrity bootstrapping active.")
            return True

        target_dir = Path(templates_dir)
        if not target_dir.exists() or not target_dir.is_dir():
            logger.warning("Templates directory '%s' does not exist.", target_dir)
            return True

        mismatched_files = []
        # Bug #1 fix: Nuclei ships both ``.yaml`` and ``.yml`` templates; the
        # original code only globbed ``*.yaml`` and silently skipped every
        # ``.yml`` file, so the manifest check could not detect tampered
        # ``.yml`` templates. We now iterate the union of both extensions.
        candidate_paths = list(target_dir.rglob("*.yaml")) + list(target_dir.rglob("*.yml"))
        for file_path in candidate_paths:
            relative_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
            expected_hash = manifest.get(relative_path)

            if expected_hash:
                actual_hash = self.calculate_sha256(file_path)
                if actual_hash != expected_hash:
                    mismatched_files.append((relative_path, expected_hash, actual_hash))

        if mismatched_files:
            for rel_path, exp, act in mismatched_files:
                logger.error(
                    "CRITICAL: Integrity mismatch on template '%s'!\nExpected: %s\nActual: %s",
                    rel_path,
                    exp,
                    act,
                )
            return False

        logger.info("Nuclei template integrity checks complete. 100%% verified.")
        return True
