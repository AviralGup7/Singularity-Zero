"""Target Hot-Reload & Scan Suspend/Resume Manager.

Permits clean mid-scan pausing and hot-resumptions by reading target-specific
suspend flags at tier boundaries and serializing running contexts.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class HotReloadManager:
    """Manages active suspend flags and coordinates pipeline pauses."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.flags_dir = self.output_dir / ".suspend_flags"
        self.flags_dir.mkdir(parents=True, exist_ok=True)
        self.suspend_trigger_count = 0

    def _get_flag_path(self, target: str) -> Path:
        safe_target = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
        return self.flags_dir / f"{safe_target}.suspend"

    def trigger_suspend(self, target: str) -> None:
        """Create a suspend flag file for the given target."""
        path = self._get_flag_path(target)
        try:
            path.touch()
            self.suspend_trigger_count += 1
            logger.info("Suspend flag file written for target: %s", target)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to write suspend flag for target '%s': %s", target, exc)

    def clear_suspend(self, target: str) -> None:
        """Remove the suspend flag file for the given target."""
        path = self._get_flag_path(target)
        if path.exists():
            try:
                path.unlink()
                logger.info("Cleared suspend flag for target: %s", target)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to clear suspend flag for target '%s': %s", target, exc)

    def check_suspend_trigger(self, target: str, stage: str) -> bool:
        """Check if a suspend is requested for the target.

        NOTE: This function flags whether a suspend is requested, returning True
        if the flag is present. The caller (e.g. the pipeline orchestrator) is
        responsible for performing the actual execution pause or mid-stage wait.

        If true, logs the pause event.
        """
        path = self._get_flag_path(target)
        if path.exists():
            logger.warning(
                "⏸️  Scan suspend requested for target '%s' at boundary stage '%s'. Pausing execution...",
                target,
                stage,
            )
            return True
        return False
