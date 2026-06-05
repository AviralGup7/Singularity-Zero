"""Continuous Discovery and Drift Detection.

Tracks recon outcome snapshots over consecutive execution cycles and highlights
any changes in subdomains, live hosts, open ports, and resolved URL paths.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, cast

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Per-target locks ensure that concurrent compute_drift calls for the same
# target serialise their read-modify-write of the snapshot file. Without
# this lock the second writer would overwrite the first's snapshot,
# silently losing observations.
_TARGET_LOCKS: dict[str, threading.Lock] = {}
_TARGET_LOCKS_GUARD = threading.Lock()


def _get_target_lock(target: str) -> threading.Lock:
    with _TARGET_LOCKS_GUARD:
        lock = _TARGET_LOCKS.get(target)
        if lock is None:
            lock = threading.Lock()
            _TARGET_LOCKS[target] = lock
        return lock


class DriftDetector:
    """Manages recon outcome snapshots and calculates differences between runs."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.snapshots_dir = self.output_dir / "recon_snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe_target_filename(target: str) -> str:
        """Return a path-safe filename derived from the target string.

        Strips directory separators and parent-directory references, then
        replaces any remaining unsafe characters with underscores. The
        result is bounded in length to avoid pathological filenames.
        """
        raw = str(target or "").strip()
        if not raw:
            return "_invalid_target"
        # Remove any path separators and parent-directory markers
        sanitized = raw.replace("\\", "_").replace("/", "_").replace("..", "_")
        # Replace any remaining non-alphanumeric, dot, dash, or underscore chars
        sanitized = "".join(c if c.isalnum() or c in ".-_" else "_" for c in sanitized)
        sanitized = sanitized.strip("._")
        if not sanitized:
            sanitized = "_invalid_target"
        return sanitized[:200]

    def _get_snapshot_path(self, target: str) -> Path:
        return self.snapshots_dir / f"{self._safe_target_filename(target)}_snapshot.json"

    def _get_report_path(self, target: str) -> Path:
        return self.output_dir / f"{self._safe_target_filename(target)}_drift_report.json"

    def load_latest_snapshot(self, target: str) -> dict[str, Any] | None:
        """Load the latest saved snapshot for a target."""
        path = self._get_snapshot_path(target)
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return cast(dict[str, Any], json.load(f))
        except Exception:
            logger.warning(
                "drift_detection: failed to load snapshot for %s; operation skipped",
                target,
                exc_info=True,
            )
            return None

    def save_snapshot(self, target: str, data: dict[str, Any]) -> None:
        """Save a new snapshot of recon outcomes for a target."""
        path = self._get_snapshot_path(target)
        try:
            # Atomic write: tempfile + os.replace prevents a crash mid-write
            # from leaving the snapshot half-rendered.
            parent = path.parent
            parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                os.replace(tmp_path, path)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception:
            logger.warning(
                "drift_detection: failed to save snapshot for %s; operation skipped",
                target,
                exc_info=True,
            )

    def compute_drift(self, target: str, current_data: dict[str, Any]) -> dict[str, Any]:
        """Compare current run outputs with the historical snapshot.

        Returns a dictionary detailing the drift delta.

        Concurrent invocations for the same target are serialised via a
        per-target lock so the snapshot/report files cannot be torn or
        clobbered by interleaved read-modify-write sequences.
        """
        with _get_target_lock(target):
            return self._compute_drift_locked(target, current_data)

    def _compute_drift_locked(self, target: str, current_data: dict[str, Any]) -> dict[str, Any]:
        historical = self.load_latest_snapshot(target) or {}
        is_first_run = not bool(historical)

        # 1. Compare Subdomains
        hist_subdomains = set(historical.get("subdomains", []))
        curr_subdomains = set(current_data.get("subdomains", []))
        new_subdomains = sorted(list(curr_subdomains - hist_subdomains)) if not is_first_run else []
        removed_subdomains = (
            sorted(list(hist_subdomains - curr_subdomains)) if not is_first_run else []
        )

        # 2. Compare Live Hosts
        hist_live_hosts = set(historical.get("live_hosts", []))
        curr_live_hosts = set(current_data.get("live_hosts", []))
        new_live_hosts = sorted(list(curr_live_hosts - hist_live_hosts)) if not is_first_run else []
        removed_live_hosts = (
            sorted(list(hist_live_hosts - curr_live_hosts)) if not is_first_run else []
        )

        # 3. Compare Open Ports
        hist_ports = set(historical.get("open_ports", []))
        curr_ports = set(current_data.get("open_ports", []))
        new_ports = sorted(list(curr_ports - hist_ports)) if not is_first_run else []
        removed_ports = sorted(list(hist_ports - curr_ports)) if not is_first_run else []

        # 4. Compare Discovered URLs
        hist_urls = set(historical.get("urls", []))
        curr_urls = set(current_data.get("urls", []))
        new_urls = sorted(list(curr_urls - hist_urls)) if not is_first_run else []
        removed_urls = sorted(list(hist_urls - curr_urls)) if not is_first_run else []

        drift_report = {
            "target": target,
            "has_drift": bool(
                not is_first_run
                and (
                    new_subdomains
                    or removed_subdomains
                    or new_live_hosts
                    or removed_live_hosts
                    or new_ports
                    or removed_ports
                    or new_urls
                    or removed_urls
                )
            ),
            "deltas": {
                "subdomains": {
                    "added": new_subdomains,
                    "removed": removed_subdomains,
                    "added_count": len(new_subdomains),
                    "removed_count": len(removed_subdomains),
                },
                "live_hosts": {
                    "added": new_live_hosts,
                    "removed": removed_live_hosts,
                    "added_count": len(new_live_hosts),
                    "removed_count": len(removed_live_hosts),
                },
                "open_ports": {
                    "added": new_ports,
                    "removed": removed_ports,
                    "added_count": len(new_ports),
                    "removed_count": len(removed_ports),
                },
                "urls": {
                    "added": new_urls,
                    "removed": removed_urls,
                    "added_count": len(new_urls),
                    "removed_count": len(removed_urls),
                },
            },
        }

        # Save the current data as the new baseline snapshot
        self.save_snapshot(target, current_data)

        # Dump a target-specific drift report to output directory
        report_path = self._get_report_path(target)
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(drift_report, f, indent=2, ensure_ascii=False)
        except Exception:
            logger.warning(
                "drift_detection: failed to write drift report for %s; operation skipped",
                target,
                exc_info=True,
            )

        return drift_report

    def render_cli_summary(self, drift_report: dict[str, Any]) -> str:
        """Generate a beautiful text-based CLI summary report."""
        if not drift_report.get("has_drift", False):
            return "✨ No asset/recon drift detected. Target profile is fully consistent with the previous run."

        lines = [
            "⚠️  Reconnaissance Asset Drift Detected!",
            "=" * 50,
            f"Target: {drift_report.get('target')}",
            "-" * 50,
        ]

        deltas = drift_report.get("deltas", {})
        for category, info in deltas.items():
            added = info.get("added", [])
            removed = info.get("removed", [])
            if added or removed:
                lines.append(f"📁 {category.upper()}:")
                if added:
                    lines.append(f"  [+] Added ({len(added)}):")
                    for item in added[:10]:
                        lines.append(f"      - {item}")
                    if len(added) > 10:
                        lines.append(f"      ... and {len(added) - 10} more")
                if removed:
                    lines.append(f"  [-] Removed ({len(removed)}):")
                    for item in removed[:10]:
                        lines.append(f"      - {item}")
                    if len(removed) > 10:
                        lines.append(f"      ... and {len(removed) - 10} more")
                lines.append("-" * 30)

        return "\n".join(lines)
