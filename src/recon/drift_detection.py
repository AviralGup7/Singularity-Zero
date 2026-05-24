"""Continuous Discovery and Drift Detection.

Tracks recon outcome snapshots over consecutive execution cycles and highlights
any changes in subdomains, live hosts, open ports, and resolved URL paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class DriftDetector:
    """Manages recon outcome snapshots and calculates differences between runs."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.snapshots_dir = self.output_dir / "recon_snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def _get_snapshot_path(self, target: str) -> Path:
        # Sanitize target to make it a safe filename
        safe_target = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
        return self.snapshots_dir / f"{safe_target}_snapshot.json"

    def load_latest_snapshot(self, target: str) -> dict[str, Any] | None:
        """Load the latest saved snapshot for a target."""
        path = self._get_snapshot_path(target)
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def save_snapshot(self, target: str, data: dict[str, Any]) -> None:
        """Save a new snapshot of recon outcomes for a target."""
        path = self._get_snapshot_path(target)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:  # noqa: S110
            pass

    def compute_drift(self, target: str, current_data: dict[str, Any]) -> dict[str, Any]:
        """Compare current run outputs with the historical snapshot.

        Returns a dictionary detailing the drift delta.
        """
        historical = self.load_latest_snapshot(target) or {}
        is_first_run = not bool(historical)

        # 1. Compare Subdomains
        hist_subdomains = set(historical.get("subdomains", []))
        curr_subdomains = set(current_data.get("subdomains", []))
        new_subdomains = sorted(list(curr_subdomains - hist_subdomains)) if not is_first_run else []
        removed_subdomains = sorted(list(hist_subdomains - curr_subdomains)) if not is_first_run else []

        # 2. Compare Live Hosts
        hist_live_hosts = set(historical.get("live_hosts", []))
        curr_live_hosts = set(current_data.get("live_hosts", []))
        new_live_hosts = sorted(list(curr_live_hosts - hist_live_hosts)) if not is_first_run else []
        removed_live_hosts = sorted(list(hist_live_hosts - curr_live_hosts)) if not is_first_run else []

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
            "has_drift": bool(not is_first_run and (new_subdomains or removed_subdomains or new_live_hosts or removed_live_hosts or new_ports or removed_ports or new_urls or removed_urls)),
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
                }
            }
        }

        # Save the current data as the new baseline snapshot
        self.save_snapshot(target, current_data)

        # Dump a target-specific drift report to output directory
        report_path = self.output_dir / f"{target}_drift_report.json"
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(drift_report, f, indent=2, ensure_ascii=False)
        except Exception:  # noqa: S110
            pass

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
