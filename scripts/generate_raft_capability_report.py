#!/usr/bin/env python3
"""Emit raft_capability_report() JSON (architecture review P0-10 / Phase 5).

Optionally cross-checks that unit tests for multi-node Raft exist on disk so
the matrix "tested" flags stay honest without running the full suite.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.core.frontier.raft_capabilities import raft_capability_report  # noqa: E402


def _test_files_exist() -> dict[str, bool]:
    tests = ROOT / "tests" / "unit" / "core"
    return {
        "test_raft_cluster": (tests / "test_raft_cluster.py").is_file(),
        "test_authoritative_durability_suite": (
            tests / "test_authoritative_durability_suite.py"
        ).is_file(),
    }


def main() -> int:
    report = raft_capability_report()
    report["test_files"] = _test_files_exist()
    # Honesty: if multi-node test file missing, flip tested flags
    if not report["test_files"].get("test_raft_cluster"):
        for cap in report["capabilities"]:
            if cap["name"] in {
                "in_process_3_node_quorum",
                "leader_election_failover",
            }:
                cap["tested"] = False
                cap["notes"] = (cap.get("notes") or "") + " [test file missing]"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
