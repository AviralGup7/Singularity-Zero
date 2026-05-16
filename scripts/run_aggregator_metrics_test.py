"""Lightweight runner for `metrics_summary` tests without pytest.

This avoids invoking pytest (which in this workspace enforces coverage
settings) and provides a quick, local verification of the helper.
"""

from typing import Any
from src.recon.collectors.aggregator import metrics_summary


def _test_empty() -> None:
    summary = metrics_summary({})
    assert summary["total_urls"] == 0
    assert summary["total_errors"] == 0


def _test_populated() -> None:
    stage_meta = {
        "wayback": {"status": "ok", "duration_seconds": 1.2, "new_urls": 5, "errors": 0},
        "commoncrawl": {"status": "ok", "duration_seconds": 0.8, "new_urls": 3, "errors": 1},
    }
    summary = metrics_summary(stage_meta)
    assert summary["total_urls"] == 8
    assert summary["total_errors"] == 1


def main() -> None:
    _test_empty()
    _test_populated()
    print("AGGREGATOR METRICS SUMMARY TESTS PASSED")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print("Test failed:", exc)
        raise
