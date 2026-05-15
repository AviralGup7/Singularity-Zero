from __future__ import annotations

from unittest.mock import patch

import scripts.run_square_dashboard_canary as canary


class _DummyServices:
    def __init__(self, snapshots: list[dict[str, object] | None]) -> None:
        self._snapshots = list(snapshots)

    def get_job(self, _job_id: str) -> dict[str, object] | None:
        if self._snapshots:
            return self._snapshots.pop(0)
        return None


def test_wait_for_terminal_job_state_returns_terminal_snapshot_before_timeout() -> None:
    services = _DummyServices(
        [
            {"id": "job-1", "status": "running", "stage": "live_hosts"},
            {"id": "job-1", "status": "stopped", "stage": "completed"},
        ]
    )
    current = {"id": "job-1", "status": "running", "stage": "live_hosts"}

    with (
        patch(
            "scripts.run_square_dashboard_canary.time.monotonic",
            side_effect=[0.0, 0.0, 0.1],
        ),
        patch("scripts.run_square_dashboard_canary.time.sleep") as sleep_mock,
    ):
        result = canary._wait_for_terminal_job_state(
            services,
            "job-1",
            current=current,
            poll_seconds=1.0,
            timeout_seconds=5.0,
        )

    assert result["status"] == "stopped"
    sleep_mock.assert_called_once()


def test_wait_for_terminal_job_state_returns_latest_snapshot_on_timeout() -> None:
    services = _DummyServices(
        [
            {"id": "job-2", "status": "running", "stage": "urls"},
        ]
    )
    current = {"id": "job-2", "status": "running", "stage": "urls"}

    with (
        patch(
            "scripts.run_square_dashboard_canary.time.monotonic",
            side_effect=[0.0, 0.0, 1.1],
        ),
        patch("scripts.run_square_dashboard_canary.time.sleep") as sleep_mock,
    ):
        result = canary._wait_for_terminal_job_state(
            services,
            "job-2",
            current=current,
            poll_seconds=1.0,
            timeout_seconds=1.0,
        )

    assert result["status"] == "running"
    sleep_mock.assert_called_once()
