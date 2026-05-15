import time
from types import SimpleNamespace

from src.recon.katana import run_katana


def _config(filters: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(
        filters=filters,
        katana={"extra_args": ["-silent"], "timeout_seconds": 30},
        tools={
            "retry_attempts": 3,
            "retry_backoff_seconds": 1.0,
            "retry_backoff_multiplier": 2.0,
            "retry_max_backoff_seconds": 8.0,
            "retry_on_timeout": True,
            "retry_on_error": True,
        },
    )


def test_run_katana_limits_host_count(monkeypatch) -> None:
    calls: list[int] = []

    def _fake_run_commands_parallel_outcomes(
        jobs: list[tuple[list[str], None, int, object]],
    ) -> list[SimpleNamespace]:
        calls.append(len(jobs))
        return [
            SimpleNamespace(
                stdout="https://example.com/path",
                timed_out=False,
                warning_messages=[],
            )
            for _ in jobs
        ]

    monkeypatch.setattr(
        "src.recon.katana.run_commands_parallel_outcomes",
        _fake_run_commands_parallel_outcomes,
    )

    config = _config(
        {
            "katana_max_hosts": 2,
            "katana_batch_size": 1,
            "katana_time_budget_seconds": 30,
        }
    )
    live_hosts = {
        "https://a.example.com",
        "https://b.example.com",
        "https://c.example.com",
        "https://d.example.com",
    }

    urls, meta = run_katana(live_hosts, config)

    assert len(calls) == 2
    assert all(size == 1 for size in calls)
    assert meta["status"] == "ok"
    assert meta["scanned_hosts"] == 2
    assert meta["discovered_host_count"] == 4
    assert meta["host_cap_applied"] is True
    assert len(urls) == 1


def test_run_katana_stops_when_budget_exceeded(monkeypatch) -> None:
    calls = 0

    def _slow_run_commands_parallel_outcomes(
        jobs: list[tuple[list[str], None, int, object]],
    ) -> list[SimpleNamespace]:
        nonlocal calls
        calls += 1
        time.sleep(0.55)
        return [
            SimpleNamespace(
                stdout="",
                timed_out=True,
                warning_messages=["Warning: katana timed out"],
            )
            for _ in jobs
        ]

    monkeypatch.setattr(
        "src.recon.katana.run_commands_parallel_outcomes",
        _slow_run_commands_parallel_outcomes,
    )

    config = _config(
        {
            "katana_max_hosts": 10,
            "katana_batch_size": 1,
            "katana_time_budget_seconds": 1,
        }
    )
    live_hosts = {
        "https://a.example.com",
        "https://b.example.com",
        "https://c.example.com",
        "https://d.example.com",
    }

    _urls, meta = run_katana(live_hosts, config)

    assert calls < len(live_hosts)
    assert meta["status"] == "degraded_timeout"
