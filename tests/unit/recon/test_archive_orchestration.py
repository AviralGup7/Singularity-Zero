import time
from types import SimpleNamespace

from src.recon.archive import run_archive_jobs


def test_run_archive_jobs_continues_after_provider_error(monkeypatch) -> None:
    def _fake_execute_command(command, timeout, stdin_text, retry_policy):
        _ = timeout
        _ = stdin_text
        _ = retry_policy
        if command[0] == "gau":
            return SimpleNamespace(
                stdout="",
                timed_out=False,
                fatal=True,
                warning_messages=["Command failed with exit code 2"],
                duration_seconds=0.2,
                attempt_count=1,
            )
        return SimpleNamespace(
            stdout="https://api.example.com/v1/health\n",
            timed_out=False,
            fatal=False,
            warning_messages=[],
            duration_seconds=0.2,
            attempt_count=1,
        )

    monkeypatch.setattr("src.recon.archive.execute_command", _fake_execute_command)

    urls, meta = run_archive_jobs(
        hostnames=["api.example.com"],
        archive_batch_size=20,
        archive_jobs=[
            ("gau", ["gau", "--subs"], 10, None),
            ("waybackurls", ["waybackurls"], 10, None),
        ],
        filters={"ignore_extensions": []},
        progress_callback=None,
    )

    assert "https://api.example.com/v1/health" in urls
    assert meta["gau"]["status"] == "error"
    assert meta["gau"]["error_count"] == 1
    assert meta["waybackurls"]["status"] == "ok"


def test_run_archive_jobs_clamps_timeout_and_disables_retries(monkeypatch) -> None:
    invocations: list[tuple[int | None, object]] = []

    def _slow_execute_command(command, timeout, stdin_text, retry_policy):
        _ = command
        _ = stdin_text
        invocations.append((timeout, retry_policy))
        time.sleep(0.55)
        return SimpleNamespace(
            stdout="",
            timed_out=True,
            fatal=True,
            warning_messages=[f"Command {command!r} timed out after {timeout} seconds"],
            duration_seconds=0.55,
            attempt_count=1,
        )

    monkeypatch.setattr("src.recon.archive.execute_command", _slow_execute_command)

    run_archive_jobs(
        hostnames=[f"h{i}.example.com" for i in range(30)],
        archive_batch_size=10,
        archive_jobs=[
            ("gau", ["gau", "--subs"], 120, object()),
            ("waybackurls", ["waybackurls"], 120, object()),
        ],
        filters={
            "archive_time_budget_seconds": 120,
            "archive_max_consecutive_timeouts": 2,
            "ignore_extensions": [],
        },
        progress_callback=None,
    )

    assert invocations
    assert all((timeout or 0) <= 120 for timeout, _ in invocations)
    assert any((timeout or 0) < 120 for timeout, _ in invocations)
    assert all(retry_policy is not None for _, retry_policy in invocations)


def test_run_archive_jobs_marks_timeout_as_degraded_but_continues(monkeypatch) -> None:
    def _fake_execute_command(command, timeout, stdin_text, retry_policy):
        _ = timeout
        _ = stdin_text
        _ = retry_policy
        if command[0] == "gau":
            return SimpleNamespace(
                stdout="",
                timed_out=True,
                fatal=True,
                warning_messages=["Warning: Command ['gau'] timed out after 1 seconds"],
                duration_seconds=0.2,
                attempt_count=1,
            )
        return SimpleNamespace(
            stdout="https://api.example.com/v1/archive\n",
            timed_out=False,
            fatal=False,
            warning_messages=[],
            duration_seconds=0.2,
            attempt_count=1,
        )

    monkeypatch.setattr("src.recon.archive.execute_command", _fake_execute_command)

    urls, meta = run_archive_jobs(
        hostnames=["api.example.com"],
        archive_batch_size=20,
        archive_jobs=[
            ("gau", ["gau", "--subs"], 10, object()),
            ("waybackurls", ["waybackurls"], 10, object()),
        ],
        filters={"ignore_extensions": []},
        progress_callback=None,
    )

    assert "https://api.example.com/v1/archive" in urls
    assert meta["gau"]["status"] == "degraded_timeout"
    assert meta["gau"]["timeout_count"] == 1
    assert meta["gau"]["timeout_events"]
