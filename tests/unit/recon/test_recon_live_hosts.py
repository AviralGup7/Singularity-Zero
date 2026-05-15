import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from src.core.models import Config
from src.recon.live_hosts import clear_probe_cache, probe_live_hosts, probe_live_hosts_fallback


def make_config(**httpx_overrides: Any) -> Config:
    return Config(
        target_name="demo",
        output_dir=Path("output"),
        http_timeout_seconds=12,
        mode="fast",
        cache={},
        storage={},
        tools={"httpx": True},
        httpx=httpx_overrides,
        gau={},
        waybackurls={},
        katana={},
        nuclei={},
        scoring={},
        filters={},
        screenshots={},
        analysis={},
        review={},
        extensions={},
        concurrency={},
        output={},
        notifications={},
    )


class ReconLiveHostsTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_probe_cache()

    def test_probe_live_hosts_batches_httpx_results_and_normalizes_urls(self) -> None:
        config = make_config(batch_size=2, batch_concurrency=2, threads=60, extra_args=[])
        seen_stdin: list[str] = []
        hosts = {f"host{i}.example.com" for i in range(205)}

        def fake_execute_command(
            command: str,
            timeout: int | None = None,
            stdin_text: str | None = None,
            retry_policy: object | None = None,
        ) -> SimpleNamespace:
            seen_stdin.append(stdin_text or "")
            lines = []
            for host in (stdin_text or "").splitlines():
                if not host:
                    continue
                lines.append(f'{{"url":"https://{host}"}}')
            return SimpleNamespace(
                stdout="\n".join(lines),
                timed_out=False,
                fatal=False,
                warning_messages=[],
                attempt_count=1,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=timeout,
                error_message="",
            )

        with (
            patch("src.recon.live_hosts.projectdiscovery_httpx_available", return_value=True),
            patch(
                "src.recon.live_hosts.execute_command",
                side_effect=fake_execute_command,
            ),
        ):
            records, live_hosts = probe_live_hosts(hosts, config)

        self.assertEqual(len(seen_stdin), 3)
        self.assertEqual(len(records), 205)
        self.assertIn("https://host0.example.com", live_hosts)
        self.assertIn("https://host204.example.com", live_hosts)

    def test_probe_live_hosts_uses_fresh_cache_and_skips_probe(self) -> None:
        config = make_config(
            batch_size=2,
            batch_concurrency=1,
            threads=40,
            extra_args=[],
            probe_cache_ttl_seconds=1200,
        )
        hosts = {"cache-hit.example.com"}
        probe_calls = 0

        def fake_execute_command(
            command: str,
            timeout: int | None = None,
            stdin_text: str | None = None,
            retry_policy: object | None = None,
        ) -> SimpleNamespace:
            nonlocal probe_calls
            probe_calls += 1
            return SimpleNamespace(
                stdout='{"url":"https://cache-hit.example.com"}',
                timed_out=False,
                fatal=False,
                warning_messages=[],
                attempt_count=1,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=timeout,
                error_message="",
            )

        with (
            patch("src.recon.live_hosts.projectdiscovery_httpx_available", return_value=True),
            patch(
                "src.recon.live_hosts.execute_command",
                side_effect=fake_execute_command,
            ),
        ):
            first_records, first_live_hosts = probe_live_hosts(hosts, config)
            second_records, second_live_hosts = probe_live_hosts(hosts, config)

        self.assertEqual(probe_calls, 1)
        self.assertTrue(first_records)
        self.assertTrue(second_records)
        self.assertEqual(first_live_hosts, second_live_hosts)

    def test_probe_live_hosts_force_recheck_bypasses_cache(self) -> None:
        config = make_config(
            batch_size=2,
            batch_concurrency=1,
            threads=40,
            extra_args=[],
            probe_cache_ttl_seconds=1200,
        )
        hosts = {"force-recheck.example.com"}
        probe_calls = 0

        def fake_execute_command(
            command: str,
            timeout: int | None = None,
            stdin_text: str | None = None,
            retry_policy: object | None = None,
        ) -> SimpleNamespace:
            nonlocal probe_calls
            probe_calls += 1
            return SimpleNamespace(
                stdout='{"url":"https://force-recheck.example.com"}',
                timed_out=False,
                fatal=False,
                warning_messages=[],
                attempt_count=1,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=timeout,
                error_message="",
            )

        with (
            patch("src.recon.live_hosts.projectdiscovery_httpx_available", return_value=True),
            patch(
                "src.recon.live_hosts.execute_command",
                side_effect=fake_execute_command,
            ),
        ):
            probe_live_hosts(hosts, config)
            probe_live_hosts(hosts, config, force_recheck=True)

        self.assertEqual(probe_calls, 2)

    def test_probe_live_hosts_rechecks_when_cache_has_no_alive_hosts(self) -> None:
        config = make_config(
            batch_size=2,
            batch_concurrency=1,
            threads=40,
            extra_args=[],
            probe_cache_ttl_seconds=1200,
        )
        hosts = {"stale-negative-cache.example.com"}
        probe_calls = 0

        def fake_execute_command(
            command: str,
            timeout: int | None = None,
            stdin_text: str | None = None,
            retry_policy: object | None = None,
        ) -> SimpleNamespace:
            nonlocal probe_calls
            probe_calls += 1
            if probe_calls == 1:
                return SimpleNamespace(
                    stdout="",
                    timed_out=False,
                    fatal=False,
                    warning_messages=[],
                    attempt_count=1,
                    configured_timeout_seconds=timeout,
                    effective_timeout_seconds=timeout,
                    error_message="",
                )
            return SimpleNamespace(
                stdout='{"url":"https://stale-negative-cache.example.com"}',
                timed_out=False,
                fatal=False,
                warning_messages=[],
                attempt_count=1,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=timeout,
                error_message="",
            )

        with (
            patch("src.recon.live_hosts.projectdiscovery_httpx_available", return_value=True),
            patch(
                "src.recon.live_hosts.execute_command",
                side_effect=fake_execute_command,
            ),
            patch("src.recon.live_hosts.probe_live_hosts_fallback", return_value=([], set())),
        ):
            first_records, first_live_hosts = probe_live_hosts(hosts, config)
            second_records, second_live_hosts = probe_live_hosts(hosts, config)

        self.assertEqual(first_records, [])
        self.assertEqual(first_live_hosts, set())
        self.assertEqual(probe_calls, 2)
        self.assertTrue(second_records)
        self.assertEqual(second_live_hosts, {"https://stale-negative-cache.example.com"})

    def test_probe_live_hosts_adapts_batch_timeout_from_probe_timeout(self) -> None:
        config = make_config(
            batch_size=20,
            batch_concurrency=1,
            threads=80,
            extra_args=[],
            timeout_seconds=2,
            probe_timeout_seconds=2,
        )
        hosts = {"adaptive-timeout.example.com"}
        observed_timeouts: list[int] = []

        def fake_execute_command(
            command: str,
            timeout: int | None = None,
            stdin_text: str | None = None,
            retry_policy: object | None = None,
        ) -> SimpleNamespace:
            _ = (command, stdin_text, retry_policy)
            observed_timeouts.append(int(timeout or 0))
            return SimpleNamespace(
                stdout='{"url":"https://adaptive-timeout.example.com"}',
                timed_out=False,
                fatal=False,
                warning_messages=[],
                attempt_count=1,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=timeout,
                error_message="",
            )

        with (
            patch("src.recon.live_hosts.projectdiscovery_httpx_available", return_value=True),
            patch(
                "src.recon.live_hosts.execute_command",
                side_effect=fake_execute_command,
            ),
        ):
            records, live_hosts = probe_live_hosts(hosts, config)

        self.assertTrue(records)
        self.assertEqual(live_hosts, {"https://adaptive-timeout.example.com"})
        self.assertTrue(observed_timeouts)
        self.assertGreaterEqual(observed_timeouts[0], 5)

    def test_probe_live_hosts_fallback_uses_configured_thread_pool_without_batch_pool_recreation(
        self,
    ) -> None:
        config = make_config(fallback_threads=64)
        progress_messages: list[str] = []

        def fake_probe(host: str, timeout_seconds: int) -> dict[str, Any] | None:
            return {"url": f"https://{host}/", "status_code": 200, "source": "python-probe"}

        with patch("src.recon.live_hosts.probe_host_without_httpx", side_effect=fake_probe):
            records, live_hosts = probe_live_hosts_fallback(
                {"a.example.com", "b.example.com", "c.example.com"},
                5,
                config=config,
                progress_callback=lambda message, percent: progress_messages.append(
                    f"{percent}:{message}"
                ),
            )

        self.assertEqual(len(records), 3)
        self.assertEqual(
            live_hosts,
            {"https://a.example.com/", "https://b.example.com/", "https://c.example.com/"},
        )
        self.assertTrue(progress_messages)


if __name__ == "__main__":
    unittest.main()
