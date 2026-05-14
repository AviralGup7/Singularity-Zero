"""Live host probing using httpx and urllib fallback.

Probes discovered subdomains to identify which are responding HTTP services.
Uses httpx when available for fast batch probing, with a urllib-based fallback.
Includes response caching to avoid redundant probes across runs.
"""

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

import urllib3

from src.core.models import DEFAULT_USER_AGENT, Config
from src.core.utils.http_pool import get_pooled_connection
from src.pipeline.cache_backend import PersistentCache
from src.pipeline.tools import (
    build_retry_policy,
    execute_command,
    projectdiscovery_httpx_available,
)
from src.recon.common import normalize_url

PROBE_CACHE_MIN_TTL_SECONDS = 600
PROBE_CACHE_MAX_TTL_SECONDS = 1800
PROBE_CACHE_DEFAULT_TTL_SECONDS = 1200
_PROBE_CACHE_MAX_SIZE = int(os.environ.get("RECON_PROBE_CACHE_MAX_SIZE", 10000))

# NOTE: _PROBE_CACHE_MAX_SIZE is read from env but PersistentCache does not accept a max_size arg;
# cleanup is handled via eviction/ttl internally rather than a hard cap.
_probe_cache = PersistentCache()

logger = logging.getLogger(__name__)


def clear_probe_cache() -> None:
    _probe_cache.clear()


def _emit_live_host_progress(callback: Any, message: str, percent: int, **meta: object) -> None:
    if callback:
        try:
            callback(message, percent, **meta)
        except TypeError:
            callback(message, percent)


def _normalized_probe_hosts(subdomains: set[str]) -> list[str]:
    return sorted({entry.strip().lower() for entry in subdomains if entry and entry.strip()})


def _probe_cache_ttl_seconds(config: Config) -> int:
    raw = int(config.httpx.get("probe_cache_ttl_seconds", PROBE_CACHE_DEFAULT_TTL_SECONDS))
    return max(PROBE_CACHE_MIN_TTL_SECONDS, min(PROBE_CACHE_MAX_TTL_SECONDS, raw))


def _host_from_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    hostname = (parsed.hostname or "").strip().lower()
    port = getattr(parsed, "port", None)
    if port:
        return f"{hostname}:{port}"
    return hostname


def _cache_lookup(
    hosts: list[str], ttl_seconds: int, force_recheck: bool
) -> tuple[list[str], list[dict[str, Any]], set[str], int]:
    if force_recheck or os.environ.get("RECON_FLUSH_CACHE"):
        return hosts, [], set(), 0
    now = time.time()
    to_probe: list[str] = []
    cached_records: list[dict[str, Any]] = []
    cached_live_hosts: set[str] = set()
    skipped_count = 0
    for host in hosts:
        cached = _probe_cache.get(host)
        if not cached:
            to_probe.append(host)
            continue
        raw_checked_at = cached.get("checked_at", 0)
        checked_at = float(raw_checked_at) if isinstance(raw_checked_at, (int, float)) else 0.0
        if now - checked_at > ttl_seconds:
            to_probe.append(host)
            continue
        skipped_count += 1
        alive = bool(cached.get("alive"))
        if not alive:
            continue
        url = normalize_url(str(cached.get("url", "") or ""))
        if not url:
            url = normalize_url(f"https://{host}")
        if not url:
            continue
        cached_records.append(
            {
                "url": url,
                "status_code": cached.get("status_code"),
                "source": "probe-cache",
            }
        )
        cached_live_hosts.add(url)
    return to_probe, cached_records, cached_live_hosts, skipped_count


def _cache_update(
    host: str,
    *,
    alive: bool,
    url: str = "",
    status_code: int | None = None,
    ttl_seconds: int | None = None,
) -> None:
    ttl = ttl_seconds if ttl_seconds is not None else PROBE_CACHE_DEFAULT_TTL_SECONDS
    _probe_cache.set(
        host,
        {
            "checked_at": time.time(),
            "alive": bool(alive),
            "url": normalize_url(url) if url else "",
            "status_code": status_code,
        },
        ttl=ttl,
    )
    try:
        size = _probe_cache.size()
        if _PROBE_CACHE_MAX_SIZE and size > _PROBE_CACHE_MAX_SIZE:
            logger.warning(
                "Probe cache size %d exceeded max %d, running expired cleanup",
                size,
                _PROBE_CACHE_MAX_SIZE,
            )
            _probe_cache.cleanup_expired()
    except Exception as e:
        logger.debug("Failed to perform final probe cache cleanup: %s", e)


def _cache_update_from_batch(
    batch_hosts: list[str],
    batch_records: list[dict[str, Any]],
    batch_live_hosts: set[str],
    ttl_seconds: int | None = None,
) -> None:
    live_by_host: dict[str, tuple[str, int | None]] = {}
    for record in batch_records:
        url = normalize_url(str(record.get("url", "") or ""))
        if not url or url not in batch_live_hosts:
            continue
        host = _host_from_url(url)
        if not host:
            continue
        status_code = record.get("status_code")
        live_by_host[host] = (url, int(status_code) if isinstance(status_code, int) else None)

    for host in batch_hosts:
        if host in live_by_host:
            url, status_code = live_by_host[host]
            _cache_update(
                host, alive=True, url=url, status_code=status_code, ttl_seconds=ttl_seconds
            )
        else:
            _cache_update(host, alive=False, ttl_seconds=ttl_seconds)


def _httpx_batch_plan(hosts: list[str], config: Config) -> tuple[int, int]:
    batch_size = max(100, int(config.httpx.get("batch_size", 400)))
    max_parallel_batches = max(1, int(config.httpx.get("batch_concurrency", 1)))
    if len(hosts) >= 1000:
        max_parallel_batches = max(max_parallel_batches, 2)
    if str(config.mode).lower() == "aggressive":
        max_parallel_batches = max(max_parallel_batches, 2)
    return batch_size, max_parallel_batches


def _resolve_httpx_probe_timeout_seconds(config: Config) -> int:
    raw_probe_timeout = int(
        config.httpx.get("probe_timeout_seconds", max(3, config.http_timeout_seconds))
    )
    return max(1, raw_probe_timeout)


def _resolve_httpx_batch_timeout_seconds(config: Config, batch_host_count: int) -> int:
    configured_timeout = max(1, int(config.httpx.get("timeout_seconds", 120)))
    probe_timeout = _resolve_httpx_probe_timeout_seconds(config)
    threads = max(1, int(config.httpx.get("threads", 80)))
    rounds = max(1, (max(1, batch_host_count) + threads - 1) // threads)
    startup_buffer_seconds = max(
        2,
        int(config.httpx.get("batch_timeout_buffer_seconds", 3)),
    )
    adaptive_timeout = rounds * probe_timeout + startup_buffer_seconds
    return max(configured_timeout, adaptive_timeout)


def _httpx_command(config: Config) -> list[str]:
    command = [
        "httpx",
        "-silent",
        "-json",
        "-threads",
        str(config.httpx.get("threads", 80)),
    ]
    if "-timeout" not in config.httpx.get("extra_args", []):
        command.extend(
            [
                "-timeout",
                str(_resolve_httpx_probe_timeout_seconds(config)),
            ]
        )
    command.extend(config.httpx.get("extra_args", []))
    return command


def _run_httpx_batch(
    batch: list[str], command: list[str], timeout_seconds: int, retry_policy: Any
) -> tuple[list[dict[str, Any]], set[str], dict[str, Any]]:
    outcome = execute_command(
        command,
        timeout=timeout_seconds,
        stdin_text="\n".join(batch) + "\n",
        retry_policy=retry_policy,
    )
    records: list[dict[str, Any]] = []
    live_hosts: set[str] = set()
    for line in outcome.stdout.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("url"):
            record["url"] = normalize_url(record["url"])
            live_hosts.add(record["url"])
        records.append(record)
    status = "ok"
    if outcome.timed_out:
        status = "degraded_timeout"
    elif outcome.fatal:
        status = "error"
    return (
        records,
        live_hosts,
        {
            "status": status,
            "attempt_count": max(1, int(outcome.attempt_count or 1)),
            "configured_timeout_seconds": outcome.configured_timeout_seconds or timeout_seconds,
            "effective_timeout_seconds": outcome.effective_timeout_seconds or timeout_seconds,
            "warning_messages": list(outcome.warning_messages),
            "error_message": outcome.error_message,
        },
    )


def probe_live_hosts(
    subdomains: set[str],
    config: Config,
    progress_callback: Any = None,
    *,
    timeout_seconds: int | None = None,
    force_recheck: bool = False,
    **kwargs: Any,
) -> tuple[list[dict[str, Any]], set[str]]:
    effective_timeout = timeout_seconds or getattr(config, "http_timeout_seconds", 30)
    if str(config.mode).lower() == "safe":
        return probe_live_hosts_fallback(
            subdomains,
            effective_timeout,
            config=config,
            progress_callback=progress_callback,
            force_recheck=force_recheck,
        )

    if config.tools.get("httpx") and projectdiscovery_httpx_available():
        ttl_seconds = _probe_cache_ttl_seconds(config)
        hosts = _normalized_probe_hosts(subdomains)
        if hosts:
            _emit_live_host_progress(
                progress_callback,
                f"live-host preparing {len(hosts)} host candidates",
                36,
                processed=0,
                total=len(hosts),
                stage_percent=0,
            )
        to_probe, records, live_hosts, skipped_count = _cache_lookup(
            hosts, ttl_seconds, force_recheck
        )
        if skipped_count:
            _emit_live_host_progress(
                progress_callback,
                f"live-host cache hit: skipped {skipped_count}/{len(hosts)} hosts",
                36,
                processed=skipped_count,
                total=len(hosts),
                stage_percent=int((skipped_count / max(1, len(hosts))) * 100),
            )

        if not to_probe:
            if hosts and not live_hosts and not force_recheck:
                _emit_live_host_progress(
                    progress_callback,
                    "live-host cache contains no alive entries; forcing one fresh probe pass",
                    36,
                    processed=skipped_count,
                    total=len(hosts),
                    stage_percent=100,
                )
                return probe_live_hosts(
                    subdomains,
                    config,
                    progress_callback,
                    force_recheck=True,
                )
            return records, live_hosts

        batch_size, max_parallel_batches = _httpx_batch_plan(to_probe, config)
        command = _httpx_command(config)
        retry_policy = build_retry_policy(config.tools, config.httpx)
        probe_timeout_seconds = _resolve_httpx_probe_timeout_seconds(config)
        batch_timeout_seconds = _resolve_httpx_batch_timeout_seconds(config, batch_size)
        batches = [
            to_probe[start : start + batch_size] for start in range(0, len(to_probe), batch_size)
        ]
        total_batches = max(1, (len(to_probe) + batch_size - 1) // batch_size)
        parallel_workers = min(max_parallel_batches, len(batches))
        _emit_live_host_progress(
            progress_callback,
            f"live-host probing started: {len(to_probe)} hosts queued across "
            f"{total_batches} batch(es) with concurrency {parallel_workers}",
            37,
            processed=skipped_count,
            total=len(hosts),
            stage_percent=int((skipped_count / max(1, len(hosts))) * 100),
            queued_hosts=len(to_probe),
            total_batches=total_batches,
            batch_size=batch_size,
            concurrency=parallel_workers,
            probe_timeout_seconds=probe_timeout_seconds,
            batch_timeout_seconds=batch_timeout_seconds,
        )
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            future_to_batch: dict[Any, tuple[int, list[str], int]] = {}
            for batch_index, batch_hosts in enumerate(batches, 1):
                resolved_batch_timeout = _resolve_httpx_batch_timeout_seconds(
                    config,
                    len(batch_hosts),
                )
                future = executor.submit(
                    _run_httpx_batch,
                    batch_hosts,
                    command=command,
                    timeout_seconds=resolved_batch_timeout,
                    retry_policy=retry_policy,
                )
                future_to_batch[future] = (
                    batch_index,
                    batch_hosts,
                    resolved_batch_timeout,
                )

            completed_batches = 0
            processed_count = skipped_count
            for future in as_completed(future_to_batch):
                batch_index, batch_hosts, resolved_batch_timeout = future_to_batch[future]
                completed_batches += 1
                processed_count = min(len(hosts), processed_count + len(batch_hosts))
                try:
                    batch_records, batch_live_hosts, batch_meta = future.result()
                except Exception as exc:
                    percent = min(47, 36 + int((completed_batches / total_batches) * 11))
                    _emit_live_host_progress(
                        progress_callback,
                        (
                            f"live-host batch {completed_batches}/{total_batches} "
                            f"(chunk {batch_index}, timeout={resolved_batch_timeout}s) "
                            f"failed: {exc}"
                        ),
                        percent,
                        processed=processed_count,
                        total=len(hosts),
                        stage_percent=int((processed_count / max(1, len(hosts))) * 100),
                    )
                    continue

                before = len(live_hosts)
                records.extend(batch_records)
                live_hosts.update(batch_live_hosts)
                _cache_update_from_batch(
                    batch_hosts, batch_records, batch_live_hosts, ttl_seconds=ttl_seconds
                )
                percent = min(47, 36 + int((completed_batches / total_batches) * 11))
                batch_status = str(batch_meta.get("status", "ok")).strip().lower()
                batch_effective_timeout = int(
                    batch_meta.get("effective_timeout_seconds", resolved_batch_timeout)
                    or resolved_batch_timeout
                )
                batch_note = ""
                if batch_status == "degraded_timeout":
                    batch_note = f", provider timeout degraded at {batch_effective_timeout}s"
                elif batch_status == "error":
                    batch_note = ", provider warning degraded"
                _emit_live_host_progress(
                    progress_callback,
                    f"live-host batch {completed_batches}/{total_batches} "
                    f"(chunk {batch_index}): +{len(live_hosts) - before} live hosts, "
                    f"total {len(live_hosts)}{batch_note}",
                    percent,
                    processed=processed_count,
                    total=len(hosts),
                    stage_percent=int((processed_count / max(1, len(hosts))) * 100),
                )
        if records or live_hosts:
            return records, live_hosts

        return probe_live_hosts_fallback(
            subdomains,
            config.http_timeout_seconds,
            config=config,
            progress_callback=progress_callback,
            force_recheck=force_recheck,
        )

    return probe_live_hosts_fallback(
        subdomains,
        config.http_timeout_seconds,
        config=config,
        progress_callback=progress_callback,
        force_recheck=force_recheck,
    )


def probe_live_hosts_fallback(
    subdomains: set[str],
    timeout_seconds: int,
    config: Config | None = None,
    progress_callback: Any = None,
    *,
    force_recheck: bool = False,
) -> tuple[list[dict[str, Any]], set[str]]:
    hosts = _normalized_probe_hosts(subdomains)
    if not hosts:
        return [], set()

    _emit_live_host_progress(
        progress_callback,
        f"live-host preparing {len(hosts)} host candidates",
        36,
        processed=0,
        total=len(hosts),
        stage_percent=0,
    )

    ttl_seconds = _probe_cache_ttl_seconds(config) if config else PROBE_CACHE_DEFAULT_TTL_SECONDS
    to_probe, records, live_hosts, skipped_count = _cache_lookup(hosts, ttl_seconds, force_recheck)
    if skipped_count:
        _emit_live_host_progress(
            progress_callback,
            f"live-host cache hit: skipped {skipped_count}/{len(hosts)} hosts",
            36,
            processed=skipped_count,
            total=len(hosts),
            stage_percent=int((skipped_count / max(1, len(hosts))) * 100),
        )

    if not to_probe:
        if hosts and not live_hosts and not force_recheck:
            _emit_live_host_progress(
                progress_callback,
                "live-host cache contains no alive entries; forcing one fresh probe pass",
                36,
                processed=skipped_count,
                total=len(hosts),
                stage_percent=100,
            )
            return probe_live_hosts_fallback(
                subdomains,
                timeout_seconds,
                config=config,
                progress_callback=progress_callback,
                force_recheck=True,
            )
        return records, live_hosts

    workers = max(16, min(128, int(config.httpx.get("fallback_threads", 48) if config else 48)))
    batch_size = min(max(workers, 24), max(24, len(to_probe) // 8 or 24))
    total_batches = max(1, (len(to_probe) + batch_size - 1) // batch_size)
    executor_workers = min(workers, len(to_probe))
    _emit_live_host_progress(
        progress_callback,
        f"live-host fallback probing started: {len(to_probe)} hosts queued across "
        f"{total_batches} batch(es) with concurrency {executor_workers}",
        37,
        processed=skipped_count,
        total=len(hosts),
        stage_percent=int((skipped_count / max(1, len(hosts))) * 100),
        queued_hosts=len(to_probe),
        total_batches=total_batches,
        batch_size=batch_size,
        concurrency=executor_workers,
    )

    with ThreadPoolExecutor(max_workers=executor_workers) as executor:
        future_to_host = {
            executor.submit(probe_host_without_httpx, host, timeout_seconds): host
            for host in to_probe
        }
        processed = 0
        current_batch = 0
        batch_hosts: list[str] = []
        batch_records: list[dict[str, Any]] = []
        batch_live: set[str] = set()
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            processed += 1
            batch_hosts.append(host)
            try:
                result = future.result()
            except Exception as e:
                # Fix Audit #21: Lazy string formatting
                logger.warning("Error during host probing for %s: %s", host, e)
                result = None
            if result and result.get("url"):
                observed_url = str(result.get("url", "") or "").strip()
                if observed_url:
                    live_hosts.add(observed_url)
                    batch_live.add(observed_url)
                records.append(result)
                batch_records.append(result)
            if len(batch_hosts) >= batch_size or processed == len(to_probe):
                _cache_update_from_batch(
                    batch_hosts, batch_records, batch_live, ttl_seconds=ttl_seconds
                )
                current_batch += 1
                percent = min(47, 36 + int((current_batch / total_batches) * 11))
                _emit_live_host_progress(
                    progress_callback,
                    f"live-host batch {current_batch}/{total_batches}: total {len(live_hosts)} "
                    f"live hosts after {processed + skipped_count}/{len(hosts)} candidates",
                    percent,
                    processed=processed + skipped_count,
                    total=len(hosts),
                    stage_percent=int(((processed + skipped_count) / max(1, len(hosts))) * 100),
                )
                batch_hosts = []
                batch_records = []
                batch_live = set()
    return records, live_hosts


def probe_host_without_httpx(host: str, timeout_seconds: int) -> dict[str, Any] | None:
    candidates = [host] if "://" in host else [f"https://{host}", f"http://{host}"]
    pool = get_pooled_connection()
    for candidate in candidates:
        try:
            resp = pool.request(
                "GET",
                candidate,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                timeout=urllib3.util.Timeout(connect=timeout_seconds, read=timeout_seconds),
                retries=False,
            )
            return {
                "url": normalize_url(resp.geturl() or candidate),
                "status_code": resp.status,
                "source": "python-probe",
            }
        except urllib3.exceptions.HTTPError:
            continue
    return None
