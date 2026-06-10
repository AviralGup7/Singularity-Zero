"""Ultra-lightweight distributed queue worker for low-resource sub-nodes (like Android Termux).

Runs with zero heavy dependencies (no Pydantic, no Psutil, no Kuzu, no XGBoost).
Requires only the pure-Python 'redis' library.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import sys
import time
import uuid
from pathlib import Path
from typing import Any

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("cyber.worker_lite")

from src.infrastructure.queue.lua_scripts import (
    CLAIM_JOB_SCRIPT,
    COMPLETE_JOB_SCRIPT,
    FAIL_JOB_SCRIPT,
    RELEASE_LEASE_SCRIPT,
)


def _redact_redis_url(url: str) -> str:
    """Return ``url`` with any embedded password replaced by ``***``.

    ``redis://:secret@host:port/0`` becomes ``redis://:***@host:port/0`` so
    that operators can still see the host/port/db while the credential
    is hidden from logs and crash dumps.
    """
    if not url:
        return ""
    try:
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)
        if parsed.password:
            netloc = f"{parsed.username or ''}:***@{parsed.hostname or ''}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urlunparse(parsed._replace(netloc=netloc))
        return url
    except Exception:
        return "<redis-url-redacted>"


def setup_tools(dest_dir: str | None = None) -> None:
    """Download and extract precompiled Go binaries for the detected OS and architecture."""
    import platform
    import shutil
    import tempfile
    import urllib.request
    import zipfile

    sys_plat = sys.platform.lower()
    if sys_plat.startswith("win"):
        os_name = "windows"
    elif sys_plat.startswith("darwin"):
        os_name = "macOS"
    else:
        os_name = "linux"

    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        arch_name = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch_name = "arm64"
    elif machine in ("386", "i386", "i686"):
        arch_name = "386"
    else:
        logger.warning("Unsupported CPU architecture: %s. Defaulting to amd64.", machine)
        arch_name = "amd64"

    if dest_dir is None:
        dest_dir = str(Path.home() / ".local" / "bin")

    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    tools = {
        "subfinder": "2.6.7",
        "httpx": "1.6.8",
        "katana": "1.1.0",
    }

    logger.info("Initializing automated Go tool binary setup...")
    logger.info("Detected OS: %s, Architecture: %s", os_name, arch_name)
    logger.info("Destination folder: %s", dest_path)

    for tool_name, version in tools.items():
        ext = "zip"
        url = f"https://github.com/projectdiscovery/{tool_name}/releases/download/v{version}/{tool_name}_{version}_{os_name}_{arch_name}.{ext}"
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError(f"Invalid URL scheme: {url}")
        bin_name = f"{tool_name}.exe" if os_name == "windows" else tool_name
        tool_dest = dest_path / bin_name

        logger.info("Downloading %s v%s from %s...", tool_name, version, url)
        try:
            req = urllib.request.Request(  # noqa: S310
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    )
                },
            )
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_archive = Path(tmpdir) / "archive.zip"
                with (
                    urllib.request.urlopen(req, timeout=60) as response,  # noqa: S310  # nosec B310  (scheme allowlist checked above)
                    open(tmp_archive, "wb") as out_file,
                ):
                    shutil.copyfileobj(response, out_file)

                # Unpack and resolve binary
                if zipfile.is_zipfile(tmp_archive):
                    with zipfile.ZipFile(tmp_archive) as z:
                        for name in z.namelist():
                            if Path(name).name == bin_name:
                                info = z.getinfo(name)
                                if info.compress_size > 100 * 1024 * 1024:
                                    raise ValueError(
                                        f"Zip entry '{name}' compressed size "
                                        f"({info.compress_size}) exceeds 100 MiB limit"
                                    )
                                if info.file_size > 500 * 1024 * 1024:
                                    raise ValueError(
                                        f"Zip entry '{name}' uncompressed size "
                                        f"({info.file_size}) exceeds 500 MiB limit"
                                    )
                                with z.open(name) as source, open(tool_dest, "wb") as target:
                                    shutil.copyfileobj(source, target)
                                break
                else:
                    raise ValueError("Downloaded file is not a valid zip archive.")

            if not tool_dest.exists():
                raise FileNotFoundError(f"Binary '{bin_name}' not found in the downloaded archive.")

            # Set execution permissions
            if os_name != "windows":
                os.chmod(tool_dest, 0o700)  # nosec B103 noqa: S103
                if not os.access(tool_dest, os.X_OK):
                    logger.warning("Tool %s installed but is not executable", tool_name)

            logger.info("[✓] Successfully installed %s to %s", tool_name, tool_dest)

        except Exception as exc:
            logger.error("[✗] Failed to install %s: %s", tool_name, exc)
            try:
                from src.infrastructure.observability.metrics import get_metrics

                get_metrics().counter(
                    "lite_worker_tool_setup_failures_total", "Total tool setup failures"
                ).inc()
            except Exception:  # noqa: S110
                pass
            raise exc

    logger.info("Go tool binary setup completed successfully!")

    # Check if target dir is in PATH
    path_dirs = [os.path.abspath(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    dest_abs = os.path.abspath(str(dest_path))
    if dest_abs not in path_dirs:
        logger.warning(
            "WARNING: The installation directory '%s' is NOT in your system PATH.", dest_abs
        )
        logger.warning("To use these tools, please add it to your PATH by running:")
        if os_name != "windows":
            logger.warning(
                "  echo 'export PATH=\"$PATH:%s\"' >> ~/.bashrc && source ~/.bashrc", dest_abs
            )
        else:
            logger.warning('  setx PATH "%%PATH%%;%s"', dest_abs)


class LiteWorker:
    """Lite distributed queue worker specializing in running light recon tools."""

    def __init__(
        self,
        worker_id: str,
        redis_url: str,
        queue_name: str = "security-pipeline",
        concurrency: int = 1,
        poll_interval: float = 1.0,
        heartbeat_interval: float = 15.0,
        lease_seconds: float = 300.0,
        capabilities: list[str] | None = None,
        namespace: str = "queue",
    ) -> None:
        self.worker_id = worker_id
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.concurrency = max(1, concurrency)
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.lease_seconds = lease_seconds
        self.capabilities = capabilities or ["recon", "lite"]
        self._namespace = namespace

        self._redis: Any = None
        self._running = False
        self._shutdown_requested = False
        self._active_tasks: set[asyncio.Task[Any]] = set()
        self._started_at = time.time()
        self._total_processed = 0
        self._total_failed = 0
        self._hostname = socket.gethostname()
        self._pid = os.getpid()

        # Lua script SHAs
        self._shas: dict[str, str] = {}

    def _key(self, suffix: str) -> str:
        """Build a namespace-prefixed Redis key matching JobQueueCore conventions."""
        return f"{self._namespace}:{self.queue_name}:{suffix}"

    def _job_key(self, job_id: str) -> str:
        return f"{self._namespace}:{self.queue_name}:job:{job_id}"

    def _setup_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()

        def signal_handler() -> None:
            logger.info("Termination signal received. Initiating graceful shutdown...")
            self._shutdown_requested = True

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, signal_handler)
            except NotImplementedError:
                # Windows fallback
                signal.signal(sig, lambda s, f: signal_handler())

    async def _register(self) -> None:
        """Register worker node identity in Redis."""
        worker_key = self._key(f"worker:{self.worker_id}")
        workers_set = self._key("workers")

        # Build WorkerInfo compatible hash dictionary
        worker_info = {
            "id": self.worker_id,
            "hostname": self._hostname,
            "pid": str(self._pid),
            "status": "idle",
            "concurrency": str(self.concurrency),
            "active_jobs": json.dumps([]),
            "last_heartbeat": str(time.time()),
            "started_at": str(self._started_at),
            "total_processed": str(self._total_processed),
            "total_failed": str(self._total_failed),
            "metadata": json.dumps({"capabilities": self.capabilities, "lite": True}),
            "resources": json.dumps(
                {
                    "cpu_count": 1,
                    "cpu_freq_mhz": 0.0,
                    "total_ram_mb": 1024,
                    "available_ram_mb": 512,
                    "disk_gb_free": 5.0,
                    "platform": sys.platform,
                    "python_version": sys.version.split()[0],
                }
            ),
            "capabilities": json.dumps(self.capabilities),
        }

        # Write to Redis
        await self._redis.hset(worker_key, mapping=worker_info)
        await self._redis.sadd(workers_set, self.worker_id)

        # Register capabilities
        caps_key = self._key(f"worker:{self.worker_id}:capabilities")
        await self._redis.delete(caps_key)
        for cap in self.capabilities:
            await self._redis.sadd(caps_key, cap)
        await self._redis.expire(caps_key, int(self.heartbeat_interval * 5))

        logger.info(
            "LiteWorker registered cleanly (ID=%s, Host=%s, Concurrency=%d)",
            self.worker_id,
            self._hostname,
            self.concurrency,
        )

    async def _heartbeat(self) -> None:
        """Send periodic heartbeats to Redis to prove liveness."""
        worker_key = self._key(f"worker:{self.worker_id}")
        while self._running and not self._shutdown_requested:
            try:
                now = time.time()
                await self._redis.hset(
                    worker_key,
                    mapping={
                        "last_heartbeat": str(now),
                        "status": "busy" if self._active_tasks else "idle",
                        "active_jobs": json.dumps([t.get_name() for t in self._active_tasks]),
                    },
                )
                await self._redis.expire(worker_key, int(self.heartbeat_interval * 5))
                await asyncio.sleep(self.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Heartbeat failed: %s", exc)
                await asyncio.sleep(5.0)  # Faster retry on failure

    async def _execute_recon_command(self, cmd: list[str]) -> list[str]:
        """Execute a tool command safely as a subprocess and capture output lines."""
        # Ensure we look in common local install directories if not in system PATH
        env = os.environ.copy()
        home = os.path.expanduser("~")
        candidate_dirs = [
            os.path.join(home, "bin"),
            os.path.join(home, "go", "bin"),
            os.path.abspath(".tools/bin"),
        ]
        path_sep = os.pathsep
        existing_path = env.get("PATH", "")
        existing_parts = [part for part in existing_path.split(path_sep) if part]
        prepend_dirs = [
            d for d in candidate_dirs if d and d not in existing_parts and os.path.isdir(d)
        ]
        if prepend_dirs:
            env["PATH"] = path_sep.join([*prepend_dirs, existing_path])

        logger.info("Executing subprocess: %s", " ".join(cmd))
        process = await asyncio.create_subprocess_exec(
            cmd[0],
            *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            err_msg = (stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Command failed with code {process.returncode}: {err_msg}")

        output = stdout.decode("utf-8", errors="replace")
        return [line.strip() for line in output.splitlines() if line.strip()]

    async def _process_job(self, job_id: str, job_type: str, payload: dict[str, Any]) -> None:
        """Process a claimed job with clean subprocess execution and error isolation."""
        job_key = self._job_key(job_id)
        worker_jobs_key = self._key(f"worker:{self.worker_id}:jobs")
        metrics_key = self._key("metrics")
        dlq_key = self._key("dead_letter")

        # Update state in Redis to 'running'
        await self._redis.hset(
            job_key,
            mapping={
                "state": "running",
                "started_at": str(time.time()),
                "worker_id": self.worker_id,
            },
        )

        try:
            logger.info("Starting execution for job %s (type=%s)", job_id, job_type)

            # Normalize payload: core.enqueue stores the full TaskEnvelope dict
            # in the "payload" Redis hash field.  The envelope has keys like
            # {"type": ..., "payload": {...}, "metadata": ...}.
            # We extract the inner payload dict for target resolution.
            inner_payload: dict[str, Any] = {}
            if "payload" in payload and isinstance(payload["payload"], dict):
                inner_payload = payload["payload"]
            elif "schema_version" in payload:
                inner_payload = (
                    payload.get("payload", {}) if isinstance(payload.get("payload"), dict) else {}
                )
            else:
                inner_payload = payload

            target = str(
                inner_payload.get("target_name") or inner_payload.get("target") or ""
            ).strip()
            scope_entries = inner_payload.get("scope_entries", [])

            if not target and scope_entries:
                target = scope_entries[0]

            if not target:
                raise ValueError("Job payload is missing a valid target or scope_entries.")

            # Resolve canonical job type (handles legacy aliases)
            from src.infrastructure.queue.plugin_handler_bridge import normalize_job_type

            canonical_type = normalize_job_type(job_type)

            # Route to correct Go scanning tool command
            results = []
            if canonical_type in ("recon_provider.subdomains",) or job_type in (
                "subdomains",
                "subdomain_enum",
            ):
                cmd = ["subfinder", "-d", target, "-silent"]
                results = await self._execute_recon_command(cmd)
            elif canonical_type in ("recon_provider.live_hosts",) or job_type in (
                "live_hosts",
                "port_probe",
            ):
                cmd = ["httpx", "-u", target, "-silent"]
                results = await self._execute_recon_command(cmd)
            elif canonical_type in ("recon_provider.urls",) or job_type in ("urls", "katana"):
                cmd = ["katana", "-u", target, "-silent"]
                results = await self._execute_recon_command(cmd)
            else:
                # Custom/Generic command payload support
                custom_cmd = inner_payload.get("command")
                if isinstance(custom_cmd, list):
                    results = await self._execute_recon_command(custom_cmd)
                else:
                    raise ValueError(
                        f"Job type '{job_type}' (canonical: '{canonical_type}') is not "
                        f"supported by LiteWorker."
                    )

            # Job succeeded! Format output and complete the job.
            result_payload = {"status": "ok", "results": results, "count": len(results)}
            await self._redis.evalsha(
                self._shas["complete_job"],
                3,
                job_key,
                worker_jobs_key,
                metrics_key,
                json.dumps(result_payload),
                str(time.time()),
            )
            self._total_processed += 1
            logger.info("Job %s completed successfully (%d lines returned)", job_id, len(results))

        except Exception as exc:
            # Job failed. Report back cleanly.
            self._total_failed += 1
            error_msg = f"{exc.__class__.__name__}: {exc}"
            logger.error("Job %s failed: %s", job_id, error_msg)

            # Fetch retry count
            retries_str = await self._redis.hget(job_key, "retries") or "0"
            max_retries_str = await self._redis.hget(job_key, "max_retries") or "3"

            await self._redis.evalsha(
                self._shas["fail_job"],
                5,
                job_key,
                worker_jobs_key,
                self._key("queue"),
                dlq_key,
                metrics_key,
                error_msg,
                retries_str,
                max_retries_str,
                str(time.time()),
                "1.0",  # Initial delay
                "2.0",  # Multiplier
                "300.0",  # Max delay
            )

    async def _poll_and_process(self) -> None:
        """Poll Redis queue, atomically claiming jobs using the Lua engine."""
        queue_key = self._key("queue")
        worker_jobs_key = self._key(f"worker:{self.worker_id}:jobs")

        while self._running and not self._shutdown_requested:
            try:
                # Concurrency check
                if len(self._active_tasks) >= self.concurrency:
                    await asyncio.sleep(self.poll_interval)
                    continue

                # Fetch highest-priority pending jobs
                candidates = await self._redis.zrevrange(queue_key, 0, 5)
                if not candidates:
                    await asyncio.sleep(self.poll_interval)
                    continue

                claimed = False
                for candidate in candidates:
                    job_key_str = (
                        candidate.decode("utf-8") if isinstance(candidate, bytes) else candidate
                    )
                    job_id = job_key_str.split(":")[-1]

                    # Attempt to claim job atomically
                    ret = await self._redis.evalsha(
                        self._shas["claim_job"],
                        3,
                        job_key_str,
                        queue_key,
                        worker_jobs_key,
                        self.worker_id,
                        str(self.lease_seconds),
                        str(time.time()),
                    )

                    if ret and int(ret[0]) == 1:
                        # Success! Read job details
                        job_data = await self._redis.hgetall(job_key_str)
                        if job_data:

                            def _decode_redis_value(v: bytes | str) -> str:
                                return (
                                    v.decode("utf-8", errors="replace")
                                    if isinstance(v, bytes)
                                    else str(v)
                                )

                            str_data = {}
                            for k, v in job_data.items():
                                key_str = _decode_redis_value(k)
                                val_str = _decode_redis_value(v)
                                str_data[key_str] = val_str

                            job_type = str_data.get("type", "unknown")
                            try:
                                payload = json.loads(str_data.get("payload", "{}"))
                            except (json.JSONDecodeError, TypeError):
                                logger.warning("Corrupted JSON data, using empty default")
                                payload = {}

                            # Spawn processing task
                            task = asyncio.create_task(
                                self._process_job(job_id, job_type, payload),
                                name=job_id,
                            )
                            self._active_tasks.add(task)
                            task.add_done_callback(self._active_tasks.discard)
                            claimed = True
                            break

                if not claimed:
                    await asyncio.sleep(self.poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Poll loop encountered an error: %s", exc)
                # Adaptive back-off on connection/Redis failures to cool down phone
                await asyncio.sleep(5.0)

    async def _cleanup(self) -> None:
        """Gracefully release job leases and remove worker metadata from Redis."""
        logger.info("Cleaning up worker metadata and active leases...")
        worker_key = self._key(f"worker:{self.worker_id}")
        workers_set = self._key("workers")
        worker_jobs_key = self._key(f"worker:{self.worker_id}:jobs")

        # Release active job leases back to the queue
        active_jobs = list(self._active_tasks)
        for task in active_jobs:
            job_id = task.get_name()
            job_key = self._job_key(job_id)
            try:
                await self._redis.evalsha(
                    self._shas["release_lease"],
                    3,
                    job_key,
                    worker_jobs_key,
                    self._key("queue"),
                )
                logger.info("Released lease for job %s cleanly", job_id)
            except Exception as exc:
                logger.warning("Failed to release lease for job %s: %s", job_id, exc)

        # De-register worker from Redis
        try:
            await self._redis.delete(worker_key)
            await self._redis.srem(workers_set, self.worker_id)
            logger.info("LiteWorker unregistered successfully.")
        except Exception as exc:
            logger.warning("Failed to delete worker keys during cleanup: %s", exc)

    async def start(self) -> None:
        """Start the async event loops for the worker."""
        if self._running:
            return
        self._running = True

        # Initialize Redis via RedisClient for circuit breaker, tenant prefix,
        # and fallback support (fixes Gap 4-B).
        from src.infrastructure.queue.redis_client import RedisClient

        logger.info(
            "Connecting to Redis Backplane at %s",
            _redact_redis_url(self.redis_url),
        )
        self._redis_client = RedisClient(url=self.redis_url)
        # Keep a direct async reference for operations that need it
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(self.redis_url)
        await self._redis.ping()

        # Pre-register Lua scripts and fetch their SHAs (unified with core, Gap 8-C)

        self._shas["claim_job"] = await self._redis.script_load(CLAIM_JOB_SCRIPT)
        self._shas["complete_job"] = await self._redis.script_load(COMPLETE_JOB_SCRIPT)
        self._shas["fail_job"] = await self._redis.script_load(FAIL_JOB_SCRIPT)
        self._shas["release_lease"] = await self._redis.script_load(RELEASE_LEASE_SCRIPT)

        self._setup_signal_handlers()
        await self._register()

        # Start loops
        heartbeat_task = asyncio.create_task(self._heartbeat())
        poll_task = asyncio.create_task(self._poll_and_process())

        try:
            await asyncio.gather(heartbeat_task, poll_task, return_exceptions=True)
        finally:
            heartbeat_task.cancel()
            poll_task.cancel()
            await self._cleanup()
            await self._redis.aclose()
            if hasattr(self, "_redis_client"):
                self._redis_client.close()
            self._running = False
            logger.info("LiteWorker stopped cleanly.")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for the lite worker."""
    parser = argparse.ArgumentParser(description="Singularity-Zero Lightweight Distributed Worker")
    parser.add_argument(
        "--redis-url", default=os.getenv("REDIS_URL", "redis://localhost:6379/0"), help="Redis URL"
    )
    parser.add_argument("--queue", default="security-pipeline", help="Target queue name")
    parser.add_argument("--concurrency", type=int, default=1, help="Parallel job slots")
    parser.add_argument("--worker-id", default=None, help="Worker ID (defaults to UUID)")
    parser.add_argument(
        "--capabilities",
        nargs="*",
        default=["recon", "lite"],
        help="Worker capabilities",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Download and set up precompiled Go binaries automatically",
    )
    parser.add_argument(
        "--setup-dir",
        default=None,
        help="Custom directory to install the Go binaries (defaults to $HOME/bin)",
    )
    args = parser.parse_args(argv)

    if args.setup:
        try:
            setup_tools(args.setup_dir)
            sys.exit(0)
        except Exception as exc:
            logger.error("Setup failed: %s", exc)
            sys.exit(1)

    worker_id = args.worker_id or f"lite-worker-{uuid.uuid4().hex[:6]}"

    worker = LiteWorker(
        worker_id=worker_id,
        redis_url=args.redis_url,
        queue_name=args.queue,
        concurrency=args.concurrency,
        capabilities=args.capabilities,
    )

    async def _run() -> None:
        try:
            await worker.start()
        except Exception as exc:
            logger.exception("Fatal runtime error: %s", exc)
            sys.exit(1)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        logger.info("LiteWorker execution aborted by user.")


if __name__ == "__main__":
    main()
