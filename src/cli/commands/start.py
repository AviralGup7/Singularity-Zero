"""Cyber Security Test Pipeline - Start area commands (dashboard, worker, launch)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from src.cli.ui import console

_FRONTEND_SRC = Path(__file__).resolve().parents[2] / "frontend"
_FRONTEND_DIST = _FRONTEND_SRC / "dist"
_FRONTEND_INDEX = _FRONTEND_DIST / "index.html"
_SENTINEL_SOURCE = _FRONTEND_SRC / "src" / "components" / "targets" / "ImportModal.tsx"


def _ensure_frontend_built() -> bool:
    """Ensure frontend/dist matches frontend/src. Run ``npm run build`` if stale or missing."""
    needs_build = not _FRONTEND_INDEX.exists() or (
        _SENTINEL_SOURCE.exists()
        and _SENTINEL_SOURCE.stat().st_mtime > _FRONTEND_INDEX.stat().st_mtime
    )
    if not needs_build:
        return True

    npm = shutil.which("npm")
    node = shutil.which("node")
    if npm is None or node is None:
        console.print(
            "[error]ERROR: npm/node not found on PATH.[/error] "
            "The dashboard serves compiled assets from frontend/dist/, but they are missing or stale. "
            "Please run: cd frontend && npm install && npm run build"
        )
        return False

    console.print("[info]Frontend assets stale or missing. Running npm run build...[/info]")
    try:
        result = subprocess.run(
            [npm, "run", "build"],
            cwd=str(_FRONTEND_SRC),
            capture_output=True,
            text=True,
            shell=False,
            timeout=300,
        )
    except FileNotFoundError:
        console.print(
            "[error]ERROR: npm not found.[/error] "
            "Please run: cd frontend && npm install && npm run build"
        )
        return False
    except subprocess.TimeoutExpired:
        console.print("[error]ERROR: npm run build timed out after 300s.[/error]")
        return False

    if result.returncode != 0:
        console.print(f"[error]ERROR: npm run build failed (exit {result.returncode}).[/error]")
        if result.stderr:
            console.print(f"[dim]{result.stderr.strip()}[/dim]")
        console.print("Please run: cd frontend && npm install && npm run build")
        return False

    if not _FRONTEND_INDEX.exists():
        console.print(
            "[error]ERROR: Build completed but frontend/dist/index.html is still missing.[/error]"
        )
        return False

    console.print("[success]Frontend build complete.[/success]")
    return True


def handle_dashboard(args: argparse.Namespace) -> None:
    """Orchestrate the FastAPI dashboard startup."""
    if not _ensure_frontend_built():
        sys.exit(1)

    from src.dashboard.fastapi.main import main as run_server

    console.print(
        f"[info]Starting Cyber Dashboard on {args.host}:{args.port} with {args.workers} workers...[/info]"
    )

    argv = [
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--workers",
        str(args.workers),
        "--log-level",
        args.log_level.lower(),
    ]
    if args.reload:
        argv.append("--reload")

    run_server(argv)


def handle_worker(args: argparse.Namespace) -> None:
    """Orchestrate the distributed worker startup."""
    from src.infrastructure.queue.worker_lite import main as run_worker

    console.print(
        f"[info]Initializing Distributed Worker on queue: [accent]{args.queue}[/accent][/info]"
    )

    argv = ["--queue", args.queue, "--concurrency", str(args.concurrency)]
    if args.worker_id:
        argv.extend(["--worker-id", args.worker_id])

    run_worker(argv)


def handle_launch(args: argparse.Namespace) -> None:
    """Orchestrate starting both the dashboard and background queue worker in a single command."""
    from src.dashboard.fastapi.main import main as run_server

    console.print(
        "[accent]██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████[/accent]"
    )
    console.print("[accent]███             Unified Local Launcher Engine              ███[/accent]")
    console.print(
        "[accent]██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████[/accent]"
    )

    if not _ensure_frontend_built():
        return

    console.print("[success]Static frontend assets verified.[/success]")

    def run_worker_thread() -> None:
        from src.infrastructure.queue.job_queue import JobQueue
        from src.infrastructure.queue.plugin_handler_bridge import (
            register_all_plugin_handlers,
        )
        from src.infrastructure.queue.redis_client import RedisClient
        from src.infrastructure.queue.worker import Worker

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        queue = JobQueue(RedisClient(), args.queue)
        register_all_plugin_handlers(queue)

        worker_id = f"launch-worker-{uuid.uuid4().hex[:6]}"
        worker = Worker(
            worker_id=worker_id,
            queue=queue,
            concurrency=args.concurrency,
        )

        async def _run() -> None:
            try:
                await worker.start()
            except Exception as e:
                logging.getLogger("cyber").error(f"Worker execution error: {e}")
            finally:
                await worker.stop()

        try:
            loop.run_until_complete(_run())
        except Exception as e:
            logging.getLogger("cyber").error(f"Worker event loop error: {e}")
        finally:
            loop.close()

    console.print(
        f"[info]Initializing background Worker (concurrency: {args.concurrency}) on queue: [accent]{args.queue}[/accent]...[/info]"
    )
    worker_thread = threading.Thread(target=run_worker_thread, daemon=True)
    worker_thread.start()

    time.sleep(0.5)

    console.print(f"[info]Starting Cyber Dashboard on {args.host}:{args.port}...[/info]")

    argv = [
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--workers",
        "1",
    ]
    run_server(argv)
