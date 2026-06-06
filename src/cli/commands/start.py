"""Cyber Security Test Pipeline - Start area commands (dashboard, worker, launch)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import threading
import time
import uuid
from pathlib import Path

from src.cli.ui import console


def handle_dashboard(args: argparse.Namespace) -> None:
    """Orchestrate the FastAPI dashboard startup."""
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
    from src.infrastructure.queue.worker import main as run_worker

    console.print(
        f"[info]Initializing Distributed Worker on queue: [accent]{args.queue}[/accent][/info]"
    )

    argv = ["--queue", args.queue, "--concurrency", str(args.concurrency)]
    if args.worker_id:
        argv.extend(["--worker-id", args.worker_id])
    if args.replication:
        argv.append("--enable-checkpoint-replication")

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

    static_dir = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if not (static_dir / "index.html").exists():
        console.print(
            "[warning]WARNING: Compiled static frontend assets not detected at frontend/dist.[/warning]"
        )
        console.print(
            "[warning]Please run 'npm run build' inside the 'frontend' directory if the UI loads as a blank page.[/warning]"
        )
    else:
        console.print("[success]Static frontend assets verified.[/success]")

    def run_worker_thread() -> None:
        from src.infrastructure.queue.job_queue import JobQueue
        from src.infrastructure.queue.redis_client import RedisClient
        from src.infrastructure.queue.worker import Worker

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        queue = JobQueue(RedisClient(), args.queue)
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
