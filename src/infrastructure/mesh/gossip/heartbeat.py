from __future__ import annotations

"""Telemetry heartbeat for the gossip mesh.

Collects local hardware telemetry (CPU, RAM) via psutil and refreshes
local node metadata on a polling interval.
"""

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class TelemetryCollector:
    """Periodically refreshes local hardware telemetry."""

    def __init__(self, local_node_ref: Any, interval_sec: float = 5.0):
        self._local_node = local_node_ref
        self._interval = interval_sec
        self._psutil = None

    async def start(self) -> None:
        try:
            import psutil

            self._psutil = psutil
        except ImportError:
            self._psutil = None

        if self._psutil:
            self._psutil.cpu_percent(interval=None)

        await self._run_loop()

    async def _run_loop(self) -> None:
        while True:
            if self._psutil:
                try:
                    self._local_node.cpu_usage = self._psutil.cpu_percent(interval=None)
                    mem = self._psutil.virtual_memory()
                    self._local_node.ram_available_mb = round(mem.available / (1024 * 1024), 2)
                    self._local_node.last_seen = time.time()
                except Exception as exc:
                    logger.debug("Mesh telemetry collection failed: %s", exc)
            await asyncio.sleep(self._interval)
