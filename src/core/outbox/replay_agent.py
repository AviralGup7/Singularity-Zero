"""Auto-replay outbox events that never reached a successful dispatch marker.

On READY (and leader change): scan DeliveryLedger poison + DurableDLQ and
re-enqueue with rate-limit. WAL remains authoritative.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.core.frontier.event_delivery import DeliveryLedger, get_delivery_ledger
from src.core.outbox.dlq import DurableDLQ

logger = logging.getLogger(__name__)


@dataclass
class OutboxReplayAgent:
    ledger: DeliveryLedger | None = None
    dlq: DurableDLQ | None = None
    stall_window_seconds: float = 30.0
    max_per_tick: int = 32
    _last_tick: float = field(default=0.0, init=False)
    replayed: int = field(default=0, init=False)

    def tick(
        self,
        *,
        dispatch: Callable[[dict[str, Any]], None] | None = None,
        now: float | None = None,
    ) -> int:
        """Replay stalled / poisoned deliveries. Returns count attempted."""
        ts = time.time() if now is None else float(now)
        ledger = self.ledger or get_delivery_ledger()
        n = 0
        poison = ledger.get_poison_events()
        if self.dlq is not None and poison:
            self.dlq.ingest_poison(poison)
        if dispatch is None:
            return 0
        for did, payload in list(poison.items())[: self.max_per_tick]:
            try:
                dispatch(payload)
                n += 1
            except Exception as exc:
                logger.warning("outbox replay failed delivery_id=%s: %s", did, exc)
        if self.dlq is not None:
            for row in self.dlq.list()[: self.max_per_tick]:
                try:
                    if self.dlq.replay(
                        row.delivery_id,
                        dispatch=lambda rec, emit=dispatch: emit(rec.to_dict()),
                    ):
                        n += 1
                except Exception as exc:
                    logger.warning("durable DLQ replay failed %s: %s", row.delivery_id, exc)
        self.replayed += n
        self._last_tick = ts
        return n


__all__ = ["OutboxReplayAgent"]
