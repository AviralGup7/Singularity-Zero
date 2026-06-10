"""WAF-aware probe adapter.

Wraps the :class:`FastPathDispatcher` to automatically apply WAF
evasion strategies to active probe payloads. The adapter is the
runtime companion to :mod:`src.detection.waf.strategies` — the
strategy factories generate the *candidates*; this module applies
them to outbound requests.

When a :class:`WafProfile` is bound to the adapter, it picks the
appropriate :class:`StrategyBundle` and applies each strategy in
order to the request's URL, body, and headers. The adapter is
deliberately stateless: it does not keep a per-connection payload
history, so a misbehaving strategy cannot leak state between
unrelated requests.

Usage::

    from src.detection.waf.fingerprint import WafFingerprinter
    from src.detection.waf.strategies import strategy_bundle_for
    from src.analysis.fast_path import FastPathDispatcher
    from src.execution.waf_probe_adapter import WafAwareProbeAdapter

    dispatcher = FastPathDispatcher()
    adapter = WafAwareProbeAdapter(dispatcher)
    profile = WafFingerprinter().fingerprint(url)
    adapter.set_strategy_bundle(strategy_bundle_for(profile))
    response = await adapter.dispatch(url, method="POST", body=original)
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class StrategyBundle:
    """A sequence of WAF-evasion strategies to try on a probe.

    The bundle is a *plan* — the adapter walks the strategies in
    order, applying each to the URL/body/headers. The first strategy
    is the least invasive (e.g. unicode normalisation) and the last
    is the most aggressive (e.g. double-encoding). Operators can
    override the order via the ``waf_evasion.strategy_order`` config.
    """

    name: str
    strategies: list[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.strategies


class WafAwareProbeAdapter:
    """Wraps a FastPathDispatcher and applies WAF evasion strategies.

    The adapter does not change the dispatcher's scope-enforcement or
    rate-limiting behaviour — those remain in effect. It only
    mutates the request payload (URL query parameters, body bytes,
    certain headers) to bypass WAF detection rules.

    Operators can configure auto-application of bundles via the
    ``waf_evasion`` config block::

        {
          "waf_evasion": {
            "auto_apply": true,
            "strategy_order": [
              "unicode_normalization",
              "comment_injection",
              "double_encoding"
            ]
          }
        }
    """

    def __init__(self, dispatcher: Any) -> None:
        self._dispatcher = dispatcher
        self._bundle: StrategyBundle | None = None
        self._enabled: bool = False
        self._applications: int = 0
        # Strategy effectiveness tracking: maps strategy __name__ to
        # {"success": int, "failure": int} counts. Used to reorder
        # strategies at runtime based on observed success rates.
        self._strategy_stats: dict[str, dict[str, int]] = {}

    def record_strategy_outcome(self, strategy_name: str, success: bool) -> None:
        """Record whether a strategy succeeded or failed.

        Callers should invoke this after dispatch() when the response
        indicates the payload bypassed WAF detection (success) or was
        blocked (failure).
        """
        if strategy_name not in self._strategy_stats:
            self._strategy_stats[strategy_name] = {"success": 0, "failure": 0}
        key = "success" if success else "failure"
        self._strategy_stats[strategy_name][key] += 1

    def get_strategy_stats(self) -> dict[str, dict[str, int]]:
        """Return the current strategy effectiveness statistics."""
        return dict(self._strategy_stats)

    def get_effective_strategies(self) -> list[str]:
        """Return strategy names sorted by success rate (best first).

        Strategies with fewer than 3 total uses are excluded until
        enough data is collected to avoid skewing results.
        """
        stats = []
        for name, counts in self._strategy_stats.items():
            total = counts["success"] + counts["failure"]
            if total >= 3:
                rate = counts["success"] / total
                stats.append((name, rate))
        stats.sort(key=lambda x: (-x[1], x[0]))
        return [name for name, _ in stats]

    def set_strategy_bundle(self, bundle: StrategyBundle | None) -> None:
        """Bind a strategy bundle to the adapter.

        Passing ``None`` clears the binding and reverts the adapter
        to pass-through mode (no payload mutation).
        """
        self._bundle = bundle
        if bundle is not None and not bundle.is_empty():
            logger.info(
                "WafAwareProbeAdapter: armed with %d strategies from bundle %s",
                len(bundle.strategies),
                bundle.name,
            )

    def enable(self) -> None:
        """Enable auto-application of the bound bundle (if any)."""
        self._enabled = True

    def disable(self) -> None:
        """Disable auto-application. The adapter becomes pass-through
        even if a bundle is bound.
        """
        self._enabled = False

    @property
    def applications(self) -> int:
        """Number of times the adapter has applied a strategy."""
        return self._applications

    async def dispatch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        cache_key: str | None = None,
    ) -> Any:
        """Dispatch a request, applying the bound WAF strategies.

        If the adapter is disabled or no bundle is bound, the call
        is forwarded to the underlying dispatcher unchanged.
        Otherwise the strategies in the bundle are applied to a copy
        of the URL, body, and headers before dispatch.
        """
        if not self._enabled or self._bundle is None or self._bundle.is_empty():
            return await self._dispatcher.dispatch(
                url, method=method, headers=headers, cache_key=cache_key
            )

        mutated_url, mutated_headers, mutated_body = url, headers or {}, body
        for strategy in self._bundle.strategies:
            try:
                mutated_url, mutated_headers, mutated_body = self._apply_strategy(
                    strategy, mutated_url, mutated_headers, mutated_body
                )
                self._applications += 1
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "WafAwareProbeAdapter: strategy %s failed on %s: %s",
                    getattr(strategy, "__name__", strategy),
                    url,
                    exc,
                )
                # Continue with the next strategy; do not abort the probe.
                continue

        return await self._dispatcher.dispatch(
            mutated_url,
            method=method,
            headers=mutated_headers,
            cache_key=cache_key,
        )

    @staticmethod
    def _apply_strategy(
        strategy: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        url: str,
        headers: dict[str, str],
        body: Any,
    ) -> tuple[str, dict[str, str], Any]:
        """Apply a single strategy and return the mutated triple.

        Strategies receive a dict with ``url``, ``headers``, and
        ``body`` and return the same shape. This contract is loose
        enough to allow arbitrary payload mutation but rigid enough
        to keep the adapter deterministic.
        """
        payload = {"url": url, "headers": dict(headers), "body": body}
        out = strategy(payload)
        return (
            str(out.get("url", url)),
            dict(out.get("headers") or {}),
            out.get("body", body),
        )


__all__ = [
    "StrategyBundle",
    "WafAwareProbeAdapter",
]
