"""HTTP Smuggling and HTTP2 probe suite runner."""

from __future__ import annotations

from typing import Any


def _run_http_smuggling_suite(
    priority_items: list[dict[str, Any]],
    shared_response_cache: Any,
    limit: int = 10,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    smuggling_findings = probes["http_smuggling_probe"](
        priority_items,
        shared_response_cache,
        limit=limit,
    )
    http2_findings = probes["http2_probe"](
        priority_items,
        shared_response_cache,
        limit=max(1, limit // 2),
    )
    combined = [
        *(
            smuggling_findings
            if isinstance(smuggling_findings, list)
            else ([smuggling_findings] if smuggling_findings else [])
        ),
        *(
            http2_findings
            if isinstance(http2_findings, list)
            else ([http2_findings] if http2_findings else [])
        ),
    ]
    combined.sort(
        key=lambda item: (
            -float(item.get("confidence", 0.0)) if isinstance(item, dict) else 0.0,
            str(item.get("url", "")) if isinstance(item, dict) else "",
        )
    )
    return [item for item in combined if isinstance(item, dict)][:limit]
