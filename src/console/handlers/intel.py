"""Intel lookup/seed through the console channel."""

from __future__ import annotations

from typing import Any

from src.console.context import RequestContext
from src.integration.errors import bad_request
from src.intel.aggregator import unavailable_feeds
from src.intel.ioc import extract_indicators


def handle_lookup(ctx: RequestContext) -> dict[str, Any]:
    value = ctx.query.get("q") or ctx.query.get("value") or ctx.payload.get("value") or ctx.payload.get("q")
    text = ctx.payload.get("text")
    if text:
        indicators = extract_indicators(text)
        results = [ctx.runtime.intel.lookup(item).to_dict() for item in indicators]
        return {"results": results, "unavailable": list(unavailable_feeds()), "count": len(results)}
    if not value:
        raise bad_request("value or text required")
    result = ctx.runtime.intel.lookup(value)
    return {"result": result.to_dict(), "unavailable": list(unavailable_feeds())}


def handle_seed(ctx: RequestContext) -> dict[str, Any]:
    if not ctx.payload.get("value") and not ctx.payload.get("indicator"):
        raise bad_request("indicator value required")
    ctx.runtime.intel.seed_from_mapping(ctx.payload)
    value = ctx.payload.get("value") or ctx.payload.get("indicator")
    return {"result": ctx.runtime.intel.lookup(str(value)).to_dict()}
