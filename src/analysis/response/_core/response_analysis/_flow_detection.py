"""Flow detection and multi-step flow breaking probes."""

from typing import Any

from src.analysis.helpers import endpoint_base_key, endpoint_signature, is_noise_url
from src.analysis.passive.runtime import ResponseCache
from src.recon.ranking_support import stage_for_url


def flow_detector(urls: set[str]) -> list[dict[str, Any]]:
    """Detect multi-step flows from a set of URLs."""
    from src.recon.ranking_support import build_flow_graph

    cleaned = [raw_url for raw_url in sorted(urls) if not is_noise_url(raw_url)]
    flows = build_flow_graph(cleaned).get("flows", [])
    return list(flows) if isinstance(flows, list) else []


def _flow_stage(url: str) -> int | None:
    return stage_for_url(url)


def multi_step_flow_breaking_probe(
    flow_items: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 12
) -> list[dict[str, Any]]:
    """Test whether later steps in a flow can be accessed directly."""
    findings: list[dict[str, Any]] = []
    for item in flow_items:
        if len(findings) >= limit:
            break
        chain = [str(value).strip() for value in item.get("chain", []) if str(value).strip()]
        if len(chain) < 2:
            continue
        entry_url = chain[0]
        entry_stage = _flow_stage(entry_url) or 0
        for step_index, candidate in enumerate(chain[1:4], start=1):
            direct = response_cache.request(
                candidate,
                headers={"Cache-Control": "no-cache", "Referer": entry_url},
            )
            if not direct:
                continue
            final_url = str(direct.get("final_url") or direct.get("url") or candidate)
            target_stage = _flow_stage(candidate) or step_index
            final_stage = _flow_stage(final_url) or target_stage
            step_skip_possible = (
                int(direct.get("status_code") or 0) < 400 and final_stage >= target_stage
            )
            if not step_skip_possible:
                continue
            findings.append(
                {
                    "url": entry_url,
                    "endpoint_key": endpoint_signature(entry_url),
                    "endpoint_base_key": endpoint_base_key(entry_url),
                    "label": item.get("label", "flow"),
                    "entry_url": entry_url,
                    "skipped_to_url": candidate,
                    "final_url": final_url,
                    "entry_stage": entry_stage,
                    "target_stage": target_stage,
                    "final_stage": final_stage,
                    "status_code": direct.get("status_code"),
                    "step_skip_possible": step_skip_possible,
                    "signals": ["direct_step_access", "flow_break_candidate"],
                }
            )
            break
    findings.sort(key=lambda item: (-item["final_stage"], item["url"]))
    return findings[:limit]
