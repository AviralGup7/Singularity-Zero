"""Hidden Parameter Mining.

Performs Arjun-style active parameter discovery on high-priority endpoints
to find hidden inputs like ?debug=1, ?admin=true, or ?test=true using
common wordlists.
"""

import logging
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from src.analysis.helpers import classify_endpoint, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

logger = logging.getLogger(__name__)

# Common hidden parameter wordlist
HIDDEN_PARAMS = [
    "debug",
    "admin",
    "test",
    "dev",
    "role",
    "user",
    "id",
    "token",
    "secret",
    "config",
    "env",
    "dir",
    "file",
    "path",
    "url",
    "redirect",
    "next",
    "callback",
    "return",
    "access",
    "bypass",
    "auth",
    "force",
]


def param_mining_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 10
) -> list[dict[str, Any]]:
    """Actively discover hidden parameters on high priority endpoints.

    Args:
        priority_urls: List of priority URL metadata.
        response_cache: Cache instance for making requests.
        limit: Max findings.

    Returns:
        List of hidden parameter findings.
    """
    findings = []
    seen = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        # Establish baseline response
        base_resp = response_cache.request(url, method="GET")
        if not base_resp:
            continue
        base_status = base_resp.get("status_code", 0)
        base_len = len(base_resp.get("body_text", "") or "")

        # Try chunked parameter injection to save requests (Arjun-style)
        chunk_size = 5
        discovered_params = []

        parsed = urlparse(url)
        existing_params = set(k for k, v in parse_qsl(parsed.query))
        test_params = [p for p in HIDDEN_PARAMS if p not in existing_params]

        for i in range(0, len(test_params), chunk_size):
            chunk = test_params[i : i + chunk_size]
            query_dict = {p: "1" for p in chunk}
            test_query = urlencode(query_dict)
            sep = "&" if parsed.query else "?"
            test_url = f"{url}{sep}{test_query}"

            test_resp = response_cache.request(test_url, method="GET")
            if not test_resp:
                continue

            test_status = test_resp.get("status_code", 0)
            test_len = len(test_resp.get("body_text", "") or "")

            # Simple heuristic for behavior change
            if test_status != base_status or abs(test_len - base_len) > 100:
                # Behavior changed, drill down to identify which parameter caused it
                for p in chunk:
                    drill_query = urlencode({p: "1"})
                    drill_url = f"{url}{sep}{drill_query}"
                    drill_resp = response_cache.request(drill_url, method="GET")
                    if drill_resp:
                        d_status = drill_resp.get("status_code", 0)
                        d_len = len(drill_resp.get("body_text", "") or "")
                        if d_status != base_status or abs(d_len - base_len) > 100:
                            discovered_params.append(p)

        if discovered_params:
            seen.add(endpoint_key)
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_type": classify_endpoint(url),
                    "category": "hidden_parameter",
                    "title": f"Hidden parameters discovered on {url}",
                    "severity": "medium",
                    "confidence": 0.8,
                    "score": 60,
                    "signals": ["hidden_parameters_discovered"],
                    "evidence": {"discovered_parameters": discovered_params},
                    "explanation": f"Active probing discovered {len(discovered_params)} hidden parameter(s) ({', '.join(discovered_params)}) that alter the endpoint's behavior.",
                }
            )

    findings.sort(key=lambda item: (-item.get("score", 0), item.get("url", "")))
    return findings
