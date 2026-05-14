from typing import Any
from urllib.parse import urlparse

from src.recon.models import ReconCandidate


def _host_for(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").lower()


def host_candidate(
    host: str, *, source: str, metadata: dict[str, Any] | None = None
) -> ReconCandidate:
    normalized = str(host).strip().lower()
    return ReconCandidate(
        kind="host",
        value=normalized,
        host=normalized,
        url=f"https://{normalized}",
        source=source,
        metadata=metadata or {},
    )


def url_candidate(
    url: str, *, source: str, score: int = 0, metadata: dict[str, Any] | None = None
) -> ReconCandidate:
    normalized = str(url).strip()
    return ReconCandidate(
        kind="url",
        value=normalized,
        host=_host_for(normalized),
        url=normalized,
        source=source,
        score=int(score),
        metadata=metadata or {},
    )


def parameter_candidate(
    name: str, *, source: str, metadata: dict[str, Any] | None = None
) -> ReconCandidate:
    normalized = str(name).strip().lower()
    return ReconCandidate(
        kind="parameter", value=normalized, source=source, metadata=metadata or {}
    )


def standardize_recon_outputs(
    *,
    subdomains: set[str],
    live_hosts: set[str],
    urls: set[str],
    ranked_urls: list[dict[str, Any]],
    parameters: set[str],
) -> list[ReconCandidate]:
    candidates: list[ReconCandidate] = []
    candidates.extend(
        host_candidate(host, source="subdomain_discovery") for host in sorted(subdomains)
    )
    candidates.extend(host_candidate(host, source="live_host_probe") for host in sorted(live_hosts))
    candidates.extend(url_candidate(url, source="url_collection") for url in sorted(urls))
    for item in ranked_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        candidates.append(
            url_candidate(
                url,
                source="url_scoring",
                score=int(item.get("score", 0)),
                metadata={"signals": item.get("signals", [])},
            )
        )
    candidates.extend(
        parameter_candidate(name, source="parameter_extraction") for name in sorted(parameters)
    )
    return candidates
