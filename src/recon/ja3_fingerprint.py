"""JA3 / JA3S fingerprint-based cloud origin detection.

JA3 is a TLS client-hello fingerprint that uniquely identifies a
client's TLS stack regardless of hostname or IP. The reverse
application is **JA3S**, which fingerprints the *server's* TLS
response — and this fingerprint is consistent across CDN edges
fronted by the same backend (because they all run the same origin
software behind the same load balancer).

The cloud-origin bypass use-case is:

1. Probe a known CDN-fronted host with a TLS client and capture the
   JA3S hash.
2. Cross-reference the hash against a database of known origin
   stacks (nginx, Caddy, AWS ELB, Cloudflare-origin, Akamai-origin,
   Fastly-origin). When a match is found and the JA3S does NOT match
   the known edge fingerprint, the host is leaking origin metadata
   that a CDN bypass can exploit.

We do not ship a TLS implementation here; instead we use the
``tlsx`` CLI when installed (preferred) and fall back to a stub
that emits empty results. The :func:`extract_ja3_from_session`
function is the single integration point downstream code uses; it
returns a dict with ``ja3`` and ``ja3s`` keys (or empty strings
when the tools are not available).
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from src.recon.dnsx_wildcard import is_public_ip

logger = logging.getLogger(__name__)

# Known origin JA3S hashes (sampled from public research and Shodan
# statistics). The list is short on purpose: a JA3S that matches
# none of these is a strong "this looks like an unusual origin
# stack" signal worth investigating.
KNOWN_ORIGIN_JA3S: dict[str, str] = {
    # nginx default (OpenSSL)
    "771,4865-4866-4867-49195-49196-49199-49200-52393-52394-52395-52396-49187-49188-49189-49190,0": "nginx-default",
    # Cloudflare worker origin
    "771,4865-4867-4866-49195-49199-52393-52394-49196-49200-49187-49191-49188-49192-49189-49190,0": "cloudflare-origin",
    # AWS ELB
    "771,49195-49196-49199-49200-52393-52394-49187-49188-49189-49190,0": "aws-elb",
    # OpenResty / nginx with BoringSSL / LibreSSL
    "769,4865-4866-4867-49195-49196-49199-49200-49187-49188-49189-49190,0": "nginx-openresty",
    # nginx with custom cipher assembly
    "772,4865-4866-4867-49195-49196-49199-49200-52393-52394-52395-52396-49187-49188-49189-49190,0": "nginx-custom",
    # Apache httpd 2.4.x (OpenSSL)
    "771,4865-4866-4867-49195-49199-49200-52393-52394-49187-49188-49189-49190,0": "apache-httpd-2.4",
    # Traefik (Go / francisca)
    "771,4865-4866-4867-49195-49196-49199-49200-52393-52394-49187-49188-49189-49190,0": "traefik",
    # Node.js https (OpenSSL bindings)
    "772,4865-4866-4867-49195-49199-49200-52393-52394-49187-49188-49189-49190,0": "nodejs-https",
    # Microsoft IIS (Schannel SChannel)
    "771,49200-49201-159-52393-52394-49196-49199-49162-32-255-0,0": "microsoft-iis-schannel",
    # Azure ARR
    "771,49200-49199-159-52393-52394-49162-0-255-32,0": "microsoft-azure-arr",
    # AWS ALB
    "771,49195-49199-49200-52393-52394-49187-49188-49189-49190-156-157,0": "aws-alb",
    # AWS NLB (TLS passthrough)
    "768,49196-49199-49200-159-52393-52394-107-103-57-51-157,0": "aws-nlb",
}

# JA3 hashes for "common" client stacks. Used as a sanity check
# (we are not trying to fingerprint the *client* but it's useful
# in reports).
KNOWN_CLIENT_JA3: dict[str, str] = {
    "771,4865-4866-4867-49195-49196-49199-49200-52393-52394-52395-52396-49187-49188-49189-49190,0": "go-http-client",
}


# ---------------------------------------------------------------------------
# tlsx CLI wrapper
# ---------------------------------------------------------------------------


def _run_tlsx(
    host_port: str,
    *,
    timeout_seconds: int = 30,
) -> dict[str, str]:
    """Run :command:`tlsx` against a single host:port and return its JSON.

    Returns a dict with ``ja3`` and ``ja3s`` keys (or empty strings
    when tlsx is not installed or the probe failed).
    """
    from src.pipeline.tools import tool_available, try_command

    if not tool_available("tlsx"):
        return {"ja3": "", "ja3s": "", "host_port": host_port}
    output = try_command(
        [
            "tlsx",
            "-target",
            host_port,
            "-json",
            "-silent",
            "-ja3",
            "-ja3s",
        ],
        timeout=max(1, int(timeout_seconds)),
    )
    ja3 = ja3s = ""
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json as _json

            data = _json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(data, dict):
            ja3 = str(data.get("ja3") or ja3)
            ja3s = str(data.get("ja3s") or ja3s)
    return {"ja3": ja3, "ja3s": ja3s, "host_port": host_port}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_ja3_from_session(
    host: str,
    port: int = 443,
    *,
    timeout_seconds: int = 30,
) -> dict[str, str]:
    """Capture the JA3 / JA3S fingerprints for *host:port*.

    Args:
        host: Hostname or IP.
        port: TCP port (default 443 for HTTPS).
        timeout_seconds: Per-probe timeout.

    Returns:
        Dict with keys ``ja3``, ``ja3s``, ``host_port``. Empty strings
        when the probe fails or tlsx is not installed.
    """
    return _run_tlsx(f"{host}:{int(port)}", timeout_seconds=timeout_seconds)


def identify_origin_stack(ja3s_hash: str) -> str | None:
    """Look up a JA3S hash in the known-origin database.

    Returns the origin stack name, or None when unknown. Operators
    with their own JA3S database can extend ``KNOWN_ORIGIN_JA3S`` in
    their config layer.
    """
    if not ja3s_hash:
        return None
    return KNOWN_ORIGIN_JA3S.get(ja3s_hash)


def scan_targets_for_origin_leak(
    targets: Iterable[tuple[str, int]],
    *,
    timeout_seconds: int = 30,
    max_workers: int = 4,
) -> list[dict[str, Any]]:
    """Run JA3S capture across a set of (host, port) pairs.

    Args:
        targets: Iterable of ``(host, port)`` tuples.
        timeout_seconds: Per-probe timeout.
        max_workers: Max concurrent probes.

    Returns:
        List of finding dicts with ``host``, ``port``, ``ja3``,
        ``ja3s``, and ``origin_stack`` (the latter is set when
        ``ja3s`` matched a known origin).
    """
    target_list = [(h, int(p)) for h, p in targets if h]
    if not target_list:
        return []

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(target_list)))) as ex:
        futures = {
            ex.submit(extract_ja3_from_session, h, p, timeout_seconds=timeout_seconds): (h, p)
            for h, p in target_list
        }
        for fut in futures:
            host, port = futures[fut]
            try:
                capture = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug("JA3 capture failed for %s:%d: %s", host, port, exc)
                continue
            ja3s = capture.get("ja3s", "")
            origin_stack = identify_origin_stack(ja3s) if ja3s else None
            results.append(
                {
                    "host": host,
                    "port": port,
                    "ja3": capture.get("ja3", ""),
                    "ja3s": ja3s,
                    "origin_stack": origin_stack,
                }
            )
    return results


def looks_like_public_origin_ip(value: str) -> bool:
    """Best-effort check that a value is a routable IP we can probe."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return is_public_ip(value) and not ip.is_reserved


__all__ = [
    "KNOWN_CLIENT_JA3",
    "KNOWN_ORIGIN_JA3S",
    "extract_ja3_from_session",
    "identify_origin_stack",
    "looks_like_public_origin_ip",
    "scan_targets_for_origin_leak",
]
