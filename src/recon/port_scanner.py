"""Naabu port scanner integration for recon pipeline.

Modern bug-bounty recon cannot stop at the HTTP layer. The previous
pipeline only ran ``httpx`` (L7 probing) and Nuclei (HTTP-only
templates) — completely invisible to non-HTTP services such as Redis
on :6379, Elasticsearch on :9200, Docker APIs on :2375, and a long
tail of management interfaces, databases, and dev tooling.

This module wraps :command:`naabu` (ProjectDiscovery) when installed,
and provides a ``socket.connect_ex`` fallback for environments where
naabu is not available. The output is a set of
``host:port`` strings suitable for downstream :func:`probe_live_hosts`
integration or for direct service-fingerprinting.

Both modes are best-effort and never raise. A failed probe contributes
an empty result for that host; the rest of the scan continues.

When ``naabu`` is available, the CLI invocation probes both TCP (``-top-ports``)
and a small UDP set (``-u top-udp-ports:50``) unless the caller opts out via
``top_ports=0`` or supplies their own ``-u`` override in ``extra_args``. Service
version detection (``-sV``) is enabled by default unless overridden in
``extra_args``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor

from src.pipeline.tools import tool_available, try_command
from src.recon.dnsx_wildcard import is_public_ip
from src.recon.domain_validation import normalize_domain

logger = logging.getLogger(__name__)

# Default port list when ``config.naabu.top_ports`` is unset.
# Naabu's built-in ``-top-ports 100`` covers the most common 100 TCP
# services — the same set we use as the fallback. For deeper scans
# operators can raise this to 1000 or 65535 in their config.
DEFAULT_TOP_PORTS = 1000

# Concurrency for the socket fallback path.
_SOCKET_CONCURRENCY = 200

# Hostname validation regex: same shape used elsewhere in the recon
# pipeline (alphanumerics + dash + dot, with at least one dot).
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_portspec(portspec: str) -> list[int]:
    """Parse naabu-style port spec into a deduplicated sorted list of ints.

    Supports:
      * single ports:    "80"
      * comma lists:     "80,443,8080"
      * ranges:          "1-1024"
      * mixed:           "22,80,8000-8999"
    """
    ports: set[int] = set()
    for chunk in (portspec or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                start_s, end_s = chunk.split("-", 1)
                start = int(start_s)
                end = int(end_s)
                if start > end:
                    start, end = end, start
                for p in range(start, end + 1):
                    if 0 < p < 65536:
                        ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(chunk)
                if 0 < p < 65536:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)


def run_naabu_cli(
    hosts: Iterable[str],
    *,
    top_ports: int = DEFAULT_TOP_PORTS,
    extra_args: list[str] | None = None,
    timeout_seconds: int = 600,
) -> set[str]:
    """Run :command:`naabu` against a set of hosts.

    Args:
        hosts: FQDNs or IPs to scan.
        top_ports: Number of top ports to probe (naabu's ``-top-ports``).
            Set to ``0`` to use ``-p -`` (full 1-65535 scan) — only do
            this in authorised offensive engagements.
        extra_args: Additional naabu CLI flags.
        timeout_seconds: Total wall-clock budget for the invocation.

    Returns:
        Set of ``host:port`` strings (one per discovered open port).
        Empty when naabu is not installed.
    """
    if not tool_available("naabu"):
        return set()

    candidate_hosts = [h for h in {h.strip().lower() for h in hosts if h and h.strip()}]
    if not candidate_hosts:
        return set()

    args: list[str] = ["naabu", "-silent", "-nmap-cli", "false", "-warm-up-time", "0"]
    if top_ports and top_ports > 0:
        args.extend(["-top-ports", str(int(top_ports))])
    else:
        args.extend(["-p", "-"])
    if top_ports and top_ports > 0 and not any(str(a).startswith("-u") for a in (extra_args or [])):
        args.extend(["-u", "top-udp-ports:50"])
    if not any(str(a).startswith("-sV") for a in (extra_args or [])):
        args.extend(["-sV"])
    if extra_args:
        args.extend(extra_args)

    output = try_command(
        args,
        timeout=max(1, int(timeout_seconds)),
        stdin_text="\n".join(candidate_hosts) + "\n",
    )
    return _parse_naabu_output(output)


def _parse_naabu_output(output: str) -> set[str]:
    """Parse the naabu ``host:port`` plain-text output."""
    results: set[str] = set()
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        host, _, port_s = line.rpartition(":")
        host = host.strip().lower()
        try:
            port = int(port_s.strip())
        except ValueError:
            continue
        if not host or not (0 < port < 65536):
            continue
        results.add(f"{host}:{port}")
    return results


# ---------------------------------------------------------------------------
# socket.connect_ex fallback
# ---------------------------------------------------------------------------


def _is_scannable_host(host: str) -> bool:
    """Accept hostnames that match the hostname regex or are public IPs."""
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return is_public_ip(host) and not ip.is_reserved
    except ValueError:
        return _HOSTNAME_RE.match(host) is not None


def _socket_probe(host: str, port: int, timeout: float) -> bool:
    """Return True if ``host:port`` accepts a TCP connection within *timeout*."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):  # noqa: UP041 — socket-specific exception
        return False


def _socket_scan_worker(
    host: str,
    ports: list[int],
    timeout: float,
) -> set[str]:
    """Sequentially probe *ports* on a single *host* (used inside a thread)."""
    return {f"{host}:{port}" for port in ports if _socket_probe(host, port, timeout)}


def socket_port_scan(
    hosts: Iterable[str],
    ports: Iterable[int],
    *,
    timeout: float = 1.5,
    max_workers: int = _SOCKET_CONCURRENCY,
) -> set[str]:
    """Fallback port scanner using ``socket.connect_ex``.

    This is dramatically slower than naabu (no SYN scan, no parallelism
    below the host level) but works on stock Python with no extra
    binaries. Useful for tests, very small scopes, or as a last resort.

    Args:
        hosts: FQDNs or IPs to probe.
        ports: TCP ports to test.
        timeout: Per-port timeout in seconds.
        max_workers: Maximum concurrent host scans (each host runs ports
            sequentially to keep concurrency manageable).

    Returns:
        Set of ``host:port`` strings for every open port.
    """
    port_list = sorted({int(p) for p in ports if 0 < int(p) < 65536})
    if not port_list:
        return set()
    host_list = [h for h in {h.strip().lower() for h in hosts if _is_scannable_host(h)}]
    if not host_list:
        return set()

    open_ports: set[str] = set()
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, max(1, len(host_list))))) as ex:
        futures = [
            ex.submit(_socket_scan_worker, host, port_list, timeout) for host in host_list
        ]
        for fut in futures:
            try:
                open_ports.update(fut.result())
            except Exception as exc:  # noqa: BLE001
                logger.debug("socket scan failed for host: %s", exc)
    return open_ports


# ---------------------------------------------------------------------------
# Combined driver
# ---------------------------------------------------------------------------


def run_port_scan(
    hosts: Iterable[str],
    *,
    top_ports: int = DEFAULT_TOP_PORTS,
    extra_args: list[str] | None = None,
    fallback_ports: Iterable[int] | None = None,
    timeout_seconds: int = 600,
) -> set[str]:
    """Run naabu if available, otherwise fall back to a socket probe.

    Args:
        hosts: FQDNs or IPs.
        top_ports: Top-ports argument for naabu.
        extra_args: Additional naabu flags.
        fallback_ports: When naabu is unavailable, probe these TCP
            ports using the socket fallback. Default: 22, 25, 80, 443,
            3306, 5432, 6379, 8000, 8080, 8443, 9200, 27017 — the
            most common "what else is on this host" ports.
        timeout_seconds: Wall-clock budget for the call.

    Returns:
        Set of ``host:port`` strings.
    """
    if tool_available("naabu"):
        return run_naabu_cli(
            hosts,
            top_ports=top_ports,
            extra_args=extra_args,
            timeout_seconds=timeout_seconds,
        )
    if fallback_ports is None:
        fallback_ports = (
            22,
            25,
            80,
            443,
            3000,
            3306,
            5000,
            5432,
            6379,
            8000,
            8080,
            8443,
            8888,
            9200,
            15672,
            27017,
            5699,
            54321,
            55555,
            5985,
            5986,
            11211,
            2049,
            2375,
            2376,
            3389,
            5900,
            5901,
        )
    return socket_port_scan(hosts, fallback_ports)


# ---------------------------------------------------------------------------
# Async wrapper (matches the rest of the recon pipeline's surface)
# ---------------------------------------------------------------------------


async def run_port_scan_async(
    hosts: Iterable[str],
    *,
    top_ports: int = DEFAULT_TOP_PORTS,
    fallback_ports: Iterable[int] | None = None,
    timeout_seconds: int = 600,
) -> set[str]:
    """Async wrapper around :func:`run_port_scan` (offloads to a thread)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: run_port_scan(
            hosts,
            top_ports=top_ports,
            fallback_ports=fallback_ports,
            timeout_seconds=timeout_seconds,
        ),
    )


def host_in_scope(host: str, scope_roots: Iterable[str]) -> bool:
    """Return True if *host* (IP or FQDN) is in any of the *scope_roots*."""
    if not scope_roots:
        return True
    host = (host or "").lower().strip()
    if not host:
        return False
    for root in scope_roots:
        root = normalize_domain(root)
        if not root:
            continue
        if host == root or host.endswith(f".{root}"):
            return True
    return False


__all__ = [
    "DEFAULT_TOP_PORTS",
    "host_in_scope",
    "parse_portspec",
    "run_naabu_cli",
    "run_port_scan",
    "run_port_scan_async",
    "socket_port_scan",
]
