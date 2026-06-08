"""Mid-flight scope enforcement service.

Validates every URL/host discovered by a tool against the allowed scope
before it enters downstream stages or is passed to active scanners.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field

from src.core.utils import normalize_scope_entry

logger = logging.getLogger(__name__)


@dataclass
class ScopeEnforcer:
    """Enforces scope boundaries on URLs and hosts at runtime."""

    scope_entries: list[str]
    _allowlist: set[str] = field(default_factory=set)
    _wildcard_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for entry in self.scope_entries:
            entry = entry.strip()
            if not entry:
                continue
            normalized = normalize_scope_entry(entry)
            self._allowlist.add(normalized.lower())
            if entry.startswith("*."):
                self._wildcard_patterns.append(entry[2:].lower())
            elif "." in entry:
                self._wildcard_patterns.append(entry.lower())

    def is_in_scope(self, host_or_url: str) -> bool:
        """Check if a hostname or URL is within the allowed scope."""
        from urllib.parse import urlparse

        parsed = urlparse(host_or_url)
        host = (parsed.netloc or parsed.path or host_or_url).split(":")[0].strip().lower()
        if not host:
            return False
        host_clean = host.lower()
        if host_clean in self._allowlist:
            return True
        for pattern in self._wildcard_patterns:
            if host_clean == pattern or host_clean.endswith("." + pattern):
                return True
        try:
            resolved = socket.gethostbyname(host_clean)
            ip = ipaddress.ip_address(resolved)
            for entry in self.scope_entries:
                if "/" in entry:
                    try:
                        net = ipaddress.ip_network(entry.strip(), strict=False)
                        if ip in net:
                            return True
                    except Exception:
                        pass
        except Exception:
            pass
        return False

    async def is_in_scope_async(self, host_or_url: str) -> bool:
        """Async variant that offloads blocking DNS resolution to a thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.is_in_scope, host_or_url)

    def filter_in_scope(self, items: list[str]) -> list[str]:
        """Filter a list of hosts/URLs, keeping only in-scope items."""
        return [item for item in items if self.is_in_scope(item)]

    def validate_or_raise(self, host_or_url: str) -> None:
        """Raise ValueError if the host/URL is out of scope."""
        if not self.is_in_scope(host_or_url):
            raise ValueError(f"Out-of-scope target blocked: {host_or_url}")
