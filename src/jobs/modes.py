"""Scan modes understood by the job domain."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanMode:
    key: str
    label: str
    default_modules: tuple[str, ...]
    detector_mode: str
    description: str


MODES: tuple[ScanMode, ...] = (
    ScanMode(
        "standard",
        "Standard",
        ("recon", "passive", "active"),
        "standard",
        "Balanced recon + active",
    ),
    ScanMode("idor", "IDOR hunt", ("recon", "access"), "idor", "Access-control focused"),
    ScanMode("ssrf", "SSRF hunt", ("recon", "active"), "ssrf", "Outbound request abuse"),
    ScanMode("xss", "XSS hunt", ("recon", "passive", "active"), "xss", "Injection in HTML/JS"),
    ScanMode("sqli", "SQLi hunt", ("recon", "active"), "sqli", "Injection in queries"),
    ScanMode("api", "API hunt", ("recon", "passive", "active"), "api", "REST/GraphQL/gRPC"),
    ScanMode(
        "full", "Full", ("recon", "passive", "active", "nuclei"), "full", "Everything enabled"
    ),
    ScanMode("passive-only", "Passive", ("recon", "passive"), "standard", "No active probes"),
)


def get_mode(key: str) -> ScanMode:
    needle = str(key or "standard").strip().lower()
    for mode in MODES:
        if mode.key == needle:
            return mode
    return MODES[0]


def mode_keys() -> tuple[str, ...]:
    return tuple(mode.key for mode in MODES)
