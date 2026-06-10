"""WAF/CDN detection profiles for adaptive backoff tuning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class WafProfile(StrEnum):
    NONE = "none"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    GENERIC = "generic"


@dataclass(frozen=True, slots=True)
class WafTuningProfile:
    """Per-WAF tool-tuning parameters."""

    profile: WafProfile = WafProfile.NONE
    nuclei_rate_limit: int = 150
    nuclei_timeout_seconds: int = 5
    nuclei_retries: int = 2
    httpx_concurrency: int = 150
    recovery_timeout_seconds: float = 60.0
    circuit_breaker_threshold: int = 5
    circuit_breaker_recovery_seconds: float = 60.0

    @classmethod
    def for_profile(cls, profile: WafProfile | str) -> WafTuningProfile:
        p = WafProfile(profile) if not isinstance(profile, WafProfile) else profile
        profiles = {
            WafProfile.NONE: cls(
                profile=WafProfile.NONE,
                nuclei_rate_limit=150,
                nuclei_timeout_seconds=5,
                nuclei_retries=2,
                httpx_concurrency=150,
                recovery_timeout_seconds=60.0,
            ),
            WafProfile.CLOUDFLARE: cls(
                profile=WafProfile.CLOUDFLARE,
                nuclei_rate_limit=10,
                nuclei_timeout_seconds=10,
                nuclei_retries=1,
                httpx_concurrency=10,
                recovery_timeout_seconds=300.0,
                circuit_breaker_threshold=3,
                circuit_breaker_recovery_seconds=300.0,
            ),
            WafProfile.AKAMAI: cls(
                profile=WafProfile.AKAMAI,
                nuclei_rate_limit=30,
                nuclei_timeout_seconds=8,
                nuclei_retries=1,
                httpx_concurrency=30,
                recovery_timeout_seconds=180.0,
                circuit_breaker_threshold=3,
                circuit_breaker_recovery_seconds=180.0,
            ),
            WafProfile.FASTLY: cls(
                profile=WafProfile.FASTLY,
                nuclei_rate_limit=50,
                nuclei_timeout_seconds=7,
                nuclei_retries=1,
                httpx_concurrency=50,
                recovery_timeout_seconds=120.0,
                circuit_breaker_threshold=4,
                circuit_breaker_recovery_seconds=120.0,
            ),
            WafProfile.GENERIC: cls(
                profile=WafProfile.GENERIC,
                nuclei_rate_limit=40,
                nuclei_timeout_seconds=8,
                nuclei_retries=1,
                httpx_concurrency=40,
                recovery_timeout_seconds=120.0,
                circuit_breaker_threshold=4,
                circuit_breaker_recovery_seconds=120.0,
            ),
        }
        return profiles.get(p, cls())

    def to_circuit_breaker_config(self) -> dict[str, Any]:
        return {
            "circuit_breaker_failure_threshold": self.circuit_breaker_threshold,
            "circuit_breaker_recovery_timeout": self.circuit_breaker_recovery_seconds,
        }
