"""Token replay safety guardrails (R6).

Wraps the high-risk token replay logic with hard guardrails:
- Requires an explicit ``authorized_replay`` opt-in.
- Skips replay for high-blast-radius locations (referer, response body).
- Enforces per-token-type and per-host replay attempt caps.
- Applies a token-location severity multiplier on findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

UNSAFE_REPLAY_LOCATIONS: frozenset[str] = frozenset(
    {
        "response_body",
        "referer_header",
        "server_log",
        "html_attribute",
    }
)


@dataclass(frozen=True)
class ReplaySafetyConfig:
    """Configuration controlling whether/where token replay is permitted.

    Attributes:
        authorized_replay: Master switch. Must be True to attempt any
            active token replay.
        max_replay_attempts_per_token: Cap on replay attempts per token.
        max_replay_attempts_per_host: Cap on total replay attempts per host.
        skip_replay_for: Tuple of token_location values to skip even when
            authorized. Defaults to the unsafe locations listed in
            ``UNSAFE_REPLAY_LOCATIONS``.
        severity_multiplier_by_location: Mapping of token_location to
            severity multiplier applied to confidence scoring.
    """

    authorized_replay: bool = False
    max_replay_attempts_per_token: int = 3
    max_replay_attempts_per_host: int = 5
    skip_replay_for: tuple[str, ...] = tuple(sorted(UNSAFE_REPLAY_LOCATIONS))
    severity_multiplier_by_location: dict[str, float] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.severity_multiplier_by_location is None:
            object.__setattr__(
                self,
                "severity_multiplier_by_location",
                {
                    "response_body": 1.0,
                    "response_header": 1.05,
                    "html_attribute": 0.95,
                    "javascript_string": 1.0,
                    "url_query": 1.15,
                    "authorization_header": 1.30,
                    "cookie": 1.25,
                    "local_storage": 1.20,
                    "unknown": 1.0,
                },
            )

    def can_replay(self, token_location: str, attempts_used: int) -> bool:
        """Return whether a replay is permitted for the given token location."""
        if not self.authorized_replay:
            return False
        if attempts_used >= self.max_replay_attempts_per_token:
            return False
        if str(token_location or "").strip().lower() in {
            value.lower() for value in self.skip_replay_for
        }:
            return False
        return True

    def severity_for(self, token_location: str) -> float:
        loc = (token_location or "unknown").strip().lower()
        mapping = self.severity_multiplier_by_location or {}
        return float(mapping.get(loc, mapping.get("unknown", 1.0)))


def replay_safety_from_settings(
    validation_settings: dict[str, Any] | None,
) -> ReplaySafetyConfig:
    """Build a ReplaySafetyConfig from raw validation_settings dict."""
    if not validation_settings:
        return ReplaySafetyConfig()
    blackbox = validation_settings.get("extensions", {}).get("blackbox_validation", {})
    replay_cfg = blackbox.get("token_replay_safety", {}) if blackbox else {}
    return ReplaySafetyConfig(
        authorized_replay=bool(replay_cfg.get("authorized_replay", False)),
        max_replay_attempts_per_token=int(replay_cfg.get("max_replay_attempts_per_token", 3)),
        max_replay_attempts_per_host=int(replay_cfg.get("max_replay_attempts_per_host", 5)),
    )
