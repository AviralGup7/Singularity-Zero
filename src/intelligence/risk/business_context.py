"""Business context configuration loader.

Business context describes how the org values each asset and what
kinds of data or compliance regimes the asset touches. It is normally
authored by the security team in a YAML / JSON file and consumed by
``AssetCriticalityService`` and ``CompensatingControlEngine``.

The on-disk shape is::

    business_context:
      version: 1
      hosts:
        - host_patterns: ["api.example.com", "*.api.example.com"]
          asset_type: api
          entity_type: payment_processor
          criticality: 9.0
          tier: tier_1
          has_pii: true
          has_financial: true
          compliance_requirements: ["pci-dss", "soc2"]
      entity_multipliers:
        payment_processor: 1.5
        pii_store: 1.4
        auth_service: 1.3
        ci_cd_pipeline: 1.2
        documentation: 0.7
        static_site: 0.5
      compliance_requirements:
        - pci-dss
        - hipaa
        - gdpr
        - soc2
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


DEFAULT_ENTITY_MULTIPLIERS: dict[str, float] = {
    "payment_processor": 1.5,
    "pii_store": 1.4,
    "auth_service": 1.3,
    "ci_cd_pipeline": 1.2,
    "customer_data": 1.3,
    "internal_admin": 1.1,
    "partner_integration": 1.0,
    "documentation": 0.7,
    "static_site": 0.5,
    "unknown": 1.0,
}


@dataclass
class BusinessContext:
    """Resolved business context for the current run / target."""

    hosts: list[dict[str, Any]] = field(default_factory=list)
    entity_multipliers: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_ENTITY_MULTIPLIERS)
    )
    compliance_requirements: list[str] = field(default_factory=list)
    source_path: str = ""
    version: int = 1

    def get_entity_multiplier(self, entity_type: str) -> float:
        return float(self.entity_multipliers.get(str(entity_type or "unknown").lower(), 1.0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "hosts": list(self.hosts),
            "entity_multipliers": dict(self.entity_multipliers),
            "compliance_requirements": list(self.compliance_requirements),
            "source_path": self.source_path,
        }


class BusinessContextConfig:
    """Loads a ``BusinessContext`` from a JSON config block or file path."""

    @staticmethod
    def from_dict(payload: dict[str, Any], source_path: str = "") -> BusinessContext:
        hosts = list(payload.get("hosts", []) or [])
        entity_multipliers_raw = payload.get("entity_multipliers") or {}
        entity_multipliers = dict(DEFAULT_ENTITY_MULTIPLIERS)
        if isinstance(entity_multipliers_raw, dict):
            for key, value in entity_multipliers_raw.items():
                try:
                    entity_multipliers[str(key).lower()] = float(value)
                except (TypeError, ValueError):
                    continue
        compliance_requirements = [
            str(c).strip().lower()
            for c in (payload.get("compliance_requirements", []) or [])
            if str(c).strip()
        ]
        try:
            version = int(payload.get("version", 1))
        except (TypeError, ValueError):
            version = 1
        return BusinessContext(
            hosts=hosts,
            entity_multipliers=entity_multipliers,
            compliance_requirements=compliance_requirements,
            source_path=source_path,
            version=version,
        )

    @staticmethod
    def from_file(path: str) -> BusinessContext:
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("BusinessContextConfig: failed to load %s: %s", path, exc)
            return BusinessContext(source_path=path)
        if not isinstance(payload, dict):
            return BusinessContext(source_path=path)
        block = payload.get("business_context", payload)
        return BusinessContextConfig.from_dict(block, source_path=path)

    @staticmethod
    def from_pipeline_config(config: dict[str, Any] | None) -> BusinessContext:
        """Extract the business_context block from a full pipeline config."""
        config = config or {}
        block = config.get("business_context")
        if not isinstance(block, dict):
            return BusinessContext()
        return BusinessContextConfig.from_dict(block)


# ---------------------------------------------------------------------------
# Module-level cache
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()
_cached: BusinessContext | None = None
_cached_signature: tuple[str, str] | None = None


def get_default_business_context() -> BusinessContext:
    """Return a cached business context hydrated from env / config files."""
    global _cached, _cached_signature
    with _cache_lock:
        signature = (
            os.environ.get("PIPELINE_BUSINESS_CONTEXT", ""),
            os.environ.get("PIPELINE_CONFIG", ""),
        )
        if _cached is not None and _cached_signature == signature:
            return _cached
        bc = BusinessContext()
        path = os.environ.get("PIPELINE_BUSINESS_CONTEXT")
        if path:
            bc = BusinessContextConfig.from_file(path)
        else:
            cfg_path = os.environ.get("PIPELINE_CONFIG")
            if cfg_path and os.path.exists(cfg_path):
                try:
                    with open(cfg_path, encoding="utf-8") as fh:
                        cfg = json.load(fh)
                    if isinstance(cfg, dict):
                        bc = BusinessContextConfig.from_pipeline_config(cfg)
                except (OSError, json.JSONDecodeError) as exc:
                    logger.debug("BusinessContext: pipeline config read failed: %s", exc)
        _cached = bc
        _cached_signature = signature
        return _cached


def reset_default_business_context() -> None:
    global _cached, _cached_signature
    with _cache_lock:
        _cached = None
        _cached_signature = None


__all__ = [
    "BusinessContext",
    "BusinessContextConfig",
    "DEFAULT_ENTITY_MULTIPLIERS",
    "get_default_business_context",
    "reset_default_business_context",
]
