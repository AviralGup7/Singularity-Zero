"""Asset registry, criticality tiers, and target context normalization.

Findings traditionally know almost nothing about the asset they live on
beyond a hostname. This module introduces a small, dependency-free
asset registry that:

* Stores an ``Asset`` record per logical service (payment API, docs
  site, internal admin tool, ...).
* Tracks ``criticality`` as a 1-10 score and a coarser ``tier`` label
  (``tier_1`` ... ``tier_4``) for org-level aggregation.
* Tracks ``asset_type`` (api, web, mobile_backend, iot_gateway, ...)
  so per-asset calibration in the ML layer can be implemented without
  schema rewrites.
* Normalises business signals (PII, payment, auth, compliance,
  crown_jewel) into a multi-dimensional context dict that
  ``risk_score_engine`` and ``severity_model`` consume.
* Provides a thread-safe in-memory registry that can be hydrated from
  a JSON file or the telemetry ``assets`` table.

The registry is deliberately SQLite-free. Persistence is the job of
``src.learning.repositories.asset_repo``. The runtime layer just needs
fast synchronous access.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tiers
# ---------------------------------------------------------------------------

# Tier multipliers used by ``AssetCriticalityService``. Tunable via
# configuration; the defaults are conservative enterprise norms.
DEFAULT_TIER_MULTIPLIERS: dict[str, float] = {
    "tier_1": 10.0,
    "tier_2": 5.0,
    "tier_3": 2.0,
    "tier_4": 1.0,
}

# Asset types that the pipeline emits. Kept in one place so the ML
# layer, the UI, and the registry agree on the vocabulary.
KNOWN_ASSET_TYPES: tuple[str, ...] = (
    "api",
    "web",
    "mobile_backend",
    "iot_gateway",
    "ci_cd_pipeline",
    "internal_tool",
    "auth_service",
    "payment_processor",
    "pii_store",
    "documentation",
    "static_site",
    "cdn",
    "unknown",
)

# Business entity types. ``entity_type`` is the second axis of business
# context (along with ``asset_type``) and drives the business-context
# multiplier in scoring.
KNOWN_ENTITY_TYPES: tuple[str, ...] = (
    "payment_processor",
    "pii_store",
    "auth_service",
    "ci_cd_pipeline",
    "customer_data",
    "internal_admin",
    "partner_integration",
    "documentation",
    "static_site",
    "unknown",
)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, float(value)))


@dataclass
class Asset:
    """A logical asset that findings target.

    The registry is keyed on ``asset_id`` but matches inbound findings
    via either the host or the host:path-prefix tuple. A finding whose
    URL matches a registered pattern is automatically associated with
    the asset via ``AssetRegistry.lookup``.
    """

    asset_id: str
    name: str
    host_pattern: str  # glob, e.g. "api.*.example.com" or "docs.example.com"
    path_prefix: str = ""
    asset_type: str = "unknown"
    entity_type: str = "unknown"
    criticality: float = 1.0
    tier: str = "tier_4"
    business_value: float = 1.0
    compliance_requirements: list[str] = field(default_factory=list)
    owner: str = ""
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalise numeric fields and keep tier/criticality in sync.
        try:
            self.criticality = _clamp(self.criticality, 0.0, 10.0)
        except (TypeError, ValueError):
            self.criticality = 1.0
        try:
            self.business_value = _clamp(self.business_value, 0.0, 10.0)
        except (TypeError, ValueError):
            self.business_value = 1.0
        if self.asset_type not in KNOWN_ASSET_TYPES:
            self.asset_type = "unknown"
        if self.entity_type not in KNOWN_ENTITY_TYPES:
            self.entity_type = "unknown"
        if self.tier not in DEFAULT_TIER_MULTIPLIERS:
            self.tier = self._tier_for_criticality(self.criticality)

    @staticmethod
    def _tier_for_criticality(criticality: float) -> str:
        if criticality >= 8.0:
            return "tier_1"
        if criticality >= 6.0:
            return "tier_2"
        if criticality >= 3.0:
            return "tier_3"
        return "tier_4"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Asset:
        return cls(
            asset_id=str(payload.get("asset_id", "")).strip() or "unknown",
            name=str(payload.get("name", "")).strip(),
            host_pattern=str(payload.get("host_pattern", "")).strip().lower(),
            path_prefix=str(payload.get("path_prefix", "")).strip(),
            asset_type=str(payload.get("asset_type", "unknown")).strip().lower(),
            entity_type=str(payload.get("entity_type", "unknown")).strip().lower(),
            criticality=float(payload.get("criticality", 1.0) or 1.0),
            tier=str(payload.get("tier", "tier_4")),
            business_value=float(payload.get("business_value", 1.0) or 1.0),
            compliance_requirements=list(payload.get("compliance_requirements", []) or []),
            owner=str(payload.get("owner", "")),
            notes=str(payload.get("notes", "")),
            metadata=dict(payload.get("metadata", {}) or {}),
        )


class AssetRegistry:
    """Thread-safe in-memory registry of ``Asset`` records.

    Lookup semantics:
      * ``lookup(host)`` returns the best-match asset for a hostname.
      * ``lookup(url)`` first parses the URL and matches on host
        glob, then on optional ``path_prefix``.
      * The first registered asset whose host pattern matches wins.
        More specific patterns (with path_prefix) should be
        registered before broader catch-all patterns.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._assets: list[Asset] = []

    # -- mutations -------------------------------------------------------

    def add(self, asset: Asset) -> None:
        with self._lock:
            # Replace if the asset_id is already known.
            self._assets = [a for a in self._assets if a.asset_id != asset.asset_id]
            self._assets.append(asset)

    def add_many(self, assets: Iterable[Asset]) -> None:
        for asset in assets:
            self.add(asset)

    def remove(self, asset_id: str) -> None:
        with self._lock:
            self._assets = [a for a in self._assets if a.asset_id != asset_id]

    def clear(self) -> None:
        with self._lock:
            self._assets = []

    # -- accessors -------------------------------------------------------

    def all(self) -> list[Asset]:
        with self._lock:
            return list(self._assets)

    def get(self, asset_id: str) -> Asset | None:
        with self._lock:
            for asset in self._assets:
                if asset.asset_id == asset_id:
                    return asset
        return None

    def lookup(self, host_or_url: str) -> Asset | None:
        """Find the best asset for a host or full URL string."""
        host, path = _parse_host_path(str(host_or_url or ""))
        if not host:
            return None
        with self._lock:
            # Prefer matches that also have a path_prefix.
            best_with_path: Asset | None = None
            best_any: Asset | None = None
            for asset in self._assets:
                if not _host_matches(asset.host_pattern, host):
                    continue
                if asset.path_prefix and path.startswith(asset.path_prefix):
                    if best_with_path is None:
                        best_with_path = asset
                if best_any is None:
                    best_any = asset
        return best_with_path or best_any

    # -- bulk load -------------------------------------------------------

    def load_from_json(self, path: str) -> int:
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("AssetRegistry: failed to load %s: %s", path, exc)
            return 0
        records = payload.get("assets", []) if isinstance(payload, dict) else payload
        if not isinstance(records, list):
            return 0
        loaded = 0
        for item in records:
            if not isinstance(item, dict):
                continue
            try:
                self.add(Asset.from_dict(item))
                loaded += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("AssetRegistry: skipping malformed asset: %s", exc)
        return loaded

    def to_json(self) -> str:
        with self._lock:
            return json.dumps(
                {"assets": [a.to_dict() for a in self._assets]},
                indent=2,
                sort_keys=True,
            )


# ---------------------------------------------------------------------------
# Asset criticality service
# ---------------------------------------------------------------------------


@dataclass
class AssetContext:
    """Normalised view of an asset as seen by the scoring layer.

    Returned by ``AssetCriticalityService.resolve`` so the rest of the
    pipeline can consume a stable shape regardless of whether an
    explicit ``Asset`` is registered or the request falls back to
    generic defaults.
    """

    asset: Asset | None
    criticality_score: float  # 1-10
    business_multiplier: float  # 0.5x - 10x
    control_discount: float  # 0.0 - 1.0, applied as a discount
    asset_type: str
    entity_type: str
    compliance_requirements: list[str]
    is_public: bool
    has_pii: bool
    has_financial: bool
    derived_from: str  # "registry" | "default" | "config_hint"

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset.asset_id if self.asset else None,
            "criticality_score": round(self.criticality_score, 2),
            "business_multiplier": round(self.business_multiplier, 3),
            "control_discount": round(self.control_discount, 3),
            "asset_type": self.asset_type,
            "entity_type": self.entity_type,
            "compliance_requirements": list(self.compliance_requirements),
            "is_public": self.is_public,
            "has_pii": self.has_pii,
            "has_financial": self.has_financial,
            "derived_from": self.derived_from,
        }


class AssetCriticalityService:
    """Resolve an asset context for an incoming finding or target.

    Sources of truth, in priority order:
      1. Explicit ``AssetRegistry`` record (highest trust).
      2. ``business_context`` config block in the supplied
         ``business_context`` argument.
      3. Legacy ``target_info`` dict (PII / financial / compliance
         flags) so callers that have not migrated still work.
      4. Generic defaults with criticality 1.0 / multiplier 1.0.
    """

    def __init__(
        self,
        registry: AssetRegistry | None = None,
        tier_multipliers: dict[str, float] | None = None,
    ) -> None:
        self.registry = registry or AssetRegistry()
        self.tier_multipliers = dict(tier_multipliers or DEFAULT_TIER_MULTIPLIERS)

    def resolve(
        self,
        host_or_url: str = "",
        *,
        target_info: dict[str, Any] | None = None,
        business_context: dict[str, Any] | None = None,
    ) -> AssetContext:
        target_info = target_info or {}
        business_context = business_context or {}

        asset = self.registry.lookup(host_or_url) if host_or_url else None
        if asset is not None:
            return self._from_asset(asset, target_info)

        # Fall back to config-driven hints (entity_type -> criticality).
        hint = _match_business_hint(host_or_url, business_context)
        if hint is not None:
            return AssetContext(
                asset=None,
                criticality_score=float(hint.get("criticality", 5.0)),
                business_multiplier=float(
                    hint.get("multiplier", 1.0)
                ),
                control_discount=float(target_info.get("control_discount", 1.0) or 1.0),
                asset_type=str(hint.get("asset_type", "unknown")),
                entity_type=str(hint.get("entity_type", "unknown")),
                compliance_requirements=list(hint.get("compliance_requirements", []) or []),
                is_public=bool(target_info.get("is_public", False)),
                has_pii=bool(target_info.get("has_pii", False) or hint.get("has_pii", False)),
                has_financial=bool(
                    target_info.get("has_financial", False) or hint.get("has_financial", False)
                ),
                derived_from="config_hint",
            )

        return AssetContext(
            asset=None,
            criticality_score=float(target_info.get("criticality", 1.0) or 1.0),
            business_multiplier=1.0,
            control_discount=float(target_info.get("control_discount", 1.0) or 1.0),
            asset_type=str(target_info.get("asset_type", "unknown")),
            entity_type=str(target_info.get("entity_type", "unknown")),
            compliance_requirements=list(target_info.get("compliance_requirements", []) or []),
            is_public=bool(target_info.get("is_public", False)),
            has_pii=bool(target_info.get("has_pii", False)),
            has_financial=bool(target_info.get("has_financial", False)),
            derived_from="default",
        )

    def _from_asset(self, asset: Asset, target_info: dict[str, Any]) -> AssetContext:
        multiplier = self.tier_multipliers.get(asset.tier, 1.0)
        return AssetContext(
            asset=asset,
            criticality_score=asset.criticality,
            business_multiplier=multiplier,
            control_discount=float(target_info.get("control_discount", 1.0) or 1.0),
            asset_type=asset.asset_type,
            entity_type=asset.entity_type,
            compliance_requirements=list(asset.compliance_requirements)
            or list(target_info.get("compliance_requirements", []) or []),
            is_public=bool(target_info.get("is_public", False)),
            has_pii=bool(
                target_info.get("has_pii", False) or asset.entity_type == "pii_store"
            ),
            has_financial=bool(
                target_info.get("has_financial", False)
                or asset.entity_type == "payment_processor"
            ),
            derived_from="registry",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HOST_PORT_RE = re.compile(r"^(?P<host>[^/:?#]+)(?::\d+)?(?:[/?#]|$)")


def _parse_host_path(value: str) -> tuple[str, str]:
    """Extract (host, path) from a URL or host string, lowercased."""
    raw = value.strip().lower()
    if not raw:
        return "", ""
    if "://" not in raw:
        # Treat as host (and optional /path).
        match = _HOST_PORT_RE.match(raw)
        if not match:
            return raw, ""
        host = match.group("host")
        remainder = raw[match.end() - 1 :]
        path = remainder if remainder.startswith("/") else ""
        return host, path
    from urllib.parse import urlparse

    parsed = urlparse(raw)
    return (parsed.netloc or "").split(":")[0], parsed.path or ""


def _host_matches(pattern: str, host: str) -> bool:
    """Glob-style host match supporting ``*`` and ``**`` wildcards."""
    pat = (pattern or "").strip().lower()
    if not pat or not host:
        return False
    if pat == host:
        return True
    return fnmatch.fnmatchcase(host, pat)


def _match_business_hint(
    host: str, business_context: dict[str, Any]
) -> dict[str, Any] | None:
    """Match a host (or empty) against a business_context.hosts block."""
    if not business_context:
        return None
    hints = business_context.get("hosts") or []
    if not isinstance(hints, list):
        return None
    host_lc = (host or "").lower()
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        for pat in hint.get("host_patterns", []) or []:
            if _host_matches(str(pat).lower(), host_lc):
                return hint
    return None


# ---------------------------------------------------------------------------
# Module-level convenience registry
# ---------------------------------------------------------------------------

_default_registry: AssetRegistry | None = None
_default_registry_lock = threading.Lock()


def get_default_asset_registry() -> AssetRegistry:
    """Return the process-wide asset registry, hydrating it from env if set."""
    global _default_registry
    with _default_registry_lock:
        if _default_registry is None:
            _default_registry = AssetRegistry()
            cfg_path = os.environ.get("PIPELINE_ASSETS_CONFIG")
            if cfg_path:
                _default_registry.load_from_json(cfg_path)
        return _default_registry


def reset_default_asset_registry() -> None:
    """Test hook - drop the cached registry so the next call re-hydrates."""
    global _default_registry
    with _default_registry_lock:
        _default_registry = None


__all__ = [
    "Asset",
    "AssetContext",
    "AssetCriticalityService",
    "AssetRegistry",
    "DEFAULT_TIER_MULTIPLIERS",
    "KNOWN_ASSET_TYPES",
    "KNOWN_ENTITY_TYPES",
    "get_default_asset_registry",
    "reset_default_asset_registry",
]
