"""Typed manifests for active checks and payload generators."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any


class ActiveCapability(StrEnum):
    HTTP_CLIENT = "http_client"
    RESPONSE_CACHE = "response_cache"
    NETWORK_EGRESS = "network_egress"
    PAYLOAD_GENERATION = "payload_generation"
    JWT_CRYPTO = "jwt_crypto"
    WASM = "wasm"


class ActiveInputKind(StrEnum):
    URL_ITEMS = "url_items"
    URLS = "urls"
    HOSTS = "hosts"
    FINDING = "finding"
    STAGE_INPUT = "stage_input"


class ActiveResultEncoding(StrEnum):
    FINDINGS_JSON = "findings_json"
    SUGGESTIONS_JSON = "suggestions_json"
    VERIFICATION_JSON = "verification_json"


@dataclass(frozen=True, slots=True)
class ActiveIOContract:
    input_kind: ActiveInputKind
    input_schema: str
    output_schema: str
    result_encoding: ActiveResultEncoding


@dataclass(frozen=True, slots=True)
class ActiveExecutionBudget:
    timeout_seconds: float = 30.0
    memory_mb: int = 256
    max_output_bytes: int = 1_000_000

    def normalized(self) -> ActiveExecutionBudget:
        return ActiveExecutionBudget(
            timeout_seconds=max(0.05, float(self.timeout_seconds)),
            memory_mb=max(32, int(self.memory_mb)),
            max_output_bytes=max(4096, int(self.max_output_bytes)),
        )


@dataclass(frozen=True, slots=True)
class ActiveCheckManifest:
    check_id: str
    display_name: str
    io: ActiveIOContract
    required_capabilities: frozenset[ActiveCapability] = field(default_factory=frozenset)
    budget: ActiveExecutionBudget = field(default_factory=ActiveExecutionBudget)
    isolation: str = "process"
    result_encoding_version: str = "active-result.v1"

    def with_timeout(self, timeout_seconds: float | None) -> ActiveCheckManifest:
        if timeout_seconds is None:
            return self
        return replace(
            self,
            budget=replace(self.budget, timeout_seconds=float(timeout_seconds)).normalized(),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "display_name": self.display_name,
            "io": {
                "input_kind": self.io.input_kind.value,
                "input_schema": self.io.input_schema,
                "output_schema": self.io.output_schema,
                "result_encoding": self.io.result_encoding.value,
            },
            "required_capabilities": sorted(cap.value for cap in self.required_capabilities),
            "budget": {
                "timeout_seconds": self.budget.timeout_seconds,
                "memory_mb": self.budget.memory_mb,
                "max_output_bytes": self.budget.max_output_bytes,
            },
            "isolation": self.isolation,
            "result_encoding_version": self.result_encoding_version,
        }


class ActiveManifestRegistry:
    """Capability-queryable registry for active check manifests."""

    def __init__(self) -> None:
        self._manifests: dict[str, ActiveCheckManifest] = {}

    def reset(self) -> None:
        """Clear all registered manifests to prevent test state leakage."""
        self._manifests.clear()

    def register(self, manifest: ActiveCheckManifest) -> ActiveCheckManifest:
        manifest = replace(manifest, budget=manifest.budget.normalized())
        self._manifests[manifest.check_id] = manifest
        return manifest

    def get(self, check_id: str) -> ActiveCheckManifest:
        try:
            return self._manifests[check_id]
        except KeyError as exc:
            raise KeyError(f"active check manifest not registered: {check_id}") from exc

    def all(self) -> dict[str, ActiveCheckManifest]:
        return dict(self._manifests)

    def query(
        self,
        *,
        capability: ActiveCapability | str | None = None,
        input_kind: ActiveInputKind | str | None = None,
        result_encoding: ActiveResultEncoding | str | None = None,
    ) -> list[ActiveCheckManifest]:
        capability_v = ActiveCapability(capability) if capability is not None else None
        input_kind_v = ActiveInputKind(input_kind) if input_kind is not None else None
        result_encoding_v = (
            ActiveResultEncoding(result_encoding) if result_encoding is not None else None
        )
        results = list(self._manifests.values())
        if capability_v is not None:
            results = [item for item in results if capability_v in item.required_capabilities]
        if input_kind_v is not None:
            results = [item for item in results if item.io.input_kind == input_kind_v]
        if result_encoding_v is not None:
            results = [item for item in results if item.io.result_encoding == result_encoding_v]
        return sorted(results, key=lambda item: item.check_id)


def _manifest(
    check_id: str,
    *,
    input_kind: ActiveInputKind = ActiveInputKind.URL_ITEMS,
    encoding: ActiveResultEncoding = ActiveResultEncoding.FINDINGS_JSON,
    caps: set[ActiveCapability] | None = None,
    timeout: float = 30.0,
) -> ActiveCheckManifest:
    caps = caps or {ActiveCapability.HTTP_CLIENT, ActiveCapability.NETWORK_EGRESS}
    return ActiveCheckManifest(
        check_id=check_id,
        display_name=check_id.replace("_", " ").title(),
        io=ActiveIOContract(
            input_kind=input_kind,
            input_schema=f"active-check.{input_kind.value}.v1",
            output_schema=f"active-check.{encoding.value}.v1",
            result_encoding=encoding,
        ),
        required_capabilities=frozenset(caps),
        budget=ActiveExecutionBudget(timeout_seconds=timeout),
    )


def build_default_active_manifest_registry() -> ActiveManifestRegistry:
    registry = ActiveManifestRegistry()
    url_item_checks = {
        "redirect",
        "sqli",
        "csrf",
        "jwt",
        "xss",
        "ssrf",
        "file_upload",
        "oauth",
        "open_redirect",
        "path_traversal",
        "command_injection",
        "idor",
        "hpp",
        "websocket",
        "graphql",
        "xpath",
        "ssti",
        "xxe",
        "nosql",
        "auth_bypass",
        "jwt_attacks",
        "ldap",
        "deserialization",
        "proxy_ssrf",
        "host_header",
        "crlf",
        "cors",
        "trace",
        "options",
        "http_smuggling",
        "json",
        "response_diff",
        "token_reuse",
        "race_condition",
        "race_condition_alias",
        "cache_poison",
        "cache_poisoning",
    }
    for check_id in url_item_checks:
        extra = {ActiveCapability.HTTP_CLIENT, ActiveCapability.RESPONSE_CACHE}
        if check_id in {"jwt", "jwt_attacks"}:
            extra.add(ActiveCapability.JWT_CRYPTO)
        registry.register(_manifest(check_id, caps=extra))

    for check_id in {"cloud_metadata"}:
        registry.register(_manifest(check_id, input_kind=ActiveInputKind.HOSTS))

    for check_id in {"mutation", "fuzzing_suggestions"}:
        registry.register(
            _manifest(
                check_id,
                input_kind=ActiveInputKind.URLS,
                encoding=ActiveResultEncoding.SUGGESTIONS_JSON,
                caps={ActiveCapability.PAYLOAD_GENERATION},
                timeout=20.0,
            )
        )

    registry.register(
        _manifest(
            "wasm_verifier",
            input_kind=ActiveInputKind.STAGE_INPUT,
            encoding=ActiveResultEncoding.VERIFICATION_JSON,
            caps={ActiveCapability.WASM},
            timeout=10.0,
        )
    )
    return registry


DEFAULT_ACTIVE_MANIFEST_REGISTRY = build_default_active_manifest_registry()


def get_active_manifest(check_id: str) -> ActiveCheckManifest:
    return DEFAULT_ACTIVE_MANIFEST_REGISTRY.get(check_id)


def query_active_manifests(
    *,
    capability: ActiveCapability | str | None = None,
    input_kind: ActiveInputKind | str | None = None,
    result_encoding: ActiveResultEncoding | str | None = None,
) -> list[ActiveCheckManifest]:
    return DEFAULT_ACTIVE_MANIFEST_REGISTRY.query(
        capability=capability,
        input_kind=input_kind,
        result_encoding=result_encoding,
    )


def reset_active_manifest_registry() -> None:
    """Reset the global registry to its default state for clean boundaries."""
    global DEFAULT_ACTIVE_MANIFEST_REGISTRY
    DEFAULT_ACTIVE_MANIFEST_REGISTRY = build_default_active_manifest_registry()
