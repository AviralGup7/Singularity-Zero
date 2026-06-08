"""Architecture contract: active manifest checks vs registered validator engines.

This test ensures the active manifest registry and the execution
validator/engine registry stay synchronized.  A stale manifest entry
(registered check_id with no backing implementation) will cause the
pipeline to either silently short-circuit the check or raise an
unhandled KeyError — both are unacceptable in a security scanner.

Run with:
    pytest tests/unit/execution/test_active_manifest_contract.py -v
"""
from __future__ import annotations

import pytest

from src.execution.active_manifest import (
    build_default_active_manifest_registry,
)
from src.execution.validators.registry import VALIDATOR_ORDER


@pytest.fixture()
def active_registry() -> object:
    return build_default_active_manifest_registry()


@pytest.fixture()
def manifest_check_ids(active_registry: object) -> set[str]:
    return set(active_registry.all())


@pytest.fixture()
def validator_names() -> set[str]:
    return set(VALIDATOR_ORDER)


class TestActiveManifestValidatorContract:
    """Validate active_manifest ↔ validator_registry alignment."""

    @pytest.mark.architecture
    def test_validator_has_manifest_entry(
        self,
        manifest_check_ids: set[str],
        validator_names: set[str],
    ) -> None:
        """Every validator declared in VALIDATOR_ORDER must have a
        corresponding active_manifest check_id.

        Validator names are normalised: e.g. ``jwt_weakness`` in the
        validator layer maps to both ``jwt`` and ``jwt_attacks`` in the
        manifest, so we widen the matcher instead of requiring an exact
        string match.
        """
        _JWT_ALIASES = {"jwt", "jwt_attacks", "jwt_weakness"}
        _GRAPHQL_ALIASES = {"graphql", "graphql_abuse"}
        _CACHE_ALIASES = {"cache_poison", "cache_poisoning"}
        missing: list[str] = []
        for name in sorted(validator_names):
            manifest_ids = {name}
            if name in _JWT_ALIASES:
                manifest_ids = manifest_ids | _JWT_ALIASES
            if name in _GRAPHQL_ALIASES:
                manifest_ids = manifest_ids | _GRAPHQL_ALIASES
            if name in _CACHE_ALIASES:
                manifest_ids = manifest_ids | _CACHE_ALIASES
            if not (manifest_ids & manifest_check_ids):
                missing.append(name)
        assert not missing, (
            f"Validators with no active manifest entry: {missing}. "
            "Add them to build_default_active_manifest_registry() or remove "
            "the validator from VALIDATOR_ORDER."
        )

    @pytest.mark.architecture
    def test_known_validator_mapped_manifest_check_ids_present(
        self,
        manifest_check_ids: set[str],
    ) -> None:
        """Core validator-backed check_ids must remain in the manifest."""
        expected_validator_backed = {
            "redirect",
            "ssrf",
            "token_reuse",
            "idor",
            "csrf",
            "xss",
            "ssti",
            "file_upload",
            "cors",
            "graphql",
            "jwt",
            "jwt_attacks",
            "race_condition_alias",
        }
        missing = expected_validator_backed - manifest_check_ids
        assert not missing, (
            f"Expected validator-backed check_ids missing from manifest: {missing}"
        )

    @pytest.mark.architecture
    def test_manifest_entries_have_capability_declaration(
        self,
        active_registry: object,
    ) -> None:
        """Every manifest entry with a WASM capability must declare it
        explicitly so the orchestrator can skip it when wasmtime is not
        installed."""
        for check_id, manifest in active_registry.all().items():
            if check_id == "wasm_verifier":
                from src.execution.active_manifest import ActiveCapability
                assert ActiveCapability.WASM in manifest.required_capabilities, (
                    f"wasm_verifier must declare WASM capability"
                )
