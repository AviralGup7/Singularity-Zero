"""Regression and coverage for Azure SAS URL generation."""

from __future__ import annotations

import pytest

from src.recon.azure_sas import (
    AzureReconResult,
    azure_account_candidates,
    generate_sas_patterns_for_account,
)


@pytest.mark.unit
def test_sas_url_does_not_repeat_account_in_path() -> None:
    patterns = generate_sas_patterns_for_account("examplestorage", containers=["public"])
    assert patterns
    for pattern in patterns:
        assert pattern.url.startswith("https://examplestorage.blob.core.windows.net/public?")
        assert "/examplestorage/public" not in pattern.url
        assert pattern.permissions in {"r", "rl"}
        assert "sig=" in pattern.url


@pytest.mark.unit
def test_sas_url_includes_blob_after_container() -> None:
    from src.recon.azure_sas import _generate_sas_patterns

    blob_patterns = _generate_sas_patterns("examplestorage", "$web", blob="index.html")
    assert blob_patterns
    for pattern in blob_patterns:
        assert pattern.url.startswith(
            "https://examplestorage.blob.core.windows.net/$web/index.html?"
        )
        assert pattern.container == "$web"
        assert pattern.blob == "index.html"


@pytest.mark.unit
def test_generate_sas_patterns_rejects_invalid_account() -> None:
    assert generate_sas_patterns_for_account("AB") == []
    assert generate_sas_patterns_for_account("not_valid_name") == []


@pytest.mark.unit
def test_azure_account_candidates_sanitizes_and_suffixes() -> None:
    names = azure_account_candidates("my-company.com")
    assert "mycompany" in names
    assert "mycompanyprod" in names
    assert all(name.islower() and name.isalnum() for name in names)
    assert azure_account_candidates("ab.com") == []


@pytest.mark.unit
def test_azure_recon_result_normalizes_web_findings() -> None:
    result = AzureReconResult(
        public_web_findings=[{"url": "https://acct.z6.web.core.windows.net"}],
        public_listing_findings=["https://acct.blob.core.windows.net/public"],
    )
    result._normalize_web_findings()
    assert result.web_endpoints == ["https://acct.z6.web.core.windows.net"]
    assert result.listing_endpoints == ["https://acct.blob.core.windows.net/public"]
    payload = result.to_dict()
    assert payload["public_web_count"] == 1
    assert payload["sas_pattern_count"] == 0
