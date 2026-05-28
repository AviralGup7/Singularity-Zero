"""Unit tests for the Cloud Bucket & Asset Enumeration module."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest

from src.recon.cloud_recon import CloudBucketScanner


def test_generate_candidates():
    """Verify that domain keywords correctly expand to common storage suffixes."""
    scanner = CloudBucketScanner()
    candidates = scanner.generate_candidates("test-organization.com")

    # Core candidates must exist
    assert "testorganization" in candidates
    assert "testorganization-backup" in candidates
    assert "testorganization-assets" in candidates
    assert "testorganization-prod" in candidates
    assert "testorganization.backup" in candidates


class MockResponse:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.mark.asyncio
async def test_check_aws_bucket():
    """Verify AWS S3 bucket checks classify results correctly based on response."""
    scanner = CloudBucketScanner()
    mock_session = AsyncMock()

    # Case A: Public S3 bucket
    mock_session.get = Mock(return_value=MockResponse(200))
    res = await scanner.check_aws_bucket(mock_session, "test-bucket")
    assert res is not None
    assert res["status"] == "public"
    assert res["severity"] == "high"

    # Case B: Restricted S3 bucket
    mock_session.get = Mock(return_value=MockResponse(403))
    res = await scanner.check_aws_bucket(mock_session, "test-bucket")
    assert res is not None
    assert res["status"] == "secure"
    assert res["severity"] == "info"

    # Case C: Not found
    mock_session.get = Mock(return_value=MockResponse(404))
    res = await scanner.check_aws_bucket(mock_session, "test-bucket")
    assert res is None


@pytest.mark.asyncio
async def test_check_azure_bucket():
    """Verify Azure Storage account exists check based on 400/403/200 codes."""
    scanner = CloudBucketScanner()
    mock_session = AsyncMock()

    # Exists check on Azure (400 Forbidden / Header issue means exists)
    mock_session.get = Mock(return_value=MockResponse(400))
    res = await scanner.check_azure_bucket(mock_session, "my-azure-storage")
    assert res is not None
    assert res["platform"] == "Azure Blob Storage"
    assert res["status"] == "secure"
