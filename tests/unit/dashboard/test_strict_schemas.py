import pytest
from pydantic import ValidationError

from src.dashboard.fastapi.schemas import (
    CacheKeyDeleteRequest,
    JobCreateRequest,
    NoteCreateRequest,
    NoteUpdateRequest,
)
from src.intelligence.ml.feature_vector import FeatureVector


def test_job_create_request_strict_validation() -> None:
    """Verify that JobCreateRequest rejects extra fields and invalid types strictly."""
    # Valid instance
    valid = JobCreateRequest(base_url="https://example.com")
    assert valid.base_url == "https://example.com"

    # Reject extra fields
    with pytest.raises(ValidationError) as exc:
        JobCreateRequest(base_url="https://example.com", extra_field="forbidden")
    assert "extra_field" in str(exc.value)
    assert "Extra inputs are not permitted" in str(exc.value)

    # Reject type coercions (int to str)
    with pytest.raises(ValidationError) as exc:
        JobCreateRequest(base_url=12345)  # strict=True rejects int for str
    assert "base_url" in str(exc.value)
    assert "Input should be a valid string" in str(exc.value)


def test_note_create_request_strict_validation() -> None:
    """Verify that NoteCreateRequest rejects extra fields and invalid types strictly."""
    # Valid instance
    valid = NoteCreateRequest(finding_id="finding-1", note="My test note")
    assert valid.finding_id == "finding-1"

    # Reject extra fields
    with pytest.raises(ValidationError) as exc:
        NoteCreateRequest(finding_id="finding-1", note="My test note", hack="illegal")
    assert "hack" in str(exc.value)
    assert "Extra inputs are not permitted" in str(exc.value)

    # Reject invalid types
    with pytest.raises(ValidationError) as exc:
        NoteCreateRequest(finding_id=999, note="My note")
    assert "finding_id" in str(exc.value)


def test_note_update_request_strict_validation() -> None:
    """Verify that NoteUpdateRequest rejects extra fields and invalid types strictly."""
    # Valid instance
    valid = NoteUpdateRequest(finding_id="finding-1", note="Updated note")
    assert valid.finding_id == "finding-1"

    # Reject extra fields
    with pytest.raises(ValidationError) as exc:
        NoteUpdateRequest(finding_id="finding-1", invalid_prop="extra")
    assert "invalid_prop" in str(exc.value)


def test_cache_key_delete_request_strict_validation() -> None:
    """Verify that CacheKeyDeleteRequest rejects extra fields and invalid types strictly."""
    # Valid instance
    valid = CacheKeyDeleteRequest(pattern="*")
    assert valid.pattern == "*"

    # Reject extra fields
    with pytest.raises(ValidationError) as exc:
        CacheKeyDeleteRequest(pattern="*", count=10)
    assert "count" in str(exc.value)


def test_feature_vector_strict_validation() -> None:
    """Verify that FeatureVector enforces strict type validation and values."""
    # Valid instance
    valid = FeatureVector(confidence=0.8, legacy_impact=0.5)
    assert valid.confidence == 0.8

    # Reject type coercions (str to float)
    with pytest.raises(ValidationError) as exc:
        FeatureVector(confidence="0.8")
    assert "confidence" in str(exc.value)
    assert "Input should be a valid number" in str(exc.value)
