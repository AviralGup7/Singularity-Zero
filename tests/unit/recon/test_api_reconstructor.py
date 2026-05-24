"""Unit tests for the Automatic API Schema Reconstruction module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.recon.api_reconstructor import ApiSchemaReconstructor


def test_parameterize_path():
    """Verify that numerical and UUID path segments are properly parameterized."""
    reconstructor = ApiSchemaReconstructor(".")

    # Test 1: Simple numerical ID parameterization
    path1, params1 = reconstructor.parameterize_path("/api/v1/users/123/profile")
    assert path1 == "/api/v1/users/{id1}/profile"
    assert params1 == ["id1"]

    # Test 2: UUID parameterization
    path2, params2 = reconstructor.parameterize_path("/api/v2/items/a8e0f54b-d72e-4b68-80f5-51523ccdf2a1")
    assert path2 == "/api/v2/items/{uuid1}"
    assert params2 == ["uuid1"]

    # Test 3: Mixed parameterization
    path3, params3 = reconstructor.parameterize_path("/api/v1/users/456/photos/e8b0f54b-1234-5678-abcd-1234567890ab")
    assert path3 == "/api/v1/users/{id1}/photos/{uuid2}"
    assert params3 == ["id1", "uuid2"]


def test_openapi_specification_generation():
    """Verify that raw endpoints compile into a compliant OpenAPI 3.0 spec."""
    with tempfile.TemporaryDirectory() as tmpdir:
        reconstructor = ApiSchemaReconstructor(tmpdir)
        target = "api.example.com"

        urls = [
            "https://api.example.com/api/v1/users/123?active=true",
            "https://api.example.com/api/v1/users/456?active=false&role=admin",
            "https://api.example.com/api/v1/health",
            "https://api.example.com/api/v2/items/d762f55b-4321-8765-bca1-1234567890cd",
        ]

        spec = reconstructor.reconstruct_spec(target, urls)

        # 1. Assert OpenAPI structural metadata
        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["title"] == "Reconstructed API Specification for api.example.com"
        assert spec["servers"][0]["url"] == "https://api.example.com"

        # 2. Assert path mapping and clustering
        paths = spec["paths"]
        assert "/api/v1/users/{id1}" in paths
        assert "/api/v1/health" in paths
        assert "/api/v2/items/{uuid1}" in paths

        # 3. Assert path and query parameter mappings
        users_endpoint = paths["/api/v1/users/{id1}"]
        users_params = users_endpoint["parameters"]

        param_names = [p["name"] for p in users_params]
        assert "id1" in param_names
        assert "active" in param_names
        assert "role" in param_names

        # Verify output spec JSON was written to disk
        spec_file = Path(tmpdir) / "openapi_spec.json"
        assert spec_file.exists()
