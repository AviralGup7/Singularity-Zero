import pytest
from src.fuzzing.payload_generator_http import (
    generate_ml_adversarial_variants,
    generate_body_payloads,
)


def test_generate_ml_adversarial_variants():
    payload = "admin' or '1'='1"
    variants = generate_ml_adversarial_variants(payload)
    
    # Verify we get distinct WAF evasion variants
    assert len(variants) > 0
    # Should have case perturbation
    assert any("ADMIN" in v or "admin" in v for v in variants)
    # Should have comment perturbation
    assert any("ML_PERTURB" in v for v in variants)
    # Should have URL encoding
    assert any("%27" in v for v in variants)


def test_generate_body_payloads_with_ml_adversarial():
    # Target URL with user/profile to trigger fields including strings
    urls = ["http://example.com/api/v1/user/profile"]
    suggestions = generate_body_payloads(urls)
    
    assert len(suggestions) > 0
    body_suggestions = suggestions[0]["body_suggestions"]
    assert len(body_suggestions) > 0
    
    # We should see the ml_adversarial strategy being injected for strings
    strategies = [s["strategy"] for s in body_suggestions]
    assert "ml_adversarial" in strategies
