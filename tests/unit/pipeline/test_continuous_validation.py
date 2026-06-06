from unittest.mock import MagicMock, patch

from src.pipeline.validation import (
    probe_system_resources,
    validate_config,
    validate_scope_disallowed_tlds,
    validate_scope_rfc1918,
    validate_scope_threat_intel,
    validate_stage_artifact,
)


def test_structural_validation_pydantic():
    # Valid config dict
    valid_config = {
        "target_name": "test-target",
        "output_dir": "output/test",
        "mode": "fast",
        "tools": {
            "retry_jitter": 0.5,
            "subfinder": True
        }
    }
    ok, report = validate_config(valid_config, ["example.com"])
    assert ok is True
    assert any(c["name"] == "structural_validation" and c["passed"] for c in report["checks"])

    # Invalid config dict (retry_jitter is not a float between 0 and 1)
    invalid_config = {
        "target_name": "test-target",
        "output_dir": "output/test",
        "mode": "fast",
        "tools": {
            "retry_jitter": 2.5,  # out of bounds [0, 1]
        }
    }
    ok, report = validate_config(invalid_config, ["example.com"])
    assert ok is False
    assert any(c["name"] == "structural_validation" and not c["passed"] for c in report["checks"])

    # Invalid type
    invalid_type_config = {
        "target_name": "test-target",
        "output_dir": "output/test",
        "mode": "fast",
        "tools": {
            "retry_jitter": "fast",  # not a float
        }
    }
    ok, report = validate_config(invalid_type_config, ["example.com"])
    assert ok is False
    assert any(c["name"] == "structural_validation" and not c["passed"] for c in report["checks"])


def test_semantic_scope_disallowed_tlds():
    # Disallowed TLD
    ok, msg = validate_scope_disallowed_tlds("target.local")
    assert ok is False
    assert "uses disallowed TLD" in msg

    # Allowed TLD
    ok, msg = validate_scope_disallowed_tlds("target.com")
    assert ok is True
    assert msg == ""


def test_semantic_scope_rfc1918():
    # Private IP
    ok, msg = validate_scope_rfc1918("192.168.1.1")
    assert ok is False
    assert "private RFC1918" in msg

    # Private CIDR
    ok, msg = validate_scope_rfc1918("10.0.0.0/24")
    assert ok is False
    assert "private RFC1918" in msg

    # Public IP
    ok, msg = validate_scope_rfc1918("8.8.8.8")
    assert ok is True

    # Resolves to private IP
    with patch("socket.gethostbyname", return_value="172.16.0.5"):
        ok, msg = validate_scope_rfc1918("internal.dev")
        assert ok is False
        assert "resolves to a private RFC1918" in msg


def test_semantic_scope_threat_intel():
    # Intersects with threat intel
    with patch("src.intelligence.threat_intel.ThreatIntelCorrelator.match_ioc", return_value={"malicious": True, "matched_feeds": ["VirusTotal"]}):
        ok, msg = validate_scope_threat_intel("malicious-c2.com")
        assert ok is False
        assert "intersects with threat-intel" in msg

    # Safe domain
    with patch("src.intelligence.threat_intel.ThreatIntelCorrelator.match_ioc", return_value={"malicious": False}):
        ok, msg = validate_scope_threat_intel("safe-domain.com")
        assert ok is True


def test_validate_stage_artifact(tmp_path):
    ctx = MagicMock()
    ctx.output_store.run_dir = tmp_path

    # Subdomains validation
    subdomains_file = tmp_path / "subdomains.txt"
    subdomains_file.write_text("example.com\ntest.example.com", encoding="utf-8")
    ok, err = validate_stage_artifact("subdomains", ctx)
    assert ok is True
    assert err is None

    # Empty subdomains
    subdomains_file.write_text("", encoding="utf-8")
    ok, err = validate_stage_artifact("subdomains", ctx)
    assert ok is False
    assert "is empty" in err


def test_probe_system_resources(tmp_path):
    ok, details = probe_system_resources(tmp_path)
    assert "disk" in details
    assert "memory" in details
    assert "file_descriptors" in details
    assert details["disk"]["passed"] is True or details["disk"]["passed"] is False
