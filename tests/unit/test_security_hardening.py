"""Tests for security hardening measures.

Covers:
- defusedxml replacing xml.etree.ElementTree
- Production startup enforcement (DASHBOARD_AUTH_DISABLED, default secrets)
- Secret validator placeholder detection
- SSRF protection consistency
- .gitignore completeness
"""

from __future__ import annotations

from pathlib import Path

import pytest


class TestDefusedXmlReplacement:
    """Verify that xml.etree.ElementTree is replaced with defusedxml."""

    def test_ast_mutator_uses_defusedxml(self) -> None:
        """ast_mutator should import defusedxml, not xml.etree.ElementTree."""
        from pathlib import Path

        source_path = Path(__file__).parent.parent.parent / "src" / "fuzzing" / "ast_mutator.py"
        source = source_path.read_text(encoding="utf-8")
        assert "defusedxml" in source, "ast_mutator should use defusedxml"
        assert "xml.etree.ElementTree" not in source, (
            "ast_mutator should NOT import xml.etree.ElementTree"
        )

    def test_defusedxml_blocks_xxe(self) -> None:
        """defusedxml should reject XXE payloads."""
        import defusedxml.ElementTree as ET

        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root>&xxe;</root>"
        )
        with pytest.raises(Exception):
            ET.fromstring(xxe_payload)

    def test_no_unsafe_xml_imports_in_project(self) -> None:
        """No Python file should import xml.etree.ElementTree directly."""
        from pathlib import Path

        src_dir = Path(__file__).parent.parent.parent / "src"
        unsafe_imports = []
        for py_file in src_dir.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8")
                if "import xml.etree.ElementTree" in content:
                    unsafe_imports.append(str(py_file.relative_to(src_dir)))
            except Exception:
                pass
        assert len(unsafe_imports) == 0, (
            f"Files still using xml.etree.ElementTree: {unsafe_imports}"
        )


class TestProductionStartupEnforcement:
    """Verify that dangerous defaults are blocked in production."""

    def test_enforce_production_security_blocks_auth_disabled(self) -> None:
        """enforce_production_security should block DASHBOARD_AUTH_DISABLED=true in production."""
        from src.core.security.secret_validator import enforce_production_security

        env = {
            "APP_ENV": "production",
            "DASHBOARD_AUTH_DISABLED": "true",
            "APP_SECRET_KEY": "a" * 32,
            "SEC_JWT_SECRET": "b" * 32,
        }
        with pytest.raises(RuntimeError, match="DASHBOARD_AUTH_DISABLED=true is not allowed"):
            enforce_production_security(env)

    def test_enforce_production_security_blocks_default_secret_key(self) -> None:
        """enforce_production_security should block default APP_SECRET_KEY in production."""
        from src.core.security.secret_validator import enforce_production_security

        env = {
            "APP_ENV": "production",
            "DASHBOARD_AUTH_DISABLED": "false",
            "APP_SECRET_KEY": "dev-secret-key-change-in-production-32chars-minimum-length",
            "SEC_JWT_SECRET": "b" * 32,
        }
        with pytest.raises(RuntimeError, match="APP_SECRET_KEY is set to a default"):
            enforce_production_security(env)

    def test_enforce_production_security_blocks_default_jwt_secret(self) -> None:
        """enforce_production_security should block default SEC_JWT_SECRET in production."""
        from src.core.security.secret_validator import enforce_production_security

        env = {
            "APP_ENV": "production",
            "DASHBOARD_AUTH_DISABLED": "false",
            "APP_SECRET_KEY": "a" * 32,
            "SEC_JWT_SECRET": "dev-jwt-secret-key-at-least-32-characters-long-for-hs256",
        }
        with pytest.raises(RuntimeError, match="SEC_JWT_SECRET is set to a default"):
            enforce_production_security(env)

    def test_enforce_production_security_allows_dev_env(self) -> None:
        """enforce_production_security should NOT block in development."""
        from src.core.security.secret_validator import enforce_production_security

        env = {
            "APP_ENV": "development",
            "DASHBOARD_AUTH_DISABLED": "true",
            "APP_SECRET_KEY": "dev-secret-key-change-in-production-32chars-minimum-length",
            "SEC_JWT_SECRET": "dev-jwt-secret-key-at-least-32-characters-long-for-hs256",
        }
        # Should NOT raise in development
        enforce_production_security(env)

    def test_enforce_production_security_allows_strong_secrets(self) -> None:
        """enforce_production_security should allow strong secrets in production."""
        from src.core.security.secret_validator import enforce_production_security

        env = {
            "APP_ENV": "production",
            "DASHBOARD_AUTH_DISABLED": "false",
            "APP_SECRET_KEY": "a" * 32,
            "SEC_JWT_SECRET": "b" * 32,
        }
        # Should NOT raise with strong secrets
        enforce_production_security(env)


class TestSecretValidator:
    """Test the secret validator module."""

    def test_find_placeholder_violations_detects_known_bad(self) -> None:
        """find_placeholder_violations should detect known bad literals."""
        from src.core.security.secret_validator import find_placeholder_violations

        env = {
            "APP_SECRET_KEY": "admin",
            "GRAFANA_ADMIN_PASSWORD": "password",
        }
        violations = find_placeholder_violations(env)
        assert "APP_SECRET_KEY" in violations
        assert "GRAFANA_ADMIN_PASSWORD" in violations

    def test_find_placeholder_violations_allows_strong_secrets(self) -> None:
        """find_placeholder_violations should allow strong secrets."""
        from src.core.security.secret_validator import find_placeholder_violations

        env = {
            "APP_SECRET_KEY": "a" * 32,
            "GRAFANA_ADMIN_PASSWORD": "b" * 32,
        }
        violations = find_placeholder_violations(env)
        assert len(violations) == 0

    def test_find_production_security_violations(self) -> None:
        """find_production_security_violations should detect dangerous config in production."""
        from src.core.security.secret_validator import find_production_security_violations

        env = {
            "APP_ENV": "production",
            "DASHBOARD_AUTH_DISABLED": "true",
            "APP_SECRET_KEY": "dev-secret-key-change-in-production-32chars-minimum-length",
            "SEC_JWT_SECRET": "dev-jwt-secret-key-at-least-32-characters-long-for-hs256",
        }
        violations = find_production_security_violations(env)
        assert len(violations) == 3
        assert any("DASHBOARD_AUTH_DISABLED" in v for v in violations)
        assert any("APP_SECRET_KEY" in v for v in violations)
        assert any("SEC_JWT_SECRET" in v for v in violations)

    def test_find_production_security_violations_ignores_dev(self) -> None:
        """find_production_security_violations should not flag dev environment."""
        from src.core.security.secret_validator import find_production_security_violations

        env = {
            "APP_ENV": "development",
            "DASHBOARD_AUTH_DISABLED": "true",
            "APP_SECRET_KEY": "dev-secret-key-change-in-production-32chars-minimum-length",
            "SEC_JWT_SECRET": "dev-jwt-secret-key-at-least-32-characters-long-for-hs256",
        }
        violations = find_production_security_violations(env)
        assert len(violations) == 0


class TestSSRFProtectionConsistency:
    """Verify SSRF protections are applied consistently."""

    def test_is_safe_url_blocks_private_ips(self) -> None:
        """is_safe_url should block private/loopback IPs."""
        from src.core.utils.url_validation import is_safe_url

        assert not is_safe_url("http://127.0.0.1/secret")
        assert not is_safe_url("http://10.0.0.1/secret")
        assert not is_safe_url("http://192.168.1.1/secret")
        assert not is_safe_url("http://172.16.0.1/secret")
        assert not is_safe_url("http://[::1]/secret")

    def test_is_safe_url_blocks_cloud_metadata(self) -> None:
        """is_safe_url should block cloud metadata endpoints."""
        from src.core.utils.url_validation import is_safe_url

        assert not is_safe_url("http://169.254.169.254/latest/meta-data/")
        assert not is_safe_url("http://metadata.google.internal/")

    def test_is_safe_url_blocks_non_http_schemes(self) -> None:
        """is_safe_url should block non-HTTP schemes."""
        from src.core.utils.url_validation import is_safe_url

        assert not is_safe_url("file:///etc/passwd")
        assert not is_safe_url("gopher://127.0.0.1:6379/_INFO")
        assert not is_safe_url("dict://127.0.0.1:6379/INFO")

    def test_dashboard_validation_blocks_ssrf(self) -> None:
        """Dashboard URL validation should block SSRF attempts."""
        from pathlib import Path

        # Read the validation file to verify SSRF protections exist
        validation_path = (
            Path(__file__).parent.parent.parent / "src" / "dashboard" / "fastapi" / "validation.py"
        )
        content = validation_path.read_text(encoding="utf-8")
        assert "validate_url" in content
        assert "_ALLOWED_URL_SCHEMES" in content
        assert "169.254.169.254" in content


class TestGitignoreCompleteness:
    """Verify .gitignore covers sensitive files."""

    def test_gitignore_covers_env_files(self) -> None:
        """Should have patterns for all .env variants."""
        gitignore_path = Path(__file__).parent.parent.parent / ".gitignore"
        if not gitignore_path.exists():
            pytest.skip(".gitignore not found")

        content = gitignore_path.read_text(encoding="utf-8")
        assert ".env" in content
        assert "!.env.example" in content
        assert "*.env" in content

    def test_gitignore_covers_secrets(self) -> None:
        """Should have patterns for secret files."""
        gitignore_path = Path(__file__).parent.parent.parent / ".gitignore"
        if not gitignore_path.exists():
            pytest.skip(".gitignore not found")

        content = gitignore_path.read_text(encoding="utf-8")
        assert "secrets/" in content
        assert "*.key" in content
        assert "*.pem" in content

    def test_gitignore_covers_credential_files(self) -> None:
        """Should have patterns for credential files."""
        gitignore_path = Path(__file__).parent.parent.parent / ".gitignore"
        if not gitignore_path.exists():
            pytest.skip(".gitignore not found")

        content = gitignore_path.read_text(encoding="utf-8")
        assert "credentials/" in content
        assert "*secret*.json" in content
        assert "service-account*.json" in content
