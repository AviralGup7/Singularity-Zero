"""Tests for the security headers produced by validation.security_headers."""

from src.dashboard.fastapi.validation import security_headers


def test_security_headers_includes_hsts():
    h = security_headers()
    assert "Strict-Transport-Security" in h
    assert "max-age=" in h["Strict-Transport-Security"]


def test_security_headers_csp_drops_unsafe_inline_for_style():
    h = security_headers()
    csp = h["Content-Security-Policy"]
    # The style-src directive must not allow 'unsafe-inline' (it should
    # rely on nonces or hashes).
    assert "style-src" in csp
    # Find the style-src directive
    directives = [d.strip() for d in csp.split(";")]
    style_directive = next(d for d in directives if d.startswith("style-src"))
    assert "'unsafe-inline'" not in style_directive


def test_security_headers_has_clickjacking_protection():
    h = security_headers()
    assert h.get("X-Frame-Options") in ("DENY", "SAMEORIGIN")
    # CSP frame-ancestors is also present
    csp = h["Content-Security-Policy"]
    assert "frame-ancestors" in csp


def test_security_headers_referrer_policy():
    h = security_headers()
    assert h.get("Referrer-Policy") in (
        "no-referrer",
        "same-origin",
        "strict-origin-when-cross-origin",
    )
