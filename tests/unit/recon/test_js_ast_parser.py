"""Unit tests for the Deep JS AST Parser & Route Extractor."""

from __future__ import annotations

from src.recon.js_parsers import _extract_js_ast_endpoints, _extract_js_candidate_urls


def test_extract_js_ast_endpoints():
    """Verify that template literals, axios/fetch calls, and concats are extracted."""
    js_content = """
    // 1. Template literals
    const url1 = `/api/v1/${version}/users/${userId}/profile`;
    const url2 = `/api/v2/items/${itemId}`;

    // 2. Axios and fetch calls
    axios.get('/api/v3/billing/invoice');
    fetch(`/api/v4/reports/${reportId}`);
    $.ajax('/api/v5/settings');

    // 3. String concatenation
    var route = '/api/v6/users/' + id + '/details';
    var simpleConcat = '/api/v7/posts/' + postId;
    """

    candidates = _extract_js_ast_endpoints(js_content)

    assert "/api/v1/{param}/users/{param}/profile" in candidates
    assert "/api/v2/items/{param}" in candidates
    assert "/api/v3/billing/invoice" in candidates
    assert "/api/v4/reports/{param}" in candidates
    assert "/api/v5/settings" in candidates
    assert "/api/v6/users/{param}/details" in candidates
    assert "/api/v7/posts/{param}" in candidates


def test_extract_js_candidate_urls_with_ast():
    """Verify integration of AST candidate URLs inside candidate url resolver."""
    js_content = """
    const apiRoute = `/api/v1/${version}/users`;
    axios.post('/api/v1/auth/login');
    """

    scope_roots = {"example.com"}
    base_url = "https://example.com/app/index.js"

    discovered = _extract_js_candidate_urls(js_content, base_url, scope_roots)

    # Candidate URLs should be resolved to absolute target scoped URLs
    assert "https://example.com/api/v1/{param}/users" in discovered
    assert "https://example.com/api/v1/auth/login" in discovered
