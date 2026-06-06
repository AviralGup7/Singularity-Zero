"""Unit tests for the lazy-imported subdomain source modules.

These tests cover the contract guarantees the dynamic registrar in
``src.recon.subdomains`` relies on:

* every module exports ``query_<source>`` as an async callable
* invalid / hostile domain inputs short-circuit to ``set()``
* HTTP failures (network, non-200, rate limit, auth failure) degrade
  to an empty set without raising
* happy-path JSON / HTML responses yield the expected subdomain set
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.recon.sources import (
    bufferover,
    certspotter,
    chaos,
    dnsdumpster,
    rapiddns,
    securitytrails,
    spyse,
    virustotal,
)


def _mock_response(status_code: int, body: str | bytes, content_type: str = "application/json"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    if isinstance(body, bytes):
        resp.text = body.decode("utf-8", errors="replace")
        resp.content = body
    else:
        resp.text = body
        resp.content = body.encode("utf-8")
    if isinstance(body, str) and body and content_type.endswith("json"):
        resp.json = MagicMock(return_value=json.loads(body))
    else:
        resp.json = MagicMock(side_effect=ValueError("no json"))
    return resp


def _async_client_mock(*responses):
    """Build an ``httpx.AsyncClient`` context manager for the given response sequence.

    Each response in ``responses`` is returned in order across ``get`` and
    ``post`` calls.  We use a single shared queue plus an async side
    effect so that the first method call (whether ``get`` or ``post``)
    consumes the first response, the second call consumes the next, and
    so on.
    """
    queue: list = list(responses)

    async def _next_response(*_args, **_kwargs):
        if not queue:
            raise RuntimeError("no more mock responses configured")
        return queue.pop(0)

    client = MagicMock()
    client.get = AsyncMock(side_effect=_next_response)
    client.post = AsyncMock(side_effect=_next_response)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm, client


# ---------------------------------------------------------------------------
# Module surface: dynamic registrar imports ``query_<source>`` from each.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module, expected_name",
    [
        (dnsdumpster, "query_dnsdumpster"),
        (bufferover, "query_bufferover"),
        (certspotter, "query_certspotter"),
        (spyse, "query_spyse"),
        (securitytrails, "query_securitytrails"),
        (chaos, "query_chaos"),
    ],
)
def test_module_exposes_query_function(module, expected_name):
    func = getattr(module, expected_name, None)
    assert func is not None, f"missing {expected_name}"
    assert callable(func)


# ---------------------------------------------------------------------------
# DNSDumpster
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dnsdumpster_invalid_domain_returns_empty():
    assert await dnsdumpster.query_dnsdumpster("") == set()
    assert await dnsdumpster.query_dnsdumpster("not a domain") == set()
    assert await dnsdumpster.query_dnsdumpster("example\x00.com") == set()
    assert await dnsdumpster.query_dnsdumpster("1.2.3.4") == set()


@pytest.mark.asyncio
async def test_dnsdumpster_happy_path_parses_subdomains():
    landing_html = (
        '<html><body><form>'
        '<input type="hidden" name="csrfmiddlewaretoken" value="abc123token" />'
        '</form></body></html>'
    )
    results_html = (
        "<html><body><table class='table'>"
        "<tr><td class='col-md-4'>www.example.com</td></tr>"
        "<tr><td class='col-md-4'>api.example.com</td></tr>"
        "<tr><td class='col-md-4'>*.unrelated.org</td></tr>"
        "</table></body></html>"
    )
    landing_resp = _mock_response(200, landing_html, "text/html")
    search_resp = _mock_response(200, results_html, "text/html")
    cm, client = _async_client_mock(landing_resp, search_resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await dnsdumpster.query_dnsdumpster("example.com", timeout=5)

    assert result == {"www.example.com", "api.example.com"}
    assert client.post.await_count == 1


@pytest.mark.asyncio
async def test_dnsdumpster_missing_csrf_token_returns_empty():
    landing_resp = _mock_response(200, "<html></html>", "text/html")
    cm, _ = _async_client_mock(landing_resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await dnsdumpster.query_dnsdumpster("example.com", timeout=5)

    assert result == set()


# ---------------------------------------------------------------------------
# BufferOver
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bufferover_invalid_domain_returns_empty():
    assert await bufferover.query_bufferover("") == set()
    assert await bufferover.query_bufferover("bad domain.com") == set()


@pytest.mark.asyncio
async def test_bufferover_parses_dns_and_tls_results():
    dns_body = json.dumps(
        {
            "Results": [
                "1.2.3.4,www.example.com",
                "5.6.7.8,api.example.com,alias.example.com",
            ]
        }
    )
    tls_body = json.dumps({"Results": ["mail.example.com"]})
    dns_resp = _mock_response(200, dns_body)
    tls_resp = _mock_response(200, tls_body)
    cm, _ = _async_client_mock(dns_resp, tls_resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await bufferover.query_bufferover("example.com", timeout=5)

    assert result == {"www.example.com", "api.example.com", "alias.example.com", "mail.example.com"}


@pytest.mark.asyncio
async def test_bufferover_rate_limit_stops_iteration():
    rate_resp = _mock_response(429, "")
    cm, client = _async_client_mock(rate_resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await bufferover.query_bufferover("example.com", timeout=5)

    assert result == set()
    # Should not hammer the second endpoint after a 429.
    assert client.get.await_count == 1


# ---------------------------------------------------------------------------
# CertSpotter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_certspotter_invalid_domain_returns_empty():
    assert await certspotter.query_certspotter("") == set()


@pytest.mark.asyncio
async def test_certspotter_parses_dns_names():
    body = json.dumps(
        [
            {"id": 1, "dns_names": ["www.example.com", "*.api.example.com"]},
            {"id": 2, "dns_names": ["mail.example.com"]},
        ]
    )
    resp = _mock_response(200, body)
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await certspotter.query_certspotter("example.com", timeout=5)

    assert result == {"www.example.com", "api.example.com", "mail.example.com"}


@pytest.mark.asyncio
async def test_certspotter_uses_api_key_header_when_provided(monkeypatch):
    monkeypatch.delenv("CERTSPOTTER_API_KEY", raising=False)
    resp = _mock_response(200, "[]")
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm) as client_cls:
        await certspotter.query_certspotter(
            "example.com", api_key="sekret", timeout=5
        )

    kwargs = client_cls.call_args.kwargs
    assert kwargs["headers"]["Authorization"] == "Bearer sekret"


# ---------------------------------------------------------------------------
# Spyse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spyse_without_api_key_returns_empty(monkeypatch):
    monkeypatch.delenv("SPYSE_API_KEY", raising=False)
    assert await spyse.query_spyse("example.com") == set()


@pytest.mark.asyncio
async def test_spyse_auth_failure_returns_empty(monkeypatch):
    monkeypatch.setenv("SPYSE_API_KEY", "dead-key")
    resp = _mock_response(401, "")
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await spyse.query_spyse("example.com", timeout=5)

    assert result == set()


# ---------------------------------------------------------------------------
# SecurityTrails
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_securitytrails_without_api_key_returns_empty(monkeypatch):
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    assert await securitytrails.query_securitytrails("example.com") == set()


@pytest.mark.asyncio
async def test_securitytrails_joins_labels_with_apex():
    body = json.dumps({"subdomains": ["www", "api", "staging", "mail"]})
    resp = _mock_response(200, body)
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await securitytrails.query_securitytrails(
            "example.com", api_key="token", timeout=5
        )

    assert result == {
        "www.example.com",
        "api.example.com",
        "staging.example.com",
        "mail.example.com",
    }


@pytest.mark.asyncio
async def test_securitytrails_accepts_fully_qualified_subdomains():
    body = json.dumps({"subdomains": ["deep.nested.example.com", "example.com"]})
    resp = _mock_response(200, body)
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await securitytrails.query_securitytrails(
            "example.com", api_key="token", timeout=5
        )

    assert result == {"deep.nested.example.com", "example.com"}


@pytest.mark.asyncio
async def test_securitytrails_rejects_unrelated_labels():
    body = json.dumps({"subdomains": ["", " ", "evil.org"]})
    resp = _mock_response(200, body)
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await securitytrails.query_securitytrails(
            "example.com", api_key="token", timeout=5
        )

    assert result == set()


# ---------------------------------------------------------------------------
# Chaos (ProjectDiscovery)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chaos_without_api_key_returns_empty(monkeypatch):
    monkeypatch.delenv("CHAOS_API_KEY", raising=False)
    monkeypatch.delenv("PDCP_API_KEY", raising=False)
    assert await chaos.query_chaos("example.com") == set()


@pytest.mark.asyncio
async def test_chaos_reads_pdcp_api_key_as_fallback(monkeypatch):
    monkeypatch.delenv("CHAOS_API_KEY", raising=False)
    monkeypatch.setenv("PDCP_API_KEY", "pd-key")
    body = json.dumps(["www.example.com", "api.example.com", "evil.org"])
    resp = _mock_response(200, body)
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm) as client_cls:
        result = await chaos.query_chaos("example.com", timeout=5)

    kwargs = client_cls.call_args.kwargs
    assert kwargs["headers"]["Authorization"] == "pd-key"
    assert result == {"www.example.com", "api.example.com"}


@pytest.mark.asyncio
async def test_chaos_handles_dict_payload_with_domains_key():
    body = json.dumps({"domains": ["www.example.com", "vpn.example.com"]})
    resp = _mock_response(200, body)
    cm, _ = _async_client_mock(resp)

    with patch.object(httpx, "AsyncClient", return_value=cm):
        result = await chaos.query_chaos(
            "example.com", api_key="token", timeout=5
        )

    assert result == {"www.example.com", "vpn.example.com"}


# ---------------------------------------------------------------------------
# Sanity: existing two modules still work and remain importable.
# ---------------------------------------------------------------------------


def test_existing_modules_still_importable():
    # The new __init__ re-exports the legacy modules, so importing them
    # via the package must keep working.
    assert callable(virustotal.query_virustotal_passive)
    assert callable(rapiddns.query_rapiddns)
