"""Unit tests for enterprise ticketing clients (Jira, ServiceNow, DefectDojo)."""

from __future__ import annotations

import json
import pytest
import httpx
from src.reporting.platforms.jira import JiraClient, _map_jira_priority
from src.reporting.platforms.servicenow import ServiceNowClient, _map_servicenow_impact_urgency
from src.reporting.platforms.defectdojo import DefectDojoClient, _map_defectdojo_severity
from src.reporting.platforms.base import SubmissionEnvelope


@pytest.mark.asyncio
async def test_jira_client_not_ready():
    client = JiraClient(base_url="", api_token="")
    assert not client.ready
    res = await client.submit({"title": "SQL Injection", "severity": "critical"})
    assert not res.ok
    assert "not configured" in res.error


@pytest.mark.asyncio
async def test_jira_client_submission(monkeypatch):
    client = JiraClient(
        base_url="https://jira.example.com",
        email="security@example.com",
        api_token="dummy_token",
        project_key="SEC",
        issue_type="Bug",
    )
    assert client.ready

    async def mock_post(url, json=None, headers=None):
        req = httpx.Request("POST", str(url), json=json, headers=headers)
        return httpx.Response(201, json={"id": "10001", "key": "SEC-101"}, request=req)

    client._client = httpx.AsyncClient()
    monkeypatch.setattr(client._client, "post", mock_post)

    env = SubmissionEnvelope(
        title="SQL Injection Vulnerability",
        description="Found SQLi in /api/users",
        severity="critical",
        target_url="https://example.com/api/users",
        target_name="example.com",
        category="injection",
    )
    res = await client.submit(env)
    assert res.ok
    assert res.external_id == "SEC-101"
    assert res.url == "https://jira.example.com/browse/SEC-101"
    await client.aclose()


@pytest.mark.asyncio
async def test_servicenow_client_submission(monkeypatch):
    client = ServiceNowClient(
        instance_url="https://instance.service-now.com",
        username="admin",
        password="secretpassword",
        table_name="incident",
    )
    assert client.ready

    async def mock_post(url, json=None, headers=None):
        req = httpx.Request("POST", str(url), json=json, headers=headers)
        return httpx.Response(201, json={"result": {"sys_id": "abc12345", "number": "INC0010001"}}, request=req)

    client._client = httpx.AsyncClient()
    monkeypatch.setattr(client._client, "post", mock_post)

    res = await client.submit({"title": "XSS in Profile", "severity": "high", "category": "xss"})
    assert res.ok
    assert res.external_id == "INC0010001"
    assert "nav_to.do" in res.url
    await client.aclose()


@pytest.mark.asyncio
async def test_defectdojo_client_submission(monkeypatch):
    client = DefectDojoClient(
        base_url="https://defectdojo.example.com",
        api_key="dojokey12345",
        test_id=42,
    )
    assert client.ready
    assert client.test_id == 42

    async def mock_post(url, json=None, headers=None):
        req = httpx.Request("POST", str(url), json=json, headers=headers)
        return httpx.Response(201, json={"id": 999}, request=req)

    client._client = httpx.AsyncClient()
    monkeypatch.setattr(client._client, "post", mock_post)

    res = await client.submit({"title": "IDOR in /orders", "severity": "high", "category": "idor"})
    assert res.ok
    assert res.external_id == "999"
    assert res.url == "https://defectdojo.example.com/finding/999"
    await client.aclose()


def test_priority_mappings():
    assert _map_jira_priority("critical") == "Highest"
    assert _map_jira_priority("high") == "High"
    assert _map_jira_priority("low") == "Low"

    assert _map_servicenow_impact_urgency("critical") == ("1", "1")
    assert _map_servicenow_impact_urgency("high") == ("1", "2")

    assert _map_defectdojo_severity("critical") == "Critical"
    assert _map_defectdojo_severity("low") == "Low"
