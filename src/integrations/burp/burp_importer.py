"""Parse Burp Suite exports into pipeline-native finding structures."""

from __future__ import annotations

import html
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from src.core.models import Finding
from src.core.models.entities import SeverityLevel

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _BurpIssueRecord:
    issue_type: str
    name: str
    severity: str
    confidence: str
    url: str
    request_response: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _SitemapRecord:
    url: str
    method: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _HttpHistoryRecord:
    url: str
    method: str
    status_code: int | None
    response_time_seconds: float = 0.0
    response_length: int = 0
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)


def _severity_to_sarif_level(value: str | None) -> str:
    normalised = (value or "info").strip().lower()
    mapping = {
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(normalised, "note")


def _burp_severity_to_level(value: str | None) -> SeverityLevel:
    normalised = (value or "info").strip().lower()
    mapping: dict[str, SeverityLevel] = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(normalised, "info")


def _coerce_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def parse_issues_xml(path: str) -> list[Finding]:
    """Parse Burp Suite's issues.xml export into Finding objects."""
    findings: list[Finding] = []
    try:
        import xml.etree.ElementTree as ET

        tree = ET.parse(path)  # noqa: S314
        root = tree.getroot()
    except Exception as exc:
        logger.error("Failed to parse Burp issues XML: %s", exc)
        return findings

    for issue in root.iter("issue"):
        name = (issue.findtext("name") or "").strip()
        issue_type = (
            issue.findtext("issueType")
            or issue.findtext("type")
            or issue.findtext("issue_type")
            or ""
        ).strip()
        severity = (issue.findtext("severity") or "").strip()
        confidence = (issue.findtext("confidence") or "").strip()
        url = ""
        background = issue.findtext("background")
        remediation = issue.findtext("remediationDetail")

        for entry in issue.iter("requestresponse"):
            url_node = entry.find("url")
            if url_node is not None and url_node.text:
                url = url_node.text.strip()
                break

        for entry in issue.iter("requestresponse"):
            req = entry.findtext("request") or ""
            resp = entry.findtext("response") or ""
            html.escape(req) + "\n\n" + html.escape(resp)
            if req or resp:
                break

        evidence: dict[str, Any] = {
            "burp_issue_type": issue_type,
            "burp_confidence": confidence,
            "background": background or "",
            "remediation": remediation or "",
        }
        request_responses = []
        for entry in issue.iter("requestresponse"):
            req_node = entry.find("request")
            res_node = entry.find("response")
            if req_node is not None or res_node is not None:
                request_responses.append(
                    {
                        "request": req_node.text if req_node is not None else "",
                        "response": res_node.text if res_node is not None else "",
                    }
                )
        if request_responses:
            evidence["request_responses"] = request_responses

        if not url:
            continue
        try:
            finding = Finding(
                category="external_burp",
                title=name or "Burp Suite finding",
                url=url,
                severity=_burp_severity_to_level(severity),
                confidence=_burp_confidence_to_float(confidence),
                evidence=evidence,
                signals=[issue_type, severity, confidence],
            )
            findings.append(finding)
        except Exception as exc:
            logger.debug("Skipping malformed Burp issue: %s", exc)
    return findings


def _burp_confidence_to_fluid_confidence(value: str) -> float:
    normalised = (value or "certain").strip().lower()
    mapping = {
        "certain": 0.95,
        "firm": 0.8,
        "tentative": 0.6,
    }
    return mapping.get(normalised, 0.5)


def _burp_confidence_to_float(value: str) -> float:
    normalised = (value or "certain").strip().lower()
    mapping = {
        "certain": 0.95,
        "firm": 0.8,
        "tentative": 0.6,
    }
    return mapping.get(normalised, 0.5)


def parse_sitemap_json(path: str) -> list[dict[str, Any]]:
    """Parse Burp SiteMap JSON export to seed priority_urls.

    Accepts either a list of entries or a wrapper object with a ``urls`` key.
    """
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, dict):
        items = payload.get("urls") or payload.get("items") or payload.get("sitemap") or []
    elif isinstance(payload, list):
        items = payload
    else:
        items = []
    priority_urls: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or item.get("requestUrl") or "").strip()
        if not url:
            continue
        method = str(item.get("method") or item.get("request_method") or "GET").upper()
        req = item.get("request") or {}
        params: dict[str, Any] = {}
        if isinstance(req, dict):
            params = req.get("params") or req.get("query") or {}
        record = {
            "url": url,
            "method": method,
            "burp_entry": item,
            "params": params,
        }
        if "path" in item:
            record["path"] = item.get("path")
        if "status" in item:
            record["burp_status"] = item.get("status")
        priority_urls.append(record)
    return priority_urls


def import_http_history(path: str) -> list[_HttpHistoryRecord]:
    """Parse Burp HTTP replay export file."""
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, dict):
        items = payload.get("items") or payload.get("requests") or payload.get("history") or []
    elif isinstance(payload, list):
        items = payload
    else:
        items = []
    records: list[_HttpHistoryRecord] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = _deep_get(item, ["url", "requestUrl", "final_url"])
        method = str(_deep_get(item, ["method", "request_method"]) or "GET").upper()
        status = item.get("status_code") or item.get("status") or item.get("response_status")
        try:
            status_code = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_code = None
        timing = _deep_get(item, ["response_time", "timing"])
        timing_value = 0.0
        if isinstance(timing, dict):
            timing_value = float(timing.get("seconds") or timing.get("ms") or 0.0)
        elif isinstance(timing, (int, float)):
            timing_value = float(timing)
        response_length = 0
        resp = item.get("response") or item.get("res") or {}
        if isinstance(resp, dict):
            body = resp.get("body") or resp.get("body_text") or ""
            try:
                response_length = len(str(body))
            except Exception:
                response_length = 0
        records.append(
            _HttpHistoryRecord(
                url=str(url).strip(),
                method=method,
                status_code=status_code,
                response_time_seconds=timing_value,
                response_length=response_length,
                request=item.get("request") or {},
                response=resp,
            )
        )
    return records


def _deep_get(item: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in item:
            return item[key]
    return None
