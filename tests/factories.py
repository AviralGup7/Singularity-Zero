"""
Test data factories using the builder pattern.

Provides chainable builder classes for constructing test data dicts
and objects used across the test suite.
"""

from __future__ import annotations

import copy
from typing import Any


class ResponseBuilder:
    """Builder for mock HTTP response dicts."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {
            "url": "https://example.com/api/v1/test",
            "status_code": 200,
            "body": '{"status": "ok"}',
            "headers": {"Content-Type": "application/json"},
            "response_time": 0.15,
            "redirect_chain": [],
        }

    def with_url(self, url: str) -> ResponseBuilder:
        self._data["url"] = url
        return self

    def with_status(self, code: int) -> ResponseBuilder:
        self._data["status_code"] = code
        return self

    def with_body(self, body: str) -> ResponseBuilder:
        self._data["body"] = body
        return self

    def with_headers(self, headers: dict[str, Any]) -> ResponseBuilder:
        self._data["headers"] = headers
        return self

    def with_header(self, key: str, value: str) -> ResponseBuilder:
        self._data["headers"][key] = value
        return self

    def with_response_time(self, seconds: float) -> ResponseBuilder:
        self._data["response_time"] = seconds
        return self

    def with_redirect_chain(self, chain: list[str]) -> ResponseBuilder:
        self._data["redirect_chain"] = chain
        return self

    def with_json_body(self, obj: dict[str, Any]) -> ResponseBuilder:
        import json

        self._data["body"] = json.dumps(obj)
        self._data["headers"]["Content-Type"] = "application/json"
        return self

    def with_error_body(self, message: str = "Internal Server Error") -> ResponseBuilder:
        self._data["status_code"] = 500
        self._data["body"] = f'{{"error": "{message}"}}'
        return self

    def with_not_found(self) -> ResponseBuilder:
        self._data["status_code"] = 404
        self._data["body"] = '{"error": "Not Found"}'
        return self

    def with_unauthorized(self) -> ResponseBuilder:
        self._data["status_code"] = 401
        self._data["body"] = '{"error": "Unauthorized"}'
        return self

    def build(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)


class FindingBuilder:
    """Builder for mock security finding dicts."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {
            "id": "finding-001",
            "title": "Test Finding",
            "severity": "medium",
            "confidence": "high",
            "category": "injection",
            "url": "https://example.com/api/v1/test",
            "method": "GET",
            "parameter": "id",
            "payload": "1' OR '1'='1",
            "evidence": "SQL syntax error in response",
            "description": "A test security finding",
            "cwe_id": "CWE-89",
            "cvss_score": 7.5,
            "remediation": "Use parameterized queries",
            "tags": ["sqli", "injection"],
            "source": "manual",
            "timestamp": "2026-01-01T00:00:00Z",
        }

    def with_id(self, finding_id: str) -> FindingBuilder:
        self._data["id"] = finding_id
        return self

    def with_title(self, title: str) -> FindingBuilder:
        self._data["title"] = title
        return self

    def with_severity(self, severity: str) -> FindingBuilder:
        self._data["severity"] = severity
        return self

    def with_confidence(self, confidence: str) -> FindingBuilder:
        self._data["confidence"] = confidence
        return self

    def with_category(self, category: str) -> FindingBuilder:
        self._data["category"] = category
        return self

    def with_url(self, url: str) -> FindingBuilder:
        self._data["url"] = url
        return self

    def with_method(self, method: str) -> FindingBuilder:
        self._data["method"] = method
        return self

    def with_parameter(self, param: str) -> FindingBuilder:
        self._data["parameter"] = param
        return self

    def with_payload(self, payload: str) -> FindingBuilder:
        self._data["payload"] = payload
        return self

    def with_evidence(self, evidence: str) -> FindingBuilder:
        self._data["evidence"] = evidence
        return self

    def with_cwe(self, cwe_id: str) -> FindingBuilder:
        self._data["cwe_id"] = cwe_id
        return self

    def with_cvss(self, score: float) -> FindingBuilder:
        self._data["cvss_score"] = score
        return self

    def with_tags(self, tags: list[str]) -> FindingBuilder:
        self._data["tags"] = tags
        return self

    def add_tag(self, tag: str) -> FindingBuilder:
        self._data["tags"].append(tag)
        return self

    def with_source(self, source: str) -> FindingBuilder:
        self._data["source"] = source
        return self

    def with_critical_severity(self) -> FindingBuilder:
        self._data["severity"] = "critical"
        self._data["cvss_score"] = 9.8
        return self

    def with_high_severity(self) -> FindingBuilder:
        self._data["severity"] = "high"
        self._data["cvss_score"] = 8.5
        return self

    def with_low_severity(self) -> FindingBuilder:
        self._data["severity"] = "low"
        self._data["cvss_score"] = 3.1
        return self

    def build(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)


class RequestBuilder:
    """Builder for mock HTTP request dicts."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {
            "method": "GET",
            "url": "https://example.com/api/v1/test",
            "headers": {"Authorization": "Bearer test-token", "Content-Type": "application/json"},
            "body": None,
            "params": {},
            "timeout": 30,
            "allow_redirects": True,
        }

    def with_method(self, method: str) -> RequestBuilder:
        self._data["method"] = method
        return self

    def with_url(self, url: str) -> RequestBuilder:
        self._data["url"] = url
        return self

    def with_headers(self, headers: dict[str, Any]) -> RequestBuilder:
        self._data["headers"] = headers
        return self

    def with_header(self, key: str, value: str) -> RequestBuilder:
        self._data["headers"][key] = value
        return self

    def with_body(self, body: str | dict[str, Any]) -> RequestBuilder:
        if isinstance(body, dict):
            import json

            self._data["body"] = json.dumps(body)
        else:
            self._data["body"] = body
        return self

    def with_json_body(self, obj: dict[str, Any]) -> RequestBuilder:
        import json

        self._data["body"] = json.dumps(obj)
        self._data["headers"]["Content-Type"] = "application/json"
        return self

    def with_params(self, params: dict[str, Any]) -> RequestBuilder:
        self._data["params"] = params
        return self

    def with_param(self, key: str, value: str) -> RequestBuilder:
        self._data["params"][key] = value
        return self

    def with_timeout(self, timeout: int) -> RequestBuilder:
        self._data["timeout"] = timeout
        return self

    def with_auth_token(self, token: str) -> RequestBuilder:
        self._data["headers"]["Authorization"] = f"Bearer {token}"
        return self

    def with_content_type(self, content_type: str) -> RequestBuilder:
        self._data["headers"]["Content-Type"] = content_type
        return self

    def build(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)


class ConfigBuilder:
    """Builder for mock Config objects/dicts."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {
            "target_name": "example.com",
            "output_dir": "output",
            "scope": ["example.com", "api.example.com"],
            "concurrency": {
                "nuclei_workers": 2,
                "http_workers": 5,
                "scan_workers": 3,
            },
            "output": {
                "dedupe_aliases": True,
                "format": "json",
                "include_raw": False,
            },
            "scan": {
                "depth": 2,
                "max_pages": 100,
                "follow_redirects": True,
            },
            "auth": {
                "type": "bearer",
                "token": "test-token",
            },
            "rate_limit": {
                "requests_per_second": 10,
                "burst": 20,
            },
            "logging": {
                "level": "INFO",
                "file": "scan.log",
            },
            "notifications": {
                "enabled": False,
                "channels": [],
            },
        }

    def with_target(self, target: str) -> ConfigBuilder:
        self._data["target_name"] = target
        return self

    def with_output_dir(self, output_dir: str) -> ConfigBuilder:
        self._data["output_dir"] = output_dir
        return self

    def with_scope(self, scope: list[str]) -> ConfigBuilder:
        self._data["scope"] = scope
        return self

    def with_concurrency(self, concurrency: dict[str, int]) -> ConfigBuilder:
        self._data["concurrency"] = concurrency
        return self

    def with_nuclei_workers(self, workers: int) -> ConfigBuilder:
        self._data["concurrency"]["nuclei_workers"] = workers
        return self

    def with_http_workers(self, workers: int) -> ConfigBuilder:
        self._data["concurrency"]["http_workers"] = workers
        return self

    def with_scan_depth(self, depth: int) -> ConfigBuilder:
        self._data["scan"]["depth"] = depth
        return self

    def with_max_pages(self, max_pages: int) -> ConfigBuilder:
        self._data["scan"]["max_pages"] = max_pages
        return self

    def with_auth(self, auth: dict[str, str]) -> ConfigBuilder:
        self._data["auth"] = auth
        return self

    def with_bearer_token(self, token: str) -> ConfigBuilder:
        self._data["auth"] = {"type": "bearer", "token": token}
        return self

    def with_rate_limit(self, rps: int, burst: int = 0) -> ConfigBuilder:
        self._data["rate_limit"] = {
            "requests_per_second": rps,
            "burst": burst or rps * 2,
        }
        return self

    def with_logging_level(self, level: str) -> ConfigBuilder:
        self._data["logging"]["level"] = level
        return self

    def with_output_format(self, fmt: str) -> ConfigBuilder:
        self._data["output"]["format"] = fmt
        return self

    def with_dedupe(self, enabled: bool) -> ConfigBuilder:
        self._data["output"]["dedupe_aliases"] = enabled
        return self

    def build(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)
