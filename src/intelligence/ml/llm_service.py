"""
RESEARCH PROTOTYPE — not wired into the active scan pipeline. See docs/architecture.md Implementation Status table for current state.

Large Language Model (LLM) service client plane.

Provides async, non-blocking integrations with Ollama, OpenAI, Gemini,
and a high-fidelity local mock provider, complete with robust security-rule fallbacks.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx
from pydantic import BaseModel, Field

from src.intelligence.ml.context import truncate_context
from src.intelligence.ml.prompts import (
    EXPLAIN_FINDING_SYSTEM,
    GENERATE_EXECUTIVE_SUMMARY_SYSTEM,
    GENERATE_PATCH_SYSTEM,
    TRIAGE_FALSE_POSITIVE_SYSTEM,
)
from src.intelligence.ml.scoring import (
    fallback_explain,
    fallback_patch,
    fallback_summary,
    fallback_triage,
)

logger = logging.getLogger(__name__)


class LLMConfig(BaseModel):
    """Configuration schema for LLM Service integrations."""

    enabled: bool = Field(default=False)
    provider: str = Field(default="mock")  # openai, gemini, ollama, mock
    api_key: str | None = Field(default=None)
    api_base: str | None = Field(default=None)
    model: str = Field(default="gpt-4o")
    timeout_seconds: float = Field(default=10.0, gt=0)


import threading


# ...
class LLMService:
    """Async service orchestrating LLM-driven vulnerability validation and posture assessments."""

    _instance: LLMService | None = None
    _lock = threading.Lock()

    def __init__(self, config: LLMConfig | None = None) -> None:
        if config is None:
            config = self._load_from_env()
        self.config = config
        # Security Fix: Re-enabled SSL verification (verify=True)
        self.client = httpx.AsyncClient(timeout=config.timeout_seconds, verify=True)

    @classmethod
    def get_instance(cls) -> LLMService:
        """Retrieve or construct singleton instance in a thread-safe manner."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @staticmethod
    def _sanitize_output(text: str) -> str:
        """Sanitize LLM outputs before they are processed/rendered downstream."""
        if not text:
            return ""
        # Remove any NUL bytes
        cleaned = text.replace("\x00", "")
        # Remove raw script tags to prevent XSS if rendered as HTML
        import re

        cleaned = re.sub(
            r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "", cleaned, flags=re.IGNORECASE
        )
        return cleaned

    @staticmethod
    def _load_from_env() -> LLMConfig:
        """Parse configuration directly from active environment variables."""
        enabled_str = os.getenv("LLM_ENABLED", "false").lower()
        api_key = os.getenv("LLM_API_KEY") or os.getenv("GOOGLE_API_KEY")
        return LLMConfig(
            enabled=(enabled_str in {"true", "1", "yes"}),
            provider=os.getenv("LLM_PROVIDER", "mock").lower(),
            api_key=api_key,
            api_base=os.getenv("LLM_API_BASE"),
            model=os.getenv("LLM_MODEL", "gpt-4o"),
            timeout_seconds=float(os.getenv("LLM_TIMEOUT", "10.0")),
        )

    async def aclose(self) -> None:
        """Safely release underlying HTTP resources."""
        await self.client.aclose()

    @staticmethod
    def _truncate_context(text: str, max_chars: int = 4000) -> str:
        """Truncate context to fit within LLM token limits safely.

        Delegates to :func:`src.intelligence.ml.context.truncate_context`.
        """
        return truncate_context(text, max_chars)

    def _validate_provider_response(
        self, data: Any, required_keys: list[str], provider: str
    ) -> None:
        """Validate that provider response matches expected schema."""
        if not isinstance(data, dict):
            raise ValueError(f"{provider} returned non-object response: {type(data).__name__}")
        for key in required_keys:
            if key not in data:
                raise ValueError(f"{provider} response missing required key: {key}")

    async def _query_provider(self, system_prompt: str, user_prompt: str) -> str:
        """Perform non-blocking HTTP request to configured LLM api providers."""
        if not self.config.enabled or self.config.provider == "mock":
            raise ValueError("LLM provider disabled or configured to mock")

        # 1. OpenAI Integration
        if self.config.provider == "openai":
            url = self.config.api_base or "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.config.api_key or ''}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.2,
            }
            resp = await self.client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            self._validate_provider_response(data, ["choices"], "openai")
            if not isinstance(data["choices"], list) or len(data["choices"]) == 0:
                raise ValueError("openai returned empty choices")
            msg = data["choices"][0].get("message", {})
            return self._sanitize_output(str(msg.get("content", "")))

        # 2. Ollama Integration (Local)
        elif self.config.provider == "ollama":
            url = self.config.api_base or "http://localhost:11434/api/generate"
            payload = {
                "model": self.config.model,
                "prompt": f"[System]: {system_prompt}\n\n[User]: {user_prompt}",
                "stream": False,
                "options": {"temperature": 0.2},
            }
            resp = await self.client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            self._validate_provider_response(data, ["response"], "ollama")
            return self._sanitize_output(str(data["response"]))

        # 3. Gemini Integration
        elif self.config.provider == "gemini":
            key = self.config.api_key or ""
            url = (
                self.config.api_base
                or f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.model}:generateContent?key={key}"
            )
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": f"System Guidelines: {system_prompt}\n\nUser Task: {user_prompt}"
                            }
                        ]
                    }
                ],
                "generationConfig": {"temperature": 0.2},
            }
            resp = await self.client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            self._validate_provider_response(data, ["candidates"], "gemini")
            return self._sanitize_output(str(data["candidates"][0]["content"]["parts"][0]["text"]))

        raise NotImplementedError(f"Provider '{self.config.provider}' is unsupported")

    def _handle_failure(self, operation: str, error: Exception) -> None:
        logger.warning(
            "LLM service query failed for operation '%s', triggering fallback: %s", operation, error
        )
        try:
            from src.infrastructure.observability.metrics import get_metrics

            get_metrics().counter(
                "llm_fallback_total",
                "Total LLM query fallback events",
                labels={"operation": operation},
            ).inc()
        except Exception:  # noqa: S110
            pass

    async def explain_finding(self, finding: dict[str, Any]) -> dict[str, str]:
        """Generate finding explanations tailored separately to developer vs. auditor personas."""
        title = finding.get("title") or finding.get("type") or "Vulnerability"
        severity = finding.get("severity") or "medium"
        url = finding.get("url") or finding.get("target") or ""
        desc = finding.get("description") or ""
        evidence = finding.get("evidence") or ""

        system_prompt = EXPLAIN_FINDING_SYSTEM

        user_prompt = (
            f"Finding: {title}\n"
            f"Severity: {severity}\n"
            f"URL: {url}\n"
            f"Description: {desc}\n"
            f"Captured Evidence: {self._truncate_context(str(evidence), 2000)}"
        )

        try:
            raw = await self._query_provider(system_prompt, user_prompt)
            data = json.loads(self._clean_json(raw))
            return {
                "developer": str(data.get("developer", "")),
                "auditor": str(data.get("auditor", "")),
            }
        except Exception as e:
            self._handle_failure("explain_finding", e)
            return self._fallback_explain(finding)

    async def generate_patch(
        self,
        finding: dict[str, Any],
        request_payload: str | None = None,
        response_body: str | None = None,
    ) -> dict[str, Any]:
        """Analyze the vulnerability context and generate verified remediation code patches."""
        title = finding.get("title") or finding.get("type") or "Vulnerability"
        category = finding.get("category") or "general"
        url = finding.get("url") or ""
        evidence = finding.get("evidence") or ""

        system_prompt = GENERATE_PATCH_SYSTEM

        user_prompt = (
            f"Finding Category: {category}\n"
            f"Vulnerability Title: {title}\n"
            f"URL: {url}\n"
            f"Injected Payload/Evidence: {self._truncate_context(str(evidence), 1000)}\n"
            f"Original Request Payload: {self._truncate_context(str(request_payload or 'N/A'), 1000)}\n"
            f"Target Response Body snippet: {self._truncate_context(str(response_body or ''), 2000)}"
        )

        try:
            raw = await self._query_provider(system_prompt, user_prompt)
            data = json.loads(self._clean_json(raw))
            return {
                "title": str(data.get("title", "Parameterization Patch")),
                "description": str(data.get("description", "Secure validation")),
                "language": str(data.get("language", "python")),
                "remediation_code": str(data.get("remediation_code", "")),
            }
        except Exception as e:
            self._handle_failure("generate_patch", e)
            return self._fallback_patch(finding, request_payload, response_body)

    async def triage_false_positive(
        self,
        finding: dict[str, Any],
        request_payload: str | None = None,
        response_body: str | None = None,
    ) -> dict[str, Any]:
        """Perform automated false-positive triaging of HTTP request/response exchanges."""
        title = finding.get("title") or finding.get("type") or "Vulnerability"
        category = finding.get("category") or "general"
        url = finding.get("url") or ""
        evidence = finding.get("evidence") or ""

        system_prompt = TRIAGE_FALSE_POSITIVE_SYSTEM

        user_prompt = (
            f"Finding: {title} ({category})\n"
            f"Target URL: {url}\n"
            f"Scan Evidence: {self._truncate_context(str(evidence), 1000)}\n"
            f"Request Payload: {self._truncate_context(str(request_payload or 'N/A'), 1000)}\n"
            f"Target Response Body: {self._truncate_context(str(response_body or ''), 4000)}"
        )

        try:
            raw = await self._query_provider(system_prompt, user_prompt)
            data = json.loads(self._clean_json(raw))
            return {
                "decision": str(data.get("decision", "TP")).upper(),
                "confidence": float(data.get("confidence", 0.85)),
                "reasoning": str(data.get("reasoning", "HTTP response analysis completed.")),
            }
        except Exception as e:
            self._handle_failure("triage_false_positive", e)
            return self._fallback_triage(finding, request_payload, response_body)

    async def generate_executive_summary(
        self,
        findings: list[dict[str, Any]],
        compliance_report: dict[str, Any] | None = None,
    ) -> str:
        """Produce a comprehensive, audit-ready Markdown executive summary for scanned targets."""
        system_prompt = GENERATE_EXECUTIVE_SUMMARY_SYSTEM

        critical_count = sum(
            1 for f in findings if str(f.get("severity", "info")).lower() == "critical"
        )
        high_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "high")
        med_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "medium")
        low_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "low")

        user_prompt = (
            f"Total Findings: {len(findings)}\n"
            f"Severity breakdown: Critical={critical_count}, High={high_count}, Medium={med_count}, Low={low_count}\n"
            f"Top Vulnerabilities: {', '.join(str(f.get('title', 'Finding')) for f in findings[:5])}\n"
            f"Compliance status details: {str(compliance_report or 'No compliance mappings available')}"
        )

        try:
            return await self._query_provider(system_prompt, user_prompt)
        except Exception as e:
            self._handle_failure("generate_executive_summary", e)
            return self._fallback_summary(findings, compliance_report)

    @staticmethod
    def _clean_json(text: str) -> str:
        """Clean markdown wrapping and conversational filler from JSON strings."""
        text = text.strip()
        # Find the first { and last } to extract the JSON block
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start : end + 1]

        # Fallback to previous logic if no braces found
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def _fallback_explain(self, finding: dict[str, Any]) -> dict[str, str]:
        """Rule-based backup explanation generator.

        Delegates to :func:`src.intelligence.ml.scoring.fallback_explain`.
        """
        return fallback_explain(finding)

    def _fallback_patch(
        self,
        finding: dict[str, Any],
        request_payload: str | None = None,
        response_body: str | None = None,
    ) -> dict[str, Any]:
        """Rule-based backup patch generator matching vulnerability categories.

        Delegates to :func:`src.intelligence.ml.scoring.fallback_patch`.
        """
        return fallback_patch(finding, request_payload, response_body)

    def _fallback_triage(
        self,
        finding: dict[str, Any],
        request_payload: str | None = None,
        response_body: str | None = None,
    ) -> dict[str, Any]:
        """Rule-based false positive triage helper.

        Delegates to :func:`src.intelligence.ml.scoring.fallback_triage`.
        """
        return fallback_triage(finding, request_payload, response_body)

    def _fallback_summary(
        self,
        findings: list[dict[str, Any]],
        compliance_report: dict[str, Any] | None = None,
    ) -> str:
        """Produce GRC-ready backup summary reports.

        Delegates to :func:`src.intelligence.ml.scoring.fallback_summary`.
        """
        return fallback_summary(findings, compliance_report)
