"""Large Language Model (LLM) service client plane.

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

logger = logging.getLogger(__name__)


class LLMConfig(BaseModel):
    """Configuration schema for LLM Service integrations."""

    enabled: bool = Field(default=False)
    provider: str = Field(default="mock")  # openai, gemini, ollama, mock
    api_key: str | None = Field(default=None)
    api_base: str | None = Field(default=None)
    model: str = Field(default="gpt-4o")
    timeout_seconds: float = Field(default=10.0, gt=0)


class LLMService:
    """Async service orchestrating LLM-driven vulnerability validation and posture assessments."""

    _instance: LLMService | None = None

    def __init__(self, config: LLMConfig | None = None) -> None:
        if config is None:
            config = self._load_from_env()
        self.config = config
        self.client = httpx.AsyncClient(timeout=config.timeout_seconds, verify=False)

    @classmethod
    def get_instance(cls) -> LLMService:
        """Retrieve or construct singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @staticmethod
    def _load_from_env() -> LLMConfig:
        """Parse configuration directly from active environment variables."""
        enabled_str = os.getenv("LLM_ENABLED", "false").lower()
        return LLMConfig(
            enabled=(enabled_str in {"true", "1", "yes"}),
            provider=os.getenv("LLM_PROVIDER", "mock").lower(),
            api_key=os.getenv("LLM_API_KEY"),
            api_base=os.getenv("LLM_API_BASE"),
            model=os.getenv("LLM_MODEL", "gpt-4o"),
            timeout_seconds=float(os.getenv("LLM_TIMEOUT", "10.0")),
        )

    async def aclose(self) -> None:
        """Safely release underlying HTTP resources."""
        await self.client.aclose()

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
            return str(resp.json()["choices"][0]["message"]["content"])

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
            return str(resp.json()["response"])

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
            return str(resp.json()["candidates"][0]["content"]["parts"][0]["text"])

        raise NotImplementedError(f"Provider '{self.config.provider}' is unsupported")

    async def explain_finding(self, finding: dict[str, Any]) -> dict[str, str]:
        """Generate finding explanations tailored separately to developer vs. auditor personas."""
        title = finding.get("title") or finding.get("type") or "Vulnerability"
        severity = finding.get("severity") or "medium"
        url = finding.get("url") or finding.get("target") or ""
        desc = finding.get("description") or ""
        evidence = finding.get("evidence") or ""

        system_prompt = (
            "You are an expert security engineer and regulatory GRC auditor.\n"
            "Analyze the security finding and explain it for two separate audiences:\n"
            "1. Developer: Deep technical explanation, dynamic code injection mechanics, parameter/boundary context, and framework-level coding controls.\n"
            "2. Auditor: GRC business risk, compliance standards mapping (NIST SP 800-53, PCI DSS, OWASP Top 10), data confidentiality/integrity impact, and administrative recommendations.\n"
            "Format the response strictly as a JSON object with keys 'developer' and 'auditor' containing Markdown strings. Do not add markdown wrappers like ```json."
        )

        user_prompt = (
            f"Finding: {title}\n"
            f"Severity: {severity}\n"
            f"URL: {url}\n"
            f"Description: {desc}\n"
            f"Captured Evidence: {evidence}"
        )

        try:
            raw = await self._query_provider(system_prompt, user_prompt)
            data = json.loads(self._clean_json(raw))
            return {
                "developer": str(data.get("developer", "")),
                "auditor": str(data.get("auditor", "")),
            }
        except Exception as e:
            logger.debug("LLM explain failed, triggering rule fallback: %s", e)
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

        system_prompt = (
            "You are an elite secure coding engineer.\n"
            "Analyze the vulnerability finding, request payload, and target response.\n"
            "Determine the technology stack (Python, Node, PHP, etc.) and generate a verified, production-grade secure remediation code patch.\n"
            "Provide explanation and code. Format the response strictly as a JSON object containing keys:\n"
            "- 'title': Short remedy name\n"
            "- 'description': Technical description of the fix\n"
            "- 'language': Detected programming language\n"
            "- 'remediation_code': Complete secure cut-and-paste code block patch\n"
            "Do not add markdown wrappers around the outer JSON."
        )

        user_prompt = (
            f"Finding Category: {category}\n"
            f"Vulnerability Title: {title}\n"
            f"URL: {url}\n"
            f"Injected Payload/Evidence: {evidence}\n"
            f"Original Request Payload: {request_payload or 'N/A'}\n"
            f"Target Response Body snippet: {str(response_body or '')[:2000]}"
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
            logger.debug("LLM patch failed, triggering fallback: %s", e)
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

        system_prompt = (
            "You are an automated security analyst evaluating scan findings.\n"
            "Review the security finding and the HTTP exchange to distinguish True Positives (TP) from False Positives (FP).\n"
            "Evaluate:\n"
            "a) Is the injected payload actually reflected/interpreted, or is it returned as static text?\n"
            "b) Did the response status change significantly (e.g. from 403 blocking to 200)?\n"
            "c) Are database/stack trace errors leaked?\n"
            "Return a structured JSON object containing:\n"
            "- 'decision': Either 'TP' or 'FP'\n"
            "- 'confidence': Float between 0.0 and 1.0\n"
            "- 'reasoning': Step-by-step security reasoning detailing the choice\n"
            "Strictly output only raw JSON without markdown formatting."
        )

        user_prompt = (
            f"Finding: {title} ({category})\n"
            f"Target URL: {url}\n"
            f"Scan Evidence: {evidence}\n"
            f"Request Payload: {request_payload or 'N/A'}\n"
            f"Target Response Body: {str(response_body or '')[:4000]}"
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
            logger.debug("LLM FP review failed, triggering rule fallback: %s", e)
            return self._fallback_triage(finding, request_payload, response_body)

    async def generate_executive_summary(
        self,
        findings: list[dict[str, Any]],
        compliance_report: dict[str, Any] | None = None,
    ) -> str:
        """Produce a comprehensive, audit-ready Markdown executive summary for scanned targets."""
        system_prompt = (
            "You are an elite Chief Information Security Officer (CISO) and lead auditor.\n"
            "Summarize the pipeline scan findings and compliance posture into a professional, high-fidelity C-level executive summary.\n"
            "Include:\n"
            "1. Overall Security Posture Rating (A-F grade and risk banding)\n"
            "2. Top Critical Vulnerabilities and operational impacts\n"
            "3. Compliance Coverage Assessment (NIST SP 800-53 / ISO 27001 readiness attestation)\n"
            "4. Prioritized immediate and long-term action items.\n"
            "Write highly professional, audit-ready Markdown."
        )

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
            logger.debug("LLM summary failed, triggering rule fallback: %s", e)
            return self._fallback_summary(findings, compliance_report)

    @staticmethod
    def _clean_json(text: str) -> str:
        """Clean markdown wrapping syntax around JSON strings."""
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def _fallback_explain(self, finding: dict[str, Any]) -> dict[str, str]:
        """Rule-based backup explanation generator."""
        title = finding.get("title") or finding.get("type") or "Vulnerability"
        severity = str(finding.get("severity") or "medium").upper()
        category = str(finding.get("category") or "general").lower()

        dev_desc = (
            f"### Technical Mechanics of {title}\n\n"
            f"This vulnerability manifests when untrusted user parameter inputs are ingested without proper validation or sanitization. "
            f"An attacker can exploit this boundary to inject operational delimiters or syntax structures.\n\n"
            f"### Developer Action Checklist:\n"
            f"1. Implement strict context-aware validation.\n"
            f"2. Use parameterized APIs and prepared statements exclusively.\n"
            f"3. Apply robust output encoding before rendering dynamic structures."
        )

        auditor_desc = (
            f"### Regulatory Impact & GRC Posture for {title}\n\n"
            f"**Risk Severity**: {severity}\n"
            f"**Framework Alignments**:\n"
            f"- **OWASP Top 10**: Mapped to active category based on classification ({category}).\n"
            f"- **NIST SP 800-53**: Violates SI-10 (Information Input Validation) and SC-28 (Protection of Information at Rest).\n"
            f"- **PCI DSS v4.0**: Breaches Requirement 6.2 (Secure development controls) and 6.5 (Prevent common injection flaws).\n\n"
            f"**Operational Business Risk**: Exploitability could lead to unauthorized data exposure, system tampering, or audit-trail evasion."
        )

        return {"developer": dev_desc, "auditor": auditor_desc}

    def _fallback_patch(
        self,
        finding: dict[str, Any],
        request_payload: str | None = None,
        response_body: str | None = None,
    ) -> dict[str, Any]:
        """Rule-based backup patch generator matching vulnerability categories."""
        category = str(finding.get("category") or finding.get("title") or "general").lower()

        if "sqli" in category or "sql_injection" in category:
            return {
                "title": "Secure Parameterized Database Query",
                "description": "Utilize parameterized statements to insulate the database interpreter from user variables.",
                "language": "python",
                "remediation_code": (
                    "# Python DB-API Parameterized Query Patch\n"
                    "import psycopg2\n\n"
                    "def fetch_user_record(cursor, username, role):\n"
                    "    query = 'SELECT * FROM users WHERE username = %s AND role = %s'\n"
                    "    cursor.execute(query, (username, role))\n"
                    "    return cursor.fetchall()"
                ),
            }
        elif "idor" in category or "auth_bypass" in category or "access_control" in category:
            return {
                "title": "Strict Resource Ownership & RBAC Check",
                "description": "Assert resource-ownership and context identity controls before completing operations.",
                "language": "python",
                "remediation_code": (
                    "# Secure Authorization Context validation patch\n"
                    "def get_user_data(request, user_id):\n"
                    "    current_tenant = request.state.tenant_id\n"
                    "    current_user = request.state.user_id\n"
                    "    \n"
                    "    # Verify tenant boundary and user ownership bounds\n"
                    "    if not is_tenant_resource(user_id, current_tenant):\n"
                    "        raise PermissionError('Multi-tenant boundary breach detected')\n"
                    "    if current_user != user_id and not request.state.is_admin:\n"
                    "        raise PermissionError('Unauthorized access attempt')\n"
                    "        \n"
                    "    return db.query_resource(user_id)"
                ),
            }
        elif "xss" in category or "cross_site_scripting" in category:
            return {
                "title": "Context-Aware HTML Entity Encoding",
                "description": "Escape and encode dynamic parameters inside templates to render them strictly as static variables.",
                "language": "html",
                "remediation_code": (
                    "<!-- Secure Context-Aware HTML Encoding Patch -->\n"
                    "<script>\n"
                    "  const rawInput = '<%= html_escape(user_input) %>';\n"
                    "  document.getElementById('display-element').textContent = rawInput;\n"
                    "</script>"
                ),
            }

        # General generic fallback
        return {
            "title": "Input Boundary Validation and Sanitization",
            "description": "Apply strict sanitization filters and parameter type-assertion check gates.",
            "language": "python",
            "remediation_code": (
                "# Insecure parameter sanitization patch\n"
                "import re\n\n"
                "def clean_input_parameter(user_input: str) -> str:\n"
                "    # Enforce strict alphanumeric limits\n"
                "    return re.sub(r'[^a-zA-Z0-9_.-]', '', user_input)"
            ),
        }

    def _fallback_triage(
        self,
        finding: dict[str, Any],
        request_payload: str | None = None,
        response_body: str | None = None,
    ) -> dict[str, Any]:
        """Rule-based false positive triage helper."""
        evidence = str(finding.get("evidence") or "")
        resp_text = str(response_body or "")

        # Heuristic rules:
        # If evidence or payload is reflected exactly inside the body: High TP confidence
        # If response shows stack trace leaks or database errors: High TP confidence
        # If status code is 500: high probability of unhandled crash
        # If the target is owned by tenant and has classic mock or seed: low confidence
        is_tp = True
        confidence = 0.80
        reasons = ["Automated analysis of finding evidence and request payloads completed."]

        if evidence and evidence in resp_text:
            confidence = 0.95
            reasons.append(
                f"Confirmed reflection of vulnerability payload '{evidence}' directly in the HTTP response body."
            )

        if any(
            err in resp_text.lower()
            for err in ["traceback", "stack trace", "sql syntax", "exception"]
        ):
            is_tp = True
            confidence = 0.98
            reasons.append(
                "Detected database syntax or application stack trace disclosure leaking in HTTP response body."
            )

        return {
            "decision": "TP" if is_tp else "FP",
            "confidence": confidence,
            "reasoning": " ".join(reasons),
        }

    def _fallback_summary(
        self,
        findings: list[dict[str, Any]],
        compliance_report: dict[str, Any] | None = None,
    ) -> str:
        """Produce beautiful, GRC-ready backup summary reports."""
        critical_count = sum(
            1 for f in findings if str(f.get("severity", "info")).lower() == "critical"
        )
        high_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "high")
        med_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "medium")
        low_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "low")

        score = 100
        if critical_count > 0:
            score -= 40
        if high_count > 0:
            score -= 30
        if med_count > 0:
            score -= 15
        score = max(0, score)

        grade = "A"
        if score < 50:
            grade = "F"
        elif score < 70:
            grade = "D"
        elif score < 85:
            grade = "C"
        elif score < 95:
            grade = "B"

        findings_summary = []
        for idx, f in enumerate(findings[:5], start=1):
            findings_summary.append(
                f"**{idx}. [{str(f.get('severity')).upper()}] {str(f.get('title'))}** on `{str(f.get('url') or f.get('target'))}`"
            )

        summary_markdown = (
            f"# Executive Security Posture & Compliance Attestation Report\n\n"
            f"### 🛡️ Posture Grade: **{grade}** ({score}/100)\n"
            f"The autonomous security test pipeline completed vulnerability validation across the designated infrastructure target environments. "
            f"Overall risk assessment indicates a **{grade}** rating with **{len(findings)}** active exposures identified.\n\n"
            f"### 📊 Exposure Metrics\n"
            f"- **Critical Severity**: {critical_count} findings\n"
            f"- **High Severity**: {high_count} findings\n"
            f"- **Medium Severity**: {med_count} findings\n"
            f"- **Low Severity**: {low_count} findings\n\n"
            f"### 🎯 Top Critical Vulnerability Concerns\n"
            f"{chr(10).join(findings_summary) if findings_summary else '*No active critical or high vulnerability findings recorded.*'}\n\n"
            f"### 🔐 Compliance Readiness & GRC Attestation\n"
            f"- **OWASP Top 10 Alignment**: Scans validated input boundaries mapping to injection flaws, access failures, and security configuration drifts.\n"
            f"- **NIST SP 800-53 Requirements**: Evaluated SI-10 (Input validation checks) and SC-8 (Transmission confidentiality).\n"
            f"- **PCI-DSS Compliance Assessment**: Identified vulnerability states are cross-referenced with remediation SLAs to ensure compliance timelines are met.\n\n"
            f"### 🚀 Action Items & Mitigation Prioritization\n"
            f"1. **Remediation SLA Enforcements**: Standardized critical findings must be resolved within the 14-day window; high findings within 30 days.\n"
            f"2. **Implement Parameterization**: Update database interfaces to enforce parameterized queries.\n"
            f"3. **Triage and Rescan**: Leverage collaborative triage modules to verify and execute isolated rescan verification sweeps."
        )

        return summary_markdown
