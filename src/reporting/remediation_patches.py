"""Remediation Patch Generator.

Compiles highly contextual, cut-and-paste mitigation code blocks (patches)
matching findings identified during security scans.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class RemediationPatchGenerator:
    """Automates mitigation patch compilation for scanned vulnerabilities."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)

    def get_patch_template(self, category: str) -> dict[str, str]:
        """Fetch patch configurations matching a vulnerability category."""
        cat_lower = category.strip().lower()

        if "sql_injection" in cat_lower or "sqli" in cat_lower:
            return {
                "title": "Parameterize SQL Queries",
                "description": "Ensure all database inputs are parameterized instead of using dynamic string concatenation.",
                "remediation_code": (
                    "# Python DB-API Parameterized Query Patch Example\n"
                    'cursor.execute("SELECT * FROM users WHERE username = %s AND role = %s", (user_input, role))'
                ),
            }
        elif "xss" in cat_lower or "cross_site_scripting" in cat_lower:
            return {
                "title": "Context-aware Output Encoding",
                "description": "Escape all dynamic user inputs before rendering them inside HTML views.",
                "remediation_code": (
                    "<!-- HTML Output Escaping Patch Example -->\n"
                    "<div><%= html_escape(user_input) %></div>"
                ),
            }
        elif "cors" in cat_lower or "cross_origin" in cat_lower:
            return {
                "title": "Restrict CORS Access Control Origin",
                "description": "Configure explicit domain boundaries instead of utilizing wildcard headers.",
                "remediation_code": (
                    "# Secure Web Server Header Configuration Patch Example\n"
                    "Access-Control-Allow-Origin: https://trusted-origin.example.com\n"
                    "Access-Control-Allow-Credentials: true"
                ),
            }
        elif "csrf" in cat_lower:
            return {
                "title": "Validate Anti-CSRF Tokens",
                "description": "Enforce strict state-changing Anti-CSRF token verification and SameSite cookie policies.",
                "remediation_code": (
                    "# Secure Cookie Headers Patch Example\n"
                    "Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Strict"
                ),
            }

        # Default fallback
        return {
            "title": "General Security Hardening Patch",
            "description": "Sanitize and validate all external boundary inputs.",
            "remediation_code": (
                "# Secure Parameter Input Validator\n"
                "if not is_valid_input(user_input):\n"
                "    raise ValueError('Insecure characters detected')"
            ),
        }

    def generate_patches(self, target: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Compile dynamic remediation patches matching target findings.

        Dumps a `remediation_patches.json` file in output target root.
        """
        import asyncio
        import logging

        from src.intelligence.ml.llm_service import LLMService

        logger = logging.getLogger(__name__)
        llm = LLMService.get_instance()
        patches = []
        seen_categories = set()

        for finding in findings:
            category = finding.get("category") or finding.get("title") or "general"
            cat_key = category.strip().lower()
            if cat_key in seen_categories:
                continue
            seen_categories.add(cat_key)

            # Check if LLM is enabled to generate custom dynamic patches
            if llm.config.enabled:
                req_payload = (
                    finding.get("request_payload")
                    or finding.get("payload")
                    or finding.get("evidence")
                )
                resp_body = (
                    finding.get("response_body") or finding.get("response") or finding.get("body")
                )

                try:
                    coro = llm.generate_patch(finding, req_payload, resp_body)
                    try:
                        loop = asyncio.get_running_loop()
                        if loop.is_running():
                            import concurrent.futures

                            with concurrent.futures.ThreadPoolExecutor() as executor:
                                future = executor.submit(lambda: asyncio.run(coro))
                                patch_data = future.result()
                        else:
                            patch_data = asyncio.run(coro)
                    except RuntimeError:
                        patch_data = asyncio.run(coro)

                    patches.append(
                        {
                            "target": target,
                            "category": category,
                            "title": patch_data["title"],
                            "description": patch_data["description"],
                            "vulnerability": finding.get("title", "Detected vulnerability"),
                            "severity": finding.get("severity", "medium"),
                            "remediation_code": patch_data["remediation_code"],
                        }
                    )
                    continue
                except Exception as exc:
                    logger.debug(
                        "Failed to compile AI patch, falling back to static template: %s", exc
                    )

            template = self.get_patch_template(category)
            patches.append(
                {
                    "target": target,
                    "category": category,
                    "title": template["title"],
                    "description": template["description"],
                    "vulnerability": finding.get("title", "Detected vulnerability"),
                    "severity": finding.get("severity", "medium"),
                    "remediation_code": template["remediation_code"],
                }
            )

        # Write patch spec output file
        patches_path = self.output_dir / "remediation_patches.json"
        try:
            with open(patches_path, "w", encoding="utf-8") as f:
                json.dump(patches, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        return patches
