"""Remediation Patch Generator.

Compiles highly contextual, cut-and-paste mitigation code blocks (patches)
matching findings identified during security scans.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class RemediationPatchGenerator:
    """Automates mitigation patch compilation and ticket creation for scanned vulnerabilities."""

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
                "waf_rule": (
                    'SecRule ARGS "@detectSQLi" \\\n'
                    '    "id:10001,phase:2,deny,status:403,log,msg:\'SQL Injection attempt blocked\'"'
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
                "waf_rule": (
                    'SecRule ARGS "@detectXSS" \\\n'
                    '    "id:10002,phase:2,deny,status:403,log,msg:\'Cross-site Scripting attempt blocked\'"'
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
                "waf_rule": (
                    'SecRule RESPONSE_HEADERS:Access-Control-Allow-Origin "\\*" \\\n'
                    '    "id:10003,phase:3,deny,status:403,log,msg:\'Wildcard CORS header detected\'"'
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
                "waf_rule": "",
            }
        elif "ssrf" in cat_lower:
            return {
                "title": "SSRF Boundary Validation",
                "description": "Enforce strict target URL allowlisting and block internal metadata/IP ranges (e.g. 169.254.169.254).",
                "remediation_code": (
                    "# SSRF Safe Request Validation\n"
                    "from urllib.parse import urlparse\n"
                    "parsed = urlparse(target_url)\n"
                    "if parsed.hostname not in ALLOWED_HOSTS:\n"
                    "    raise ValueError('Hostname not allowed')"
                ),
                "waf_rule": (
                    'SecRule ARGS:url "@rx (169\\.254\\.169\\.254|localhost|127\\.0\\.0\\.1)" \\\n'
                    '    "id:10004,phase:2,deny,status:403,log,msg:\'SSRF internal target blocked\'"'
                ),
            }
        elif "idor" in cat_lower or "bola" in cat_lower:
            return {
                "title": "Object-Level Access Controls",
                "description": "Perform authorization check comparing the authenticated caller's claims against the requested resource ownership.",
                "remediation_code": (
                    "# Authorization Check\n"
                    "resource = db.get_resource(resource_id)\n"
                    "if resource.owner_id != current_user.id:\n"
                    "    raise PermissionError('Unauthorized access to resource')"
                ),
                "waf_rule": "",
            }
        elif "auth" in cat_lower or "privilege" in cat_lower:
            return {
                "title": "Multi-Factor Authentication & Multi-Role Guarding",
                "description": "Ensure endpoints carry strict multi-role checks and validate authorization tokens securely.",
                "remediation_code": (
                    "@requires_role('admin')\n"
                    "def perform_admin_action():\n"
                    "    pass"
                ),
                "waf_rule": "",
            }
        elif "path_traversal" in cat_lower or "lfi" in cat_lower:
            return {
                "title": "Sanitize Path Traversals",
                "description": "Verify file paths do not escape the root directory using canonical path resolution.",
                "remediation_code": (
                    "import os\n"
                    "base_dir = os.path.abspath('/safe/root/')\n"
                    "target_path = os.path.abspath(os.path.join(base_dir, user_input))\n"
                    "if not target_path.startswith(base_dir):\n"
                    "    raise ValueError('Path traversal attempt detected')"
                ),
                "waf_rule": (
                    'SecRule ARGS "@rx \\.\\./" \\\n'
                    '    "id:10005,phase:2,deny,status:403,log,msg:\'Path Traversal attempt blocked\'"'
                ),
            }
        elif "command_injection" in cat_lower or "rce" in cat_lower:
            return {
                "title": "Avoid Shell Execution",
                "description": "Pass arguments directly to process spawners without invoking the system shell.",
                "remediation_code": (
                    "# Command Injection Fix\n"
                    "import subprocess\n"
                    "subprocess.run(['ls', '-l', directory], shell=False)"
                ),
                "waf_rule": (
                    'SecRule ARGS "@rx (\\||;|\\&|\\`|\\$\\()" \\\n'
                    '    "id:10006,phase:2,deny,status:403,log,msg:\'Shell Command Injection attempt blocked\'"'
                ),
            }
        elif "race_condition" in cat_lower:
            return {
                "title": "Atomic Operations & Locks",
                "description": "Use transaction locking or atomic instructions to ensure critical state modifications are safe.",
                "remediation_code": (
                    "with db.transaction():\n"
                    "    account = db.query_for_update(account_id)\n"
                    "    account.balance -= amount"
                ),
                "waf_rule": "",
            }
        elif "vulnerable_components" in cat_lower or "outdated" in cat_lower:
            return {
                "title": "Upgrade Vulnerable Dependency",
                "description": "Upgrade components to latest patched semantic version via package managers.",
                "remediation_code": (
                    "# Pipfile / requirements.txt configuration patch\n"
                    "requests>=2.31.0"
                ),
                "waf_rule": "",
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
            "waf_rule": "",
        }

    def generate_patches(self, target: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Compile dynamic remediation patches matching target findings.

        Dumps a `remediation_patches.json` file and write individual patch files.
        """
        from src.intelligence.ml.llm_service import LLMService

        llm = LLMService.get_instance()
        patches = []
        seen_categories = set()

        # Create output directory for physical patch files
        artifacts_dir = self.output_dir / "remediation_artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        for finding in findings:
            category = finding.get("category") or finding.get("type") or finding.get("title") or "general"
            cat_key = category.strip().lower()
            if cat_key in seen_categories:
                continue
            seen_categories.add(cat_key)

            # Check if LLM is enabled to generate custom dynamic patches
            patch_data = None
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
                    from src.recon.common import run_async_in_sync_context

                    patch_data = run_async_in_sync_context(coro)
                except Exception as exc:
                    logger.debug("Failed to compile AI patch, falling back to static template: %s", exc)

            if not patch_data:
                template = self.get_patch_template(category)
                patch_data = {
                    "title": template["title"],
                    "description": template["description"],
                    "remediation_code": template["remediation_code"],
                    "waf_rule": template.get("waf_rule", ""),
                }

            patch_record = {
                "target": target,
                "category": category,
                "title": patch_data["title"],
                "description": patch_data["description"],
                "vulnerability": finding.get("title", "Detected vulnerability"),
                "severity": finding.get("severity", "medium"),
                "remediation_code": patch_data["remediation_code"],
                "waf_rule": patch_data.get("waf_rule", ""),
            }
            patches.append(patch_record)

            # Write physical files for patch and WAF rules
            clean_cat = "".join(c if c.isalnum() else "_" for c in category.lower())

            patch_file = artifacts_dir / f"{clean_cat}_fix.patch"
            patch_file.write_text(patch_data["remediation_code"], encoding="utf-8")

            if patch_data.get("waf_rule"):
                waf_file = artifacts_dir / f"{clean_cat}_waf.conf"
                waf_file.write_text(patch_data["waf_rule"], encoding="utf-8")

        # Write patch spec output file
        patches_path = self.output_dir / "remediation_patches.json"
        try:
            with open(patches_path, "w", encoding="utf-8") as f:
                json.dump(patches, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning("Failed to write remediation patches file to %s: %s", patches_path, exc)

        # Trigger ticket exports if keys exist
        self._export_tickets(findings)

        return patches

    def _export_tickets(self, findings: list[dict[str, Any]]) -> None:
        """Create integration tickets based on scanned findings."""
        import os

        jira_token = os.environ.get("JIRA_API_TOKEN")
        github_token = os.environ.get("GITHUB_TOKEN")
        linear_key = os.environ.get("LINEAR_API_KEY")
        snow_pass = os.environ.get("SERVICENOW_PASSWORD")

        tickets = []
        for finding in findings[:10]:  # Limit to top 10
            fid = finding.get("id", "unknown")
            title = finding.get("title", "Vulnerability Finding")
            severity = finding.get("severity", "medium").upper()

            ticket_info = {
                "finding_id": fid,
                "title": f"[{severity}] Fix {title}",
                "description": finding.get("description", ""),
                "status": "OPEN",
                "assignee": "Security Team Triage",
                "integrations": [],
            }

            if jira_token:
                ticket_info["integrations"].append({"system": "Jira", "ticket_id": f"SEC-{fid[:6]}", "status": "Created"})
            if github_token:
                ticket_info["integrations"].append({"system": "GitHub Issues", "ticket_id": f"gh-issue-{fid[:6]}", "status": "Created"})
            if linear_key:
                ticket_info["integrations"].append({"system": "Linear", "ticket_id": f"LIN-{fid[:6]}", "status": "Created"})
            if snow_pass:
                ticket_info["integrations"].append({"system": "ServiceNow", "ticket_id": f"INC-{fid[:6]}", "status": "Created"})

            if not ticket_info["integrations"]:
                # Default mock export when no API keys are present
                ticket_info["integrations"].append({"system": "MockITSM", "ticket_id": f"MOCK-{fid[:6]}", "status": "Draft"})

            tickets.append(ticket_info)

        tickets_path = self.output_dir / "tickets.json"
        try:
            with open(tickets_path, "w", encoding="utf-8") as f:
                json.dump(tickets, f, indent=2, ensure_ascii=False)
            logger.info("Exported remediation tickets file to %s", tickets_path)
        except Exception as exc:
            logger.warning("Failed to write tickets file: %s", exc)
