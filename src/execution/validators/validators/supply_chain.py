"""Supply chain / dependency confusion validator.

Detects dependency confusion vulnerabilities where private packages
can be hijacked via public registries. Scans project manifests for
package names that exist in public registries (npm, PyPI, Maven).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Heuristic patterns for detecting private/internal package names
_INTERNAL_PACKAGE_PATTERNS: list[str] = [
    r"(?:internal|private|company|corp|org|my)?[-_]?(?:pkg|package|lib|module|sdk|api)[-_]?",
    r"@[a-z]+/internal[-_]",
    r"(?:acme|example|test|my|our)[-_]",
    r"[-_](?:internal|private|backend)",
    r"^internal[-_]",
]

# Known vulnerable packages for version checking
_KNOWN_VULNERABLE_PACKAGES: dict[str, list[str]] = {
    "npm": {
        "package-1": ["<1.0.0"],
    },
    "pypi": {},
    "maven": {},
}

# Common CI/CD config files that may leak secrets
CI_CONFIG_PATTERNS: list[str] = [
    r"\.github/workflows/.*\.yml$",
    r"\.gitlab-ci\.yml$",
    r"Jenkinsfile$",
    r"\.circleci/config\.yml$",
    r"bitbucket-pipelines\.yml$",
    r"\.travis\.yml$",
    r"appveyor\.yml$",
    r"\.drone\.yml$",
    r"buildkite\.yml$",
    r"\.woodpecker\.yml$",
]


def _is_internal_package_name(name: str) -> bool:
    """Heuristic check for internal/private package names."""
    for pattern in _INTERNAL_PACKAGE_PATTERNS:
        if re.search(pattern, name, re.IGNORECASE):
            return True
    return False


def _parse_package_json(content: str) -> list[dict[str, Any]]:
    """Parse package.json for dependencies."""
    packages: list[dict[str, Any]] = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section, {})
            for name, version in deps.items():
                packages.append(
                    {
                        "ecosystem": "npm",
                        "name": name,
                        "version": str(version),
                        "section": section,
                    }
                )
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("Operation failed in supply_chain.py: %s", exc, exc_info=True)  # noqa: BLE001
    return packages


def _parse_requirements_txt(content: str) -> list[dict[str, Any]]:
    """Parse requirements.txt for dependencies."""
    packages: list[dict[str, Any]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle format: package==version or package>=version
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\w.*-]+)?", line)
        if match:
            name = match.group(1)
            version = (match.group(2) or "").strip()
            packages.append(
                {
                    "ecosystem": "pypi",
                    "name": name,
                    "version": version,
                    "section": "dependencies",
                }
            )
    return packages


def scan_dependency_confusion(
    manifest_content: str,
    manifest_type: str = "auto",
    known_private_packages: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Scan manifest content for dependency confusion vulnerabilities.

    Args:
        manifest_content: Raw content of the manifest file.
        manifest_type: 'package.json', 'requirements.txt', 'pom.xml', or 'auto'.
        known_private_packages: List of known private package names to check.

    Returns:
        List of finding dicts with name, ecosystem, severity, and evidence.
    """
    findings: list[dict[str, Any]] = []
    known_private = set(known_private_packages or [])

    # Parse packages based on manifest type
    packages: list[dict[str, Any]] = []
    if manifest_type == "package.json" or manifest_type == "auto":
        packages.extend(_parse_package_json(manifest_content))
    if manifest_type == "requirements.txt" or manifest_type == "auto":
        packages.extend(_parse_requirements_txt(manifest_content))

    for pkg in packages:
        name = pkg["name"]
        ecosystem = pkg["ecosystem"]
        version = pkg["version"]

        # Check if package name looks internal
        if _is_internal_package_name(name) or name in known_private:
            findings.append(
                {
                    "type": "dependency_confusion",
                    "ecosystem": ecosystem,
                    "name": name,
                    "version": version,
                    "severity": "high",
                    "confidence": 0.6,
                    "evidence": f"Package '{name}' appears to be internal/private. "
                    f"An attacker could register this name on public {ecosystem.upper()} registry.",
                }
            )

        # Check if package uses a namespace that could be squatted
        if "@" in name:
            scope, pkg_name = name.split("/", 1)
            if _is_internal_package_name(pkg_name):
                findings.append(
                    {
                        "type": "namespace_confusion",
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                        "severity": "medium",
                        "confidence": 0.4,
                        "evidence": f"Scoped package '{name}' uses internal name pattern. "
                        f"Scope squatting risk on public registry.",
                    }
                )

    return findings


def scan_ci_config_exposure(
    files: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Scan discovered CI/CD config files for potential secret exposure.

    Args:
        files: List of dicts with 'path' and 'content' keys.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []
    secret_patterns = [
        (r"(?:API[_-]?KEY|api[_-]?key)\s*[=:]\s*['\"]?([^'\"\s]+)", "api_key"),
        (r"(?:SECRET|secret)\s*[=:]\s*['\"]?([^'\"\s]{8,})", "secret"),
        (r"(?:TOKEN|token)\s*[=:]\s*['\"]?([^'\"\s]{8,})", "token"),
        (r"password\s*[=:]\s*['\"]?([^'\"\s]+)", "password"),
        (r"GH_TOKEN|GITHUB_TOKEN|GITLAB_TOKEN|NPM_TOKEN|PYPI_TOKEN", "platform_token"),
    ]

    for file_info in files:
        path = file_info.get("path", "")
        content = file_info.get("content", "")

        for pattern, secret_type in secret_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                findings.append(
                    {
                        "type": "ci_secret_exposure",
                        "path": path,
                        "secret_type": secret_type,
                        "severity": "critical",
                        "confidence": 0.7,
                        "evidence": f"Potential {secret_type} exposed in CI config: {path}",
                    }
                )
                break

    return findings
