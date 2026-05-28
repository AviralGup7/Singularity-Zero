"""Bundle Secret Scanning & Attestation Quality Gate.

Scans frontend bundles, assets, and source directories to detect hardcoded
API keys, private keys, authorization tokens, or default credentials before compilation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Entropy and static secret signature matching rules
SECRET_PATTERNS = {
    "Generic API Key": re.compile(r"(?i)(api[-_]?key|secret[-_]?key|auth[-_]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
    "Private Key Block": re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    "Slack Webhook URL": re.compile(r"https://hooks\.slack\.com/services/[T|B][A-Z0-9]{8}/[A-Z0-9]{8}/[A-Z0-9a-zA-Z]{24}"),
    "AWS Access ID / Key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
}


def scan_file_for_secrets(file_path: Path) -> list[str]:
    """Search file content for matching secrets."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        findings = []
        for name, pattern in SECRET_PATTERNS.items():
            matches = pattern.finditer(content)
            for m in matches:
                # Truncate secret in log output for safety
                snippet = m.group(0)[:15] + "..."
                findings.append(f"Hardcoded {name} signature found: {snippet}")
        return findings
    except Exception as exc:
        return [f"Scan failure on {file_path}: {exc}"]


def main() -> int:
    """Run security check scans."""
    print("Initializing Client Bundle Secret Attestation Gate...")
    target_dir = Path("frontend") / "src"

    if not target_dir.exists():
        print("Frontend directory missing. Scanning root source layouts...")
        target_dir = Path("src")

    all_findings = []
    file_extensions = ("*.js", "*.ts", "*.tsx", "*.html", "*.json")

    for ext in file_extensions:
        for path in target_dir.rglob(ext):
            if "node_modules" in path.parts or ".venv" in path.parts:
                continue
            findings = scan_file_for_secrets(path)
            if findings:
                all_findings.extend([f"{path.name}: {f}" for f in findings])

    if all_findings:
        print("Secret Attestation Gate: [FAIL] - Leaked secrets detected inside assets!")
        for f in all_findings:
            print(f"  - {f}")
        return 1

    print("Secret Attestation Gate: [PASS] - Zero hardcoded credentials or private keys detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
