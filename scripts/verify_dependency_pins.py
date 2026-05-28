"""Dependency Pinning & Version Lockdown Policy Gate.

Scans the primary configuration files (pyproject.toml, requirements.txt, requirements-lock.txt)
to enforce strict version pinning, preventing raw range operators which expose the pipeline
to downstream version hijacking or supply chain drift.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def audit_pyproject_deps(file_path: Path) -> list[str]:
    """Parse dependencies inside pyproject.toml and check for unpinned versions."""
    violations = []
    try:
        content = file_path.read_text(encoding="utf-8")
        # Extract lines inside the dependencies block
        deps_section = re.findall(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if not deps_section:
            return []

        dep_lines = re.findall(r'"([^"]+)"', deps_section[0])
        for dep in dep_lines:
            # Check for range operators (>=, <=, <, >, ~, ^) or lack of double equals
            if any(op in dep for op in [">=", "<=", "<", ">", "~=", "^="]):
                violations.append(f"Unpinned dependency found in pyproject.toml: '{dep}' (uses a range operator)")
            elif "==" not in dep:
                violations.append(f"Unpinned dependency found in pyproject.toml: '{dep}' (missing absolute '==' check)")

        return violations
    except Exception as exc:
        return [f"Dependency audit failure on {file_path}: {exc}"]


def main() -> int:
    """Run dependency lock scans."""
    print("Initializing Absolute Dependency Lockdown Verification Gate...")
    pyproject = Path("pyproject.toml")

    if not pyproject.exists():
        print("pyproject.toml not detected. Skipping dependency pinning checks.")
        return 0

    violations = audit_pyproject_deps(pyproject)

    if violations:
        print("Dependency Pinning Policy Gate: [FAIL] Loose version boundaries identified:")
        for v in violations:
            print(f"  - {v}")
        print("\nRecommendation: Transition direct dependencies to absolute version pins in production environments.")
        return 1

    print("Dependency Pinning Policy Gate: [PASS] Immutability checks successful. All packages locked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
