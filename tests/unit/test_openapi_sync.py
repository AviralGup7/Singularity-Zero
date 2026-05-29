import os
import subprocess
import sys
from pathlib import Path


def test_openapi_validation_and_sync() -> None:
    """Verify that validate_openapi.py runs successfully and detects docs out-of-sync."""
    # Inherit system environment variables to prevent WinError 10106 in Windows sandboxes
    test_env = os.environ.copy()
    test_env["PYTHONPATH"] = "."

    # 1. Run the validator - it must return 0 because we just ran --write and it is in sync
    res = subprocess.run(
        [sys.executable, "scripts/validate_openapi.py"],
        env=test_env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "OpenAPI Validation Gate: [PASS]" in res.stdout
    assert "Documentation Sync Gate: [PASS]" in res.stdout

    # 2. Modify docs/api-reference.md slightly to simulate drift
    docs_path = Path("docs") / "api-reference.md"
    original_content = docs_path.read_text(encoding="utf-8")

    try:
        # Intentionally break synchronization by replacing a minor detail
        modified_content = original_content.replace("mesh_aware: true", "mesh_aware: false")
        docs_path.write_text(modified_content, encoding="utf-8")

        # Run check - it must fail with returncode 1
        res_fail = subprocess.run(
            [sys.executable, "scripts/validate_openapi.py"],
            env=test_env,
            capture_output=True,
            text=True,
        )
        assert res_fail.returncode == 1
        assert "CRITICAL DRIFT: docs/api-reference.md is OUT OF SYNC" in res_fail.stdout

        # Run with --write - it must return 0 and restore sync
        res_write = subprocess.run(
            [sys.executable, "scripts/validate_openapi.py", "--write"],
            env=test_env,
            capture_output=True,
            text=True,
        )
        assert res_write.returncode == 0
        assert "Successfully updated and synchronized" in res_write.stdout

        # Verify sync is fully restored
        res_final = subprocess.run(
            [sys.executable, "scripts/validate_openapi.py"],
            env=test_env,
            capture_output=True,
            text=True,
        )
        assert res_final.returncode == 0
        assert "Documentation Sync Gate: [PASS]" in res_final.stdout

    finally:
        # Ensure we always restore the original content to prevent test pollution
        docs_path.write_text(original_content, encoding="utf-8")
