"""OpenAPI Contract Quality, Schema Drift, and Documentation Sync Gate.

Validates active FastAPI dashboard schemas against a baseline specification
to prevent accidental downstream integration breaks, and synchronizes the
documentation in docs/api-reference.md.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


def enrich_openapi_metadata(openapi_spec: dict[str, Any]) -> dict[str, Any]:
    """Inject AI-metadata and endpoint-level x-ai actions into the OpenAPI spec."""
    # 1. Top-level x-ai-metadata
    openapi_spec["info"]["x-ai-metadata"] = {
        "agent_roles": ["orchestrator", "worker", "dashboard", "auditor"],
        "stateful_endpoints": ["/api/jobs/{id}", "/api/jobs/{id}/progress/stream"],
        "mesh_aware": True,
    }

    # 2. Path-level x-ai mapping
    ai_meta_mapping = {
        ("/api/jobs", "get"): {"x-ai-action": "list_jobs", "x-ai-idempotency": True},
        ("/api/jobs", "post"): {
            "x-ai-action": "start_scan",
            "x-ai-requires": ["base_url"],
            "x-ai-idempotency": False,
            "x-ai-impact": "high",
        },
        ("/api/health/ready", "get"): {"x-ai-action": "check_readiness", "x-ai-idempotency": True},
        ("/api/health/mesh", "get"): {"x-ai-action": "get_mesh_health", "x-ai-idempotency": True},
        ("/api/bloom/health", "get"): {"x-ai-action": "get_bloom_health", "x-ai-idempotency": True},
        ("/api/bloom/reconcile", "post"): {
            "x-ai-action": "reconcile_bloom_mesh",
            "x-ai-idempotency": True,
            "x-ai-impact": "medium",
        },
        ("/api/findings/{finding_id}", "put"): {
            "x-ai-action": "update_finding",
            "x-ai-idempotency": False,
        },
        ("/api/findings/{finding_id}", "delete"): {
            "x-ai-action": "delete_finding",
            "x-ai-idempotency": False,
            "x-ai-impact": "high",
        },
        ("/api/remediated/{finding_id}/verify", "post"): {
            "x-ai-action": "verify_remediation",
            "x-ai-idempotency": False,
            "x-ai-impact": "medium",
            "x-ai-requires": ["finding_id"],
        },
    }

    for (path_pattern, method), meta in ai_meta_mapping.items():
        if path_pattern in openapi_spec.get("paths", {}):
            if method in openapi_spec["paths"][path_pattern]:
                for k, v in meta.items():
                    openapi_spec["paths"][path_pattern][method][k] = v

    return openapi_spec


def main() -> int:
    """Validate openapi.json structure, drift metrics, and sync api-reference.md."""
    print("Initializing OpenAPI Schema Quality Gate & Doc Sync...")
    baseline_path = Path("configs") / "openapi-baseline.json"
    current_path = Path("output") / "openapi.json"
    docs_path = Path("docs") / "api-reference.md"

    # 1. Dynamically generate active OpenAPI schema from FastAPI app
    try:
        from src.dashboard.fastapi.app import create_app

        app = create_app()
        active_openapi = app.openapi()

        # Save generated openapi.json to output directory
        current_path.parent.mkdir(parents=True, exist_ok=True)
        current_path.write_text(json.dumps(active_openapi, indent=2), encoding="utf-8")
        print(f"Successfully generated active OpenAPI schema at {current_path}")
    except Exception as exc:
        print(f"Error generating active OpenAPI schema dynamically: {exc}")
        return 2

    if not baseline_path.exists():
        print(f"Baseline file missing at {baseline_path}. Bootstrapping configuration...")
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps({"paths": {}, "components": {}}, indent=2))

    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        current = json.loads(current_path.read_text(encoding="utf-8"))

        drift_detected = False
        # Analyze top-level path modifications
        baseline_paths = set(baseline.get("paths", {}).keys())
        current_paths = set(current.get("paths", {}).keys())

        removed_paths = baseline_paths - current_paths
        if removed_paths:
            print(f"CRITICAL DRIFT: Removed endpoints detected! {removed_paths}")
            drift_detected = True

        # Check for removed methods on remaining paths
        for path in baseline_paths & current_paths:
            baseline_methods = set(baseline["paths"][path].keys())
            current_methods = set(current["paths"][path].keys())
            removed_methods = baseline_methods - current_methods
            if removed_methods:
                print(f"CRITICAL DRIFT: Removed methods {removed_methods} on endpoint '{path}'!")
                drift_detected = True

        # Analyze component schema modifications
        baseline_schemas = baseline.get("components", {}).get("schemas", {})
        current_schemas = current.get("components", {}).get("schemas", {})

        for name, baseline_schema in baseline_schemas.items():
            if name not in current_schemas:
                print(f"CRITICAL DRIFT: Removed schema '{name}'!")
                drift_detected = True
                continue

            current_schema = current_schemas[name]
            # Check for removed properties
            baseline_props = set(baseline_schema.get("properties", {}).keys())
            current_props = set(current_schema.get("properties", {}).keys())
            removed_props = baseline_props - current_props
            if removed_props:
                print(f"CRITICAL DRIFT: Removed properties {removed_props} from schema '{name}'!")
                drift_detected = True

            # Check for type changes in remaining properties
            for prop in baseline_props & current_props:
                b_prop = baseline_schema["properties"][prop]
                c_prop = current_schema["properties"][prop]
                b_type = b_prop.get("type") or b_prop.get("$ref")
                c_type = c_prop.get("type") or c_prop.get("$ref")
                if b_type != c_type:
                    print(
                        f"CRITICAL DRIFT: Type changed for '{name}.{prop}'! (expected {b_type}, got {c_type})"
                    )
                    drift_detected = True

            # Check if any new required fields were added
            baseline_req = set(baseline_schema.get("required", []))
            current_req = set(current_schema.get("required", []))
            new_req = current_req - baseline_req
            if new_req:
                print(f"CRITICAL DRIFT: Newly required fields {new_req} added to schema '{name}'!")
                drift_detected = True

        if drift_detected:
            print("OpenAPI Validation Gate: [FAIL] - Breaking changes identified.")
            return 1

        print("OpenAPI Validation Gate: [PASS] - Schemas are fully backward-compatible.")

        # 2. Enrich OpenAPI schema and validate docs/api-reference.md
        enriched_spec = enrich_openapi_metadata(dict(active_openapi))
        yaml_str = yaml.dump(enriched_spec, sort_keys=False, default_flow_style=False)

        if not docs_path.exists():
            print(f"Documentation file missing at {docs_path}. Bootstrapping...")
            docs_path.parent.mkdir(parents=True, exist_ok=True)
            docs_path.write_text("# API Reference\n\n```yaml\n```\n", encoding="utf-8")

        current_doc_content = docs_path.read_text(encoding="utf-8")

        # Regex substitution to place YAML inside the fenced block
        updated_doc_content = re.sub(
            r"```yaml\n.*?\n```", f"```yaml\n{yaml_str}```", current_doc_content, flags=re.DOTALL
        )

        write_mode = "--write" in sys.argv
        if current_doc_content != updated_doc_content:
            if write_mode:
                docs_path.write_text(updated_doc_content, encoding="utf-8")
                print(
                    f"Successfully updated and synchronized {docs_path} with active OpenAPI spec."
                )
                return 0
            else:
                print(
                    "CRITICAL DRIFT: docs/api-reference.md is OUT OF SYNC with active FastAPI spec!"
                )
                print(
                    "Please run: python scripts/validate_openapi.py --write to synchronize the file."
                )
                return 1
        else:
            print("Documentation Sync Gate: [PASS] - docs/api-reference.md is fully in sync.")
            return 0

    except Exception as exc:
        print(f"Validation failure: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
