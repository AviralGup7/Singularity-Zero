#!/usr/bin/env python3
"""Export OpenAPI specification from the FastAPI application.

Usage:
    python scripts/export_openapi.py

This script generates docs/openapi.yaml from the FastAPI app's OpenAPI schema.
Run this after significant API changes to keep documentation in sync.
"""

import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    import yaml
except ImportError:
    print("PyYAML not installed. Install with: pip install pyyaml")
    sys.exit(1)


def export_openapi():
    """Export the OpenAPI spec to docs/openapi.yaml."""
    try:
        from src.dashboard.fastapi.app_factory import create_app
        
        app = create_app()
        openapi_schema = app.openapi()
        
        docs_dir = project_root / "docs"
        docs_dir.mkdir(exist_ok=True)
        
        output_path = docs_dir / "openapi.yaml"
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(openapi_schema, f, default_flow_style=False, allow_unicode=True)
        
        print(f"OpenAPI spec exported to {output_path}")
        return True
        
    except Exception as e:
        print(f"Error exporting OpenAPI spec: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    success = export_openapi()
    sys.exit(0 if success else 1)
