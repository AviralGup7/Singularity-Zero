"""Automatic API Schema Reconstruction.

Processes lists of endpoints collected during reconnaissance and compiles them
into a fully structured, standard OpenAPI 3.0.0 specification JSON file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse


class ApiSchemaReconstructor:
    """Clusters raw endpoints and structures them into valid OpenAPI 3.0 specs."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)

    def parameterize_path(self, path: str) -> tuple[str, list[str]]:
        """Normalize paths by replacing numerical and UUID segments with parameters.

        Returns parameterized path and the names of parameters extracted.
        """
        # Ensure path starts with a single slash and strip trailing
        path = "/" + path.strip("/")
        if path == "/":
            return "/", []

        # UUID Pattern
        uuid_pattern = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        )
        # ID Pattern (Numerical)
        num_pattern = re.compile(r"^\d+$")

        segments = path.split("/")
        parameterized_segments = []
        parameters = []
        param_counter = 1

        for segment in segments:
            if not segment:
                continue

            # Detect placeholder/parameters already extracted by JS AST
            if segment == "PARAMPLACEHOLDER" or segment == "{param}":
                param_name = f"id{param_counter}"
                parameterized_segments.append(f"{{{param_name}}}")
                parameters.append(param_name)
                param_counter += 1
            # Check UUID
            elif uuid_pattern.match(segment):
                param_name = f"uuid{param_counter}"
                parameterized_segments.append(f"{{{param_name}}}")
                parameters.append(param_name)
                param_counter += 1
            # Check numerical ID
            elif num_pattern.match(segment):
                param_name = f"id{param_counter}"
                parameterized_segments.append(f"{{{param_name}}}")
                parameters.append(param_name)
                param_counter += 1
            else:
                parameterized_segments.append(segment)

        parameterized_path = "/" + "/".join(parameterized_segments)
        return parameterized_path, parameters

    def reconstruct_spec(self, target: str, urls: list[str] | set[str]) -> dict[str, Any]:
        """Compile a list of raw URLs into an OpenAPI 3.0 Specification dictionary."""
        spec: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {
                "title": f"Reconstructed API Specification for {target}",
                "description": "Automatically generated API Schema from active security endpoint reconnaissance.",
                "version": "1.0.0",
            },
            "servers": [{"url": f"https://{target}"}],
            "paths": {},
        }

        # Cluster by parameterized paths
        paths_dict: dict[str, dict[str, Any]] = {}

        for raw_url in sorted(urls):
            if not raw_url:
                continue
            parsed = urlparse(raw_url)
            # Only process HTTP/HTTPS endpoints
            if parsed.scheme not in {"http", "https"}:
                continue

            path = parsed.path or "/"
            parameterized, path_params = self.parameterize_path(path)

            # Infer method from path keywords
            methods = {"get": {}}
            path_lower = path.lower()
            if any(k in path_lower for k in ["delete", "remove"]):
                methods = {"delete": {}}
            elif any(k in path_lower for k in ["create", "add", "insert", "upload", "submit"]):
                methods = {"post": {}}
            elif any(k in path_lower for k in ["update", "modify", "edit", "save"]):
                methods = {"put": {}, "patch": {}}

            if parameterized not in paths_dict:
                paths_dict[parameterized] = {
                    "parameters": [],
                    "methods": methods,
                }

                # Construct path parameter schema
                for param in path_params:
                    param_type = "string"
                    param_format = None
                    if param.startswith("uuid"):
                        param_format = "uuid"
                    elif param.startswith("id"):
                        param_type = "integer"

                    schema = {"type": param_type}
                    if param_format:
                        schema["format"] = param_format

                    paths_dict[parameterized]["parameters"].append(
                        {
                            "name": param,
                            "in": "path",
                            "required": True,
                            "schema": schema,
                            "description": f"Extracted dynamic {param} parameter",
                        }
                    )

            # Process query parameters
            query_params = parse_qsl(parsed.query)
            for key, val in query_params:
                # Avoid duplicate query parameters
                existing = [
                    p["name"] for p in paths_dict[parameterized]["parameters"] if p["in"] == "query"
                ]
                if key not in existing:
                    # Parameter type inference
                    param_type = "string"
                    param_format = None
                    if key.lower().endswith("id") or key.lower() in {
                        "page",
                        "limit",
                        "offset",
                        "size",
                        "count",
                    }:
                        if val.isdigit() or not val:
                            param_type = "integer"
                    elif key.lower() in {"force", "active", "enabled", "checked", "debug"}:
                        if val.lower() in {"true", "false", "1", "0"}:
                            param_type = "boolean"

                    schema = {"type": param_type}
                    if param_format:
                        schema["format"] = param_format

                    paths_dict[parameterized]["parameters"].append(
                        {
                            "name": key,
                            "in": "query",
                            "required": False,
                            "schema": schema,
                            "description": f"Extracted dynamic query parameter {key}",
                        }
                    )

        # Format inside the final OpenAPI Paths property
        for path_route, details in paths_dict.items():
            spec["paths"][path_route] = {}
            for method, method_details in details["methods"].items():
                spec["paths"][path_route][method] = {
                    "summary": f"Endpoint {path_route}",
                    "responses": {
                        "200": {
                            "description": "Successful operation / Endpoint exists",
                        }
                    },
                }
            if details["parameters"]:
                spec["paths"][path_route]["parameters"] = details["parameters"]

        # Write OpenAPI Spec output file
        spec_path = self.output_dir / "openapi_spec.json"
        try:
            with open(spec_path, "w", encoding="utf-8") as f:
                json.dump(spec, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            import logging

            logger = logging.getLogger(__name__)
            logger.warning("Failed to write OpenAPI spec to %s: %s", spec_path, exc)

        return spec
