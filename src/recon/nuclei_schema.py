"""Utilities for validating Nuclei template files using the included JSON Schema.

This module provides a tiny, optional validator that depends on the
`jsonschema` package. It intentionally fails fast if `jsonschema` is not
installed so callers can decide how to handle the missing dependency.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import jsonschema
    from jsonschema import ValidationError
except Exception:  # pragma: no cover - runtime environment may not have jsonschema
    jsonschema = None
    ValidationError = Exception

SCHEMA_PATH = Path(__file__).with_name("nuclei_template_schema.json")


from typing import Any, cast

def load_schema() -> dict[str, Any]:
    """Load and return the bundled Nuclei template JSON Schema."""
    text = SCHEMA_PATH.read_text(encoding="utf-8")
    return cast(dict[str, Any], json.loads(text))


def validate_template_file(filepath: str) -> None:
    """Validate a template file against the bundled schema.

    Raises ``RuntimeError`` if the runtime does not have ``jsonschema``
    installed, ``FileNotFoundError`` if the template is missing, or
    ``jsonschema.ValidationError`` for validation failures.
    """
    if jsonschema is None:
        raise RuntimeError("jsonschema is required for validation; install jsonschema")

    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(path)

    content = json.loads(path.read_text(encoding="utf-8"))
    schema = load_schema()
    jsonschema.validate(instance=content, schema=schema)


def is_valid_template(filepath: str) -> bool:
    """Return True if the given template file validates against the schema.

    This helper returns ``False`` for any error (missing package,
    malformed JSON, validation failures). Use ``validate_template_file``
    when callers need exceptions.
    """
    try:
        validate_template_file(filepath)
        return True
    except Exception:
        return False


__all__ = ["load_schema", "validate_template_file", "is_valid_template"]
