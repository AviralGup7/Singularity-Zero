"""Template rendering for scenario steps."""

from typing import Any


def render_template(template_str: str, context: dict[str, Any] | None = None) -> str:
    """Render a template string with the given context."""
    if context is None:
        return template_str
    result = template_str
    for key, value in context.items():
        result = result.replace(f"{{{{{key}}}}}", str(value))
    return result
