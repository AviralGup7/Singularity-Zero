"""Template helper for scenario request rendering.

Split out of ``scenario_engine.py`` so that variable interpolation can be
re-used without pulling in the heavy scenario engine module.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_TEMPLATE_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")


def render_template(template: str, variables: dict[str, str]) -> str:
    if "{{" not in template:
        return template

    def replacement(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        if key not in variables:
            logger.warning("Template variable '%s' not found; replacing with empty string", key)
        return str(variables.get(key, ""))

    return _TEMPLATE_PATTERN.sub(replacement, template)
