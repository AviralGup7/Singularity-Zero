"""Choose which AuthFlowRunner implementation to register.

Both runners are kept. Operators pick the style with AUTH_FLOW_ENGINE:

* ``builtin`` (default) — ``auth_flow.AuthFlowRunner``
* ``yaml`` — richer declarative ``auth_flow_runner.AuthFlowRunner``
"""

from __future__ import annotations

import os
from typing import Any

_VALID = frozenset({"builtin", "yaml", "declarative"})


def normalize_auth_flow_engine(value: str | None) -> str:
    raw = (value or "builtin").strip().lower()
    if raw in {"yaml", "declarative", "steps"}:
        return "yaml"
    return "builtin"


def resolve_auth_flow_runner_cls(value: str | None = None) -> type[Any]:
    engine = normalize_auth_flow_engine(value if value is not None else os.getenv("AUTH_FLOW_ENGINE"))
    if engine == "yaml":
        from src.execution.auth.auth_flow_runner import AuthFlowRunner as YamlAuthFlowRunner

        return YamlAuthFlowRunner
    from src.execution.auth.auth_flow import AuthFlowRunner

    return AuthFlowRunner
