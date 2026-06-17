"""Self-healing controller setup for the FastAPI dashboard."""

from typing import Any

from src.core.contracts.protocol_registry import (
    get_self_healing_controller_cls,
)


def setup_self_healing_controller(
    action_registry: Any,
) -> Any:
    SelfHealingControllerCls = get_self_healing_controller_cls()
    if SelfHealingControllerCls is None:
        raise RuntimeError("SelfHealingController not registered")
    controller = SelfHealingControllerCls(action_registry=action_registry)
    return controller
