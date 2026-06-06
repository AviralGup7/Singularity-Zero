"""Self-healing controller setup for the FastAPI dashboard."""

from src.pipeline.self_healing import CorrectiveActionRegistry, SelfHealingController


def setup_self_healing_controller(action_registry: CorrectiveActionRegistry) -> SelfHealingController:
    controller = SelfHealingController(action_registry=action_registry)
    return controller
