"""AI inference or model surface detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    provider_key_indicators = item.get("provider_key_indicators")
    model_enum_path = item.get("model_enumeration_path")
    return "medium" if provider_key_indicators or model_enum_path else "low"


def _description(item: dict[str, Any]) -> str:
    return "Review the AI-oriented endpoint for model enumeration, prompt leakage, throttling, and exposed provider keys."


register_spec(
    (
        "ai_endpoint_exposure_analyzer",
        "ai_surface",
        _severity,
        "AI inference or model surface detected",
        _description,
    )
)
