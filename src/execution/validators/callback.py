"""Callback target descriptor for out-of-band validation testing.

Analyzes callback configuration to determine if active validation is possible,
identifies the provider (Interactsh, Burp Collaborator, etc.), and reports
the validation state for use by the validation engine.
"""

from typing import Any
from urllib.parse import urlparse

KNOWN_CALLBACK_PROVIDERS = ("interactsh", "burpcollaborator", "webhook.site", "requestbin")


def describe_callback_target(validation_settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """Describe the configured callback target for active validation.

    Args:
        validation_settings: Optional validation configuration dict.

    Returns:
        Dict with configured status, validation state, provider info, and notes.
    """
    settings = validation_settings or {}
    callback_config = (
        settings.get("callback", {}) if isinstance(settings.get("callback", {}), dict) else {}
    )
    configured_value = str(
        callback_config.get("base_url")
        or callback_config.get("url")
        or callback_config.get("domain")
        or ""
    ).strip()
    provider = str(callback_config.get("provider") or "").strip().lower()
    token_present = bool(str(callback_config.get("token") or "").strip())
    if not configured_value:
        return {
            "configured": False,
            "status": "not_configured",
            "validation_state": "passive_only",
            "host": "",
            "scheme": "",
            "provider": provider or "none",
            "token_present": token_present,
            "notes": [
                "No callback receiver is configured.",
                "Add extensions.callback.base_url if you want active callback-aware prioritization.",
            ],
        }

    normalized = configured_value if "://" in configured_value else f"https://{configured_value}"
    parsed = urlparse(normalized)
    host = (parsed.netloc or parsed.path).lower()
    detected_provider = provider or _infer_provider(host)
    validation_state = "active_ready" if token_present else "passive_only"
    notes = [f"Callback host configured as {host}."]
    if token_present:
        notes.append(
            "A callback token is present, so active callback workflows can be correlated externally."
        )
    return {
        "configured": True,
        "status": "configured",
        "validation_state": validation_state,
        "host": host,
        "scheme": parsed.scheme or "https",
        "provider": detected_provider,
        "token_present": token_present,
        "notes": notes,
    }


def _infer_provider(host: str) -> str:
    lowered = host.lower()
    for provider in KNOWN_CALLBACK_PROVIDERS:
        if provider in lowered:
            return provider
    return "custom"
