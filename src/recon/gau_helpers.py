"""Helpers for resolving `gau` extra-args and provider expansion.

Extracted from `src.recon.urls` to keep argument handling testable
and focused.
"""

from __future__ import annotations

from src.core.models import Config


def replace_gau_provider_args(extra_args: list[str], providers: str) -> list[str]:
    result: list[str] = []
    skip_next = False
    replaced = False
    for token in extra_args:
        if skip_next:
            skip_next = False
            continue
        text = str(token)
        lowered = text.lower().strip()
        if lowered == "--providers":
            result.extend(["--providers", providers])
            skip_next = True
            replaced = True
            continue
        if lowered.startswith("--providers="):
            result.append(f"--providers={providers}")
            replaced = True
            continue
        result.append(text)
    if not replaced:
        result.extend(["--providers", providers])
    return result


def resolve_gau_extra_args(config: Config) -> list[str]:
    extra_args = [str(arg) for arg in config.gau.get("extra_args", [])]
    filters = config.filters or {}
    auto_expand = bool(filters.get("gau_auto_expand_providers", True))
    if not auto_expand:
        return extra_args

    providers_value = ""
    i = 0
    while i < len(extra_args):
        token = str(extra_args[i]).strip()
        lowered = token.lower()
        if lowered == "--providers" and i + 1 < len(extra_args):
            providers_value = str(extra_args[i + 1]).strip().lower()
            break
        if lowered.startswith("--providers="):
            providers_value = lowered.split("=", 1)[1].strip()
            break
        i += 1

    if providers_value in {"wayback", ""}:
        return replace_gau_provider_args(
            extra_args,
            "wayback,commoncrawl,urlscan,otx",
        )
    return extra_args


__all__ = ["resolve_gau_extra_args", "replace_gau_provider_args"]
