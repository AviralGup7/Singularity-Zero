"""Injects WAF-adaptive arguments into Nuclei invocations."""

from __future__ import annotations

from src.pipeline.waf_profile import WafProfile, WafTuningProfile


def build_nuclei_args(
    existing_args: list[str],
    waf_profile: WafProfile | str | None = None,
    override: WafTuningProfile | None = None,
) -> list[str]:
    """Return augmented Nuclei argument list with WAF-aware rate-limit flags.

    If ``-rl``, ``-timeout``, or ``-retries`` are already present in
    ``existing_args`` they take precedence and are not duplicated.
    """
    profile = override or WafTuningProfile.for_profile(waf_profile or WafProfile.NONE)
    args = list(existing_args)

    def _has(flag: str) -> bool:
        return any(a == flag or a.startswith(flag + " ") or a.startswith(flag + "=") for a in args)

    if not _has("-rl"):
        args += ["-rl", str(profile.nuclei_rate_limit)]
    if not _has("-timeout"):
        args += ["-timeout", str(profile.nuclei_timeout_seconds)]
    if not _has("-retries"):
        args += ["-retries", str(profile.nuclei_retries)]
    return args
