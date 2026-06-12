"""Active analysis probes."""

import logging


def __getattr__(name: str):
    if name == "detect_grafana":
        from .injection.grafana_ssrf import detect_grafana

        return detect_grafana
    if name == "scan_grafana_ssrf":
        from .injection.grafana_ssrf import scan_grafana_ssrf

        return scan_grafana_ssrf
    if name == "proxy_ssrf_probe":
        from .injection.proxy_ssrf import proxy_ssrf_probe

        return proxy_ssrf_probe
    if name == "business_logic_probes":
        try:
            from src.analysis.active.business_logic.coordinator import (
                run_business_logic_probes as business_logic_probes,
            )

            return business_logic_probes
        except ImportError as exc:
            logging.warning("Operation failed in __init__.py: %s", exc, exc_info=True)
            raise AttributeError(name) from exc
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "detect_grafana",
    "scan_grafana_ssrf",
    "proxy_ssrf_probe",
]
