"""Backend startup profiling script.

Measures cold/warm startup times, import hotspots, and memory footprint.
"""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def measure_import_time(module_name: str) -> float:
    """Measure time to import a module."""
    start = time.perf_counter()
    try:
        importlib.import_module(module_name)
    except Exception:
        pass
    return time.perf_counter() - start


def profile_cold_startup() -> dict[str, float]:
    """Profile cold startup by importing key modules."""
    modules = [
        "src.core",
        "src.core.contracts",
        "src.core.contracts.health",
        "src.core.events",
        "src.core.plugins",
        "src.core.frontier",
        "src.core.frontier.state",
        "src.core.frontier.bloom",
        "src.infrastructure",
        "src.infrastructure.observability",
        "src.infrastructure.observability.metrics",
        "src.execution",
        "src.execution.validators",
        "src.analysis",
        "src.analysis.plugin_runtime",
        "src.detection",
        "src.detection.finding",
        "src.pipeline",
        "src.pipeline.services",
        "src.recon",
        "src.dashboard",
    ]

    results = {}
    for module in modules:
        results[module] = measure_import_time(module)

    return results


def profile_memory() -> dict[str, int]:
    """Profile memory usage of imported modules."""
    import tracemalloc

    tracemalloc.start()

    # Import key modules
    key_modules = [
        "src.core",
        "src.infrastructure",
        "src.execution",
        "src.analysis",
        "src.detection",
        "src.pipeline",
    ]

    for module in key_modules:
        try:
            importlib.import_module(module)
        except Exception:
            pass

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "current_bytes": current,
        "peak_bytes": peak,
        "current_mb": current / (1024 * 1024),
        "peak_mb": peak / (1024 * 1024),
    }


def main() -> None:
    print("=" * 60)
    print("Backend Startup Profiling")
    print("=" * 60)

    # Cold startup
    print("\n[Cold Startup - Import Times]")
    cold_times = profile_cold_startup()
    sorted_times = sorted(cold_times.items(), key=lambda x: x[1], reverse=True)

    for module, time_s in sorted_times[:10]:
        print(f"  {module:45s} {time_s*1000:8.2f} ms")

    total_cold = sum(cold_times.values())
    print(f"\n  {'Total':45s} {total_cold*1000:8.2f} ms")

    # Memory
    print("\n[Memory Usage]")
    memory = profile_memory()
    print(f"  Current: {memory['current_mb']:.2f} MB")
    print(f"  Peak:    {memory['peak_mb']:.2f} MB")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
