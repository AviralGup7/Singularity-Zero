"""ResourceGuard — memory-aware scheduling gate.

Prevents OOM by estimating per-stage RAM requirements and checking
available system memory before dispatch.

Bug #18: When psutil is unavailable, returns a safe default (4096 MB)
instead of 0, which caused all stages to be skipped as "insufficient_ram".

Bug #24: Model path is resolved relative to this file's directory, not
os.getcwd(), so it works regardless of the working directory.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

# Bug #24: Resolve model path relative to this file, not CWD
_MODULE_DIR = Path(__file__).resolve().parent
_DEFAULT_MODEL_PATH = str(_MODULE_DIR.parent.parent / ".ai" / "performance_model.json")

# Bug #18: Safe default when psutil is unavailable — 4 GB allows most
# stages to run.  Only truly massive scans (100k+ URLs) need more.
_PSUTIL_UNAVAILABLE_DEFAULT_RAM_MB = 4096

_BUILTIN_DEFAULTS = {
    "version": "2.0",
    "description": "Built-in conservative fallback model",
    "tool_profiles": {"default": {"base_ram_mb": 128, "notes": "fallback for unlisted tools"}},
    "concurrent_tool_memory_multiplier": 1.4,
    "oom_guard": {
        "enabled": True,
        "reserve_ram_mb": 2048,
        "kill_ram_mb": 0.90,
        "action_on_oom": "skip_stage",
        "check_interval_seconds": 30,
    },
    "stage_baselines": {},
    "stage_tools": {},
}


class ResourceGuard:
    def __init__(self, performance_model_path: str = _DEFAULT_MODEL_PATH) -> None:
        self.model = self._load_model(performance_model_path)
        self.oom_guard = self.model.get("oom_guard", _BUILTIN_DEFAULTS["oom_guard"])
        self.tool_profiles = self.model.get("tool_profiles", _BUILTIN_DEFAULTS["tool_profiles"])
        self.multiplier = self.model.get(
            "concurrent_tool_memory_multiplier",
            _BUILTIN_DEFAULTS["concurrent_tool_memory_multiplier"],
        )
        self.stage_baselines = self.model.get(
            "stage_baselines", _BUILTIN_DEFAULTS["stage_baselines"]
        )
        self.stage_tools = self.model.get("stage_tools", _BUILTIN_DEFAULTS["stage_tools"])

    def _load_model(self, path: str) -> dict[str, Any]:
        # Bug #24: If path is relative, resolve against this file's directory
        # first, then fall back to CWD for backward compatibility.
        if not os.path.isabs(path):
            candidate = str(_MODULE_DIR.parent.parent / path)
            if not os.path.isfile(candidate):
                candidate = os.path.join(os.getcwd(), path)
        else:
            candidate = path

        if not os.path.isfile(candidate):
            logger.warning(
                "ResourceGuard: performance_model.json not found at %s; using built-in defaults.",
                candidate,
            )
            return cast("dict[str, Any]", json.loads(json.dumps(_BUILTIN_DEFAULTS)))

        try:
            with open(candidate, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("performance_model.json root must be an object")
            return data
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logger.warning(
                "ResourceGuard: failed to load %s (%s); using built-in defaults.", candidate, exc
            )
            return cast("dict[str, Any]", json.loads(json.dumps(_BUILTIN_DEFAULTS)))

    def _get_profile(self, tool_name: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self.tool_profiles.get(
                tool_name, self.tool_profiles.get("default", {"base_ram_mb": 128})
            ),
        )

    def _tool_ram(self, tool_name: str, target_count: int, url_count: int) -> int:
        profile = self._get_profile(tool_name)
        base = int(profile.get("base_ram_mb", 128))

        if "per_template_mb" in profile:
            templates = int(profile.get("max_templates_default", 5000))
            base += int(profile["per_template_mb"] * templates)

        if "per_1000_urls_mb" in profile:
            base += int((url_count / 1000.0) * profile["per_1000_urls_mb"])

        if "crawl_depth_multiplier" in profile:
            depth = 3
            base += int(base * profile["crawl_depth_multiplier"] * (depth - 1))

        if "per_rule_set_mb" in profile:
            rule_sets = int(profile.get("max_rule_sets", 4))
            base += int(profile["per_rule_set_mb"] * rule_sets)

        if "per_10000_ports_mb" in profile:
            ports = 1000
            base += int((ports / 10000.0) * profile["per_10000_ports_mb"])

        return max(0, base)

    def estimate_stage_ram(
        self,
        stage_name: str,
        target_count: int,
        url_count: int,
        active_tools: list[str] | None = None,
    ) -> int:
        tools = active_tools if active_tools else self.stage_tools.get(stage_name, ["default"])
        total = sum(self._tool_ram(t, target_count, url_count) for t in tools)
        total = int(total * self.multiplier)
        total += int(self.oom_guard.get("reserve_ram_mb", 2048))
        return max(0, total)

    def _get_available_ram_mb(self) -> int:
        try:
            import psutil

            return int(psutil.virtual_memory().available / (1024 * 1024))
        except ImportError as exc:
            logger.warning(
                "psutil not available for RAM check — using safe default %d MB: %s",
                _PSUTIL_UNAVAILABLE_DEFAULT_RAM_MB,
                exc,
            )
        except Exception as exc:
            logger.debug("ResourceGuard: psutil check failed (%s).", exc)

        # Bug #18: Return a safe default instead of 0.  Returning 0 caused
        # all stages to be skipped as "insufficient_ram", silently disabling
        # the entire pipeline on systems without psutil.
        return _PSUTIL_UNAVAILABLE_DEFAULT_RAM_MB

    def check_available_ram(self, estimated_ram_mb: int) -> bool:
        available = self._get_available_ram_mb()
        return available >= estimated_ram_mb

    def check_available_ram_for_dispatch(
        self,
        estimated_ram_mb: int,
        in_flight_count: int = 0,
        in_flight_avg_ram_mb: int = 0,
    ) -> tuple[bool, str | None]:
        """Check if there is enough RAM to dispatch another task.

        Bug #19: Preventive check that accounts for in-flight work,
        not just current memory.  Returns (ok, reason_if_not_ok).

        Args:
            estimated_ram_mb: RAM needed by the task about to be dispatched.
            in_flight_count: Number of tasks currently running.
            in_flight_avg_ram_mb: Average RAM per in-flight task (estimate).
        """
        if not self.oom_guard.get("enabled", True):
            return True, None

        available = self._get_available_ram_mb()
        # Account for in-flight work that hasn't been counted by psutil yet
        planned_overhead = in_flight_count * in_flight_avg_ram_mb
        reserve = int(self.oom_guard.get("reserve_ram_mb", 2048))
        needed = estimated_ram_mb + planned_overhead + reserve

        if available < needed:
            return False, (
                f"dispatch_denied available_{available}_mb "
                f"needed_{needed}_mb (estimated={estimated_ram_mb}, "
                f"in_flight={in_flight_count}x{in_flight_avg_ram_mb})"
            )
        return True, None

    def should_skip_stage(
        self, stage_name: str, target_count: int, url_count: int
    ) -> tuple[bool, str | None]:
        if not self.oom_guard.get("enabled", True):
            return False, None

        estimated = self.estimate_stage_ram(stage_name, target_count, url_count)
        if not self.check_available_ram(estimated):
            reason = f"insufficient_ram estimated_{estimated}_mb"
            return True, reason
        return False, None

    def check_critical_oom(self) -> None:
        if not self.oom_guard.get("enabled", True):
            return
        kill_percent = self.oom_guard.get("kill_ram_mb", 0.90)
        try:
            import psutil

            mem = psutil.virtual_memory()
            if mem.percent >= (kill_percent * 100):
                raise RuntimeError(
                    f"Critical OOM: memory usage {mem.percent:.1f}% exceeds threshold {kill_percent * 100:.1f}%"
                )
        except ImportError:
            pass
        except RuntimeError:
            raise
        except Exception as exc:
            logger.debug("ResourceGuard: psutil-based OOM check failed (%s).", exc)

    def check_and_halt_on_oom(self) -> str | None:
        if not self.oom_guard.get("enabled", True):
            return None
        kill_percent = self.oom_guard.get("kill_ram_mb", 0.90)
        try:
            import psutil

            mem = psutil.virtual_memory()
            if mem.percent >= (kill_percent * 100):
                return (
                    f"memory usage {mem.percent:.1f}% exceeds threshold {kill_percent * 100:.1f}%"
                )
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("ResourceGuard: OOM check failed (%s).", exc)
        return None

    def get_concurrency_cap(self, stage_name: str, default: int) -> int:
        baseline = self.stage_baselines.get(stage_name, {})
        return int(baseline.get("concurrency_cap", default))
