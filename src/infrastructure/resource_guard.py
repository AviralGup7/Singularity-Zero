import json
import logging
import os
import shutil
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_MODEL_PATH = ".ai/performance_model.json"

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
        if not os.path.isabs(path):
            base = os.getcwd()
            candidate = os.path.join(base, path)
        else:
            candidate = path

        if not os.path.isfile(candidate):
            logger.warning(
                "ResourceGuard: performance_model.json not found at %s; using built-in defaults.",
                candidate,
            )
            return json.loads(json.dumps(_BUILTIN_DEFAULTS))

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
            return json.loads(json.dumps(_BUILTIN_DEFAULTS))

    def _get_profile(self, tool_name: str) -> dict[str, Any]:
        return self.tool_profiles.get(
            tool_name, self.tool_profiles.get("default", {"base_ram_mb": 128})
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
            logger.warning("Operation failed in resource_guard.py: %s", exc, exc_info=True)  # noqa: BLE001
        except Exception as exc:
            logger.debug(
                "ResourceGuard: psutil check failed (%s); falling back to disk usage.", exc
            )

        try:
            usage = shutil.disk_usage("/")
            return int(usage.free / (1024 * 1024))
        except Exception as exc:
            logger.debug("ResourceGuard: shutil.disk_usage fallback failed (%s).", exc)
            return 0

    def check_available_ram(self, estimated_ram_mb: int) -> bool:
        available = self._get_available_ram_mb()
        return available >= estimated_ram_mb

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
        except ImportError as exc:
            logger.warning("Operation failed in resource_guard.py: %s", exc, exc_info=True)  # noqa: BLE001
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
        except ImportError as exc:
            logger.warning("Operation failed in resource_guard.py: %s", exc, exc_info=True)  # noqa: BLE001
        except Exception as exc:
            logger.debug("ResourceGuard: OOM check failed (%s).", exc)
        return None

    def get_concurrency_cap(self, stage_name: str, default: int) -> int:
        baseline = self.stage_baselines.get(stage_name, {})
        return int(baseline.get("concurrency_cap", default))
