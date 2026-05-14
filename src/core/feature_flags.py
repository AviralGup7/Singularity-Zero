import hashlib  # Fix #342: moved from _check_rollout to module level
import json
import os
import re
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


@lru_cache(maxsize=128)
def _compile_regex(pattern: str) -> re.Pattern:
    """Cache compiled regex patterns to avoid recompilation."""
    return re.compile(pattern)


class FeatureFlagCondition(BaseModel):
    """Condition for feature flag evaluation."""

    attribute: str
    operator: str = Field(default="eq")
    value: Any


class FeatureFlag(BaseModel):
    """Represents a single feature flag with rollout and condition support."""

    name: str = Field(min_length=1)
    enabled: bool = Field(default=False)
    rollout_percentage: float = Field(default=100.0, ge=0.0, le=100.0)
    conditions: list[FeatureFlagCondition] = Field(default_factory=list)
    description: str = Field(default="")
    env_overrides: dict[str, bool] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(
                "Flag name must contain only alphanumeric characters, underscores, or hyphens"
            )
        return v.lower()


class FeatureFlagManager:
    """Manages feature flags with rollout, conditions, and environment overrides."""

    def __init__(self) -> None:
        self._flags: dict[str, FeatureFlag] = {}
        self._lock = threading.RLock()
        self._config_path: Path | None = None

    def register(self, flag: FeatureFlag) -> None:
        with self._lock:
            if flag.name in self._flags:
                logger.warning("Feature flag '%s' already registered, overwriting", flag.name)
            self._flags[flag.name] = flag
            logger.info("Registered feature flag '%s'", flag.name)

    def unregister(self, name: str) -> bool:
        with self._lock:
            name = name.lower()
            if name in self._flags:
                del self._flags[name]
                logger.info("Unregistered feature flag '%s'", name)
                return True
            logger.warning("Attempted to unregister unknown flag '%s'", name)
            return False

    def is_enabled(
        self,
        name: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        name = name.lower()
        with self._lock:
            flag = self._flags.get(name)

        if flag is None:
            logger.debug("Feature flag '%s' not found, returning False", name)
            return False

        if not flag.enabled:
            return False

        env_override = self._check_env_override(flag)
        if env_override is not None:
            return env_override

        if flag.conditions and not self._evaluate_conditions(flag.conditions, context):
            return False

        return self._check_rollout(name, flag.rollout_percentage)

    def get_flag(self, name: str) -> FeatureFlag | None:
        with self._lock:
            return self._flags.get(name.lower())

    def list_flags(self) -> dict[str, FeatureFlag]:
        with self._lock:
            return dict(self._flags)

    def load_from_file(self, path: str | Path) -> None:
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Feature flags config file not found: {config_path}")

        with open(config_path, encoding="utf-8") as f:
            data = json.load(f)

        flags_data = (
            data if isinstance(data, list) else data.get("flags", data.get("feature_flags", []))
        )

        loaded = 0
        for item in flags_data:
            try:
                flag = FeatureFlag(**item)
                self.register(flag)
                loaded += 1
            except Exception as exc:
                logger.error("Failed to load feature flag from config: %s", exc)

        self._config_path = config_path
        logger.info("Loaded %d feature flags from %s", loaded, config_path)

    def export_state(self, path: str | Path | None = None) -> dict[str, Any]:
        with self._lock:
            state = {
                "flags": [flag.model_dump() for flag in self._flags.values()],
                "total": len(self._flags),
            }

        if path:
            output_path = Path(path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            logger.info("Exported feature flags state to %s", output_path)

        return state

    def _check_env_override(self, flag: FeatureFlag) -> bool | None:
        current_env = os.environ.get("ENVIRONMENT", os.environ.get("APP_ENV", "")).lower()

        if current_env and current_env in flag.env_overrides:
            override_value = flag.env_overrides[current_env]
            logger.debug(
                "Flag '%s' env override for '%s': %s",
                flag.name,
                current_env,
                override_value,
            )
            return override_value

        env_var_name = f"FLAG_{flag.name.upper()}"
        if env_var_name in os.environ:
            raw = os.environ[env_var_name].lower()
            return raw in ("1", "true", "yes", "on")

        return None

    def _evaluate_conditions(
        self,
        conditions: list[FeatureFlagCondition],
        context: dict[str, Any] | None,
    ) -> bool:
        if not context:
            return False

        for condition in conditions:
            context_value = context.get(condition.attribute)
            if context_value is None:
                return False

            if not self._evaluate_condition(condition, context_value):
                return False

        return True

    def _evaluate_condition(self, condition: FeatureFlagCondition, context_value: Any) -> bool:
        operator = condition.operator.lower()
        target = condition.value

        if operator == "eq":
            return bool(context_value == target)
        if operator == "neq":
            return bool(context_value != target)
        if operator == "gt":
            return bool(context_value > target)
        if operator == "gte":
            return bool(context_value >= target)
        if operator == "lt":
            return bool(context_value < target)
        if operator == "lte":
            return bool(context_value <= target)
        if operator == "in":
            return bool(context_value in target)
        if operator == "not_in":
            return bool(context_value not in target)
        if operator == "contains":
            return bool(target in context_value)
        if operator == "regex":
            return bool(_compile_regex(target).search(str(context_value)))

        logger.warning("Unknown condition operator: %s", operator)
        return False

    def _check_rollout(self, name: str, percentage: float, context: dict[str, Any] | None = None) -> bool:
        if percentage <= 0.0:
            return False
        if percentage >= 100.0:
            return True

        # Fix #256/#341: Include a context key so the rollout is per-user, not global.
        # Without this, every user gets the same bucket and 50% means all-or-nothing.
        context_key = ""
        if context:
            # Use a stable identifier: user_id, account_id, or IP
            for attr in ("user_id", "account_id", "session_id", "ip"):
                if attr in context:
                    context_key = str(context[attr])
                    break

        seed = f"{name}:{context_key}"
        # Use SHA-256 for a more collision-resistant deterministic bucket.
        hash_value = int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16)
        bucket = hash_value % 100

        return bucket < int(percentage)
