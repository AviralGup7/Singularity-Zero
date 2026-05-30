"""Runtime model registry with autonomous rollback support."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.pipeline.self_healing import HealthComponent, HealthMetric, HealthStatus


@dataclass(slots=True)
class ModelVersion:
    name: str
    version: str
    activated_at: float = field(default_factory=time.time)
    error_rate: float = 0.0
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class ModelVersionRegistry:
    """Tracks active and previous model versions for automatic rollback."""

    def __init__(self, *, max_error_rate: float = 0.2, max_latency_ms: float = 5000.0) -> None:
        self.max_error_rate = max_error_rate
        self.max_latency_ms = max_latency_ms
        self._active: dict[str, ModelVersion] = {}
        self._history: dict[str, list[ModelVersion]] = {}
        self._pipelines: dict[str, Any] = {}
        self._pipeline_history: dict[str, list[Any]] = {}
        self._rollback_log: list[dict[str, Any]] = []

    def register(self, model: ModelVersion, *, activate: bool = True, pipeline: Any = None) -> None:
        history = self._history.setdefault(model.name, [])
        pipe_history = self._pipeline_history.setdefault(model.name, [])
        current = self._active.get(model.name)
        current_pipe = self._pipelines.get(model.name)

        if current is not None and current.version != model.version:
            history.append(current)
            if current_pipe is not None:
                pipe_history.append(current_pipe)

        if activate:
            self._active[model.name] = model
            if pipeline is not None:
                self._pipelines[model.name] = pipeline
        else:
            history.append(model)
            if pipeline is not None:
                pipe_history.append(pipeline)

    def record_health(
        self,
        model_name: str,
        *,
        error_rate: float | None = None,
        latency_ms: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        model = self._active.get(model_name)
        if model is None:
            return
        if error_rate is not None:
            model.error_rate = error_rate
        if latency_ms is not None:
            model.latency_ms = latency_ms
        if metadata:
            model.metadata.update(metadata)

    def health_metrics(self) -> list[HealthMetric]:
        metrics: list[HealthMetric] = []
        for model in self._active.values():
            bad = model.error_rate > self.max_error_rate or model.latency_ms > self.max_latency_ms
            metrics.append(
                HealthMetric(
                    component=HealthComponent.MODEL_REGISTRY,
                    name="model_error_rate",
                    value=model.error_rate,
                    threshold=self.max_error_rate,
                    status=HealthStatus.CRITICAL if bad else HealthStatus.OK,
                    labels={
                        "model_name": model.name,
                        "version": model.version,
                        "latency_ms": model.latency_ms,
                    },
                )
            )
        return metrics

    def rollback_bad_model_version(self, model_name: str | None = None) -> dict[str, Any]:
        """Rollback the named bad model, or the first unhealthy active model."""
        candidates = [self._active[model_name]] if model_name in self._active else []
        if not candidates:
            candidates = [
                model
                for model in self._active.values()
                if model.error_rate > self.max_error_rate or model.latency_ms > self.max_latency_ms
            ]
        if not candidates:
            return {"rolled_back": False, "reason": "no unhealthy model"}

        current = candidates[0]
        history = self._history.get(current.name, [])
        if not history:
            return {
                "rolled_back": False,
                "model_name": current.name,
                "version": current.version,
                "reason": "no previous version",
            }

        previous = history.pop()
        self._active[current.name] = previous

        # Rollback actual pipeline too
        pipe_history = self._pipeline_history.get(current.name, [])
        if pipe_history:
            self._pipelines[current.name] = pipe_history.pop()
        else:
            self._pipelines.pop(current.name, None)

        event = {
            "rolled_back": True,
            "model_name": current.name,
            "from_version": current.version,
            "to_version": previous.version,
            "rolled_back_at": time.time(),
        }
        self._rollback_log.append(event)
        return event

    def snapshot(self) -> dict[str, Any]:
        return {
            "active": {
                name: {
                    "version": model.version,
                    "error_rate": model.error_rate,
                    "latency_ms": model.latency_ms,
                    "activated_at": model.activated_at,
                    "metadata": dict(model.metadata),
                }
                for name, model in self._active.items()
            },
            "history_depth": {name: len(history) for name, history in self._history.items()},
            "rollback_log": list(self._rollback_log[-20:]),
        }
