
"""Step results container.

Re-implements ``StepResultsDict`` from ``scenario_engine.py`` so it can be
referenced without importing the full scenario engine module.  The public API
is unchanged.
"""

from typing import Any

from src.execution.scenario_models import ScenarioStep, ScenarioStepResult


class StepResultsDict:
    def __init__(self, steps: list[ScenarioStep]) -> None:
        self._results: dict[ScenarioStep, ScenarioStepResult] = {}
        self._steps = steps
        self._steps_by_name: dict[str, list[ScenarioStep]] = {}
        for step in steps:
            self._steps_by_name.setdefault(step.name, []).append(step)

    def __setitem__(self, key: ScenarioStep | str, value: ScenarioStepResult) -> None:
        if isinstance(key, ScenarioStep):
            self._results[key] = value
        elif isinstance(key, str):
            matching_steps = self._steps_by_name.get(key, [])
            target_step = None
            for step in matching_steps:
                if step not in self._results:
                    target_step = step
                    break
            if target_step is None and matching_steps:
                target_step = matching_steps[-1]
            if target_step:
                self._results[target_step] = value

    def __contains__(self, key: Any) -> bool:
        if isinstance(key, str):
            return any(step.name == key for step in self._results)
        return key in self._results

    def get_result(self, name: str, context_step: ScenarioStep | None) -> ScenarioStepResult | None:
        matching_steps = self._steps_by_name.get(name, [])
        if not matching_steps:
            return None
        if context_step is None:
            for step in reversed(matching_steps):
                if step in self._results:
                    return self._results[step]
            return None

        try:
            context_idx = self._steps.index(context_step)
        except ValueError:
            context_idx = len(self._steps)

        best_step = None
        for step in matching_steps:
            try:
                idx = self._steps.index(step)
            except ValueError:
                continue
            if idx < context_idx:
                best_step = step
            else:
                break

        if best_step is not None:
            return self._results.get(best_step)

        for step in matching_steps:
            if step in self._results:
                return self._results[step]
        return None

    def has_passed(self, name: str, context_step: ScenarioStep | None) -> bool:
        res = self.get_result(name, context_step)
        return bool(res and res.passed and not res.skipped)

    def get_timing_snapshot(self, context_step: ScenarioStep | None) -> dict[str, dict[str, float]]:
        snapshot: dict[str, dict[str, float]] = {}
        unique_names = {step.name for step in self._steps}
        for name in unique_names:
            res = self.get_result(name, context_step)
            if res:
                snapshot[name] = {
                    "started_at": res.started_at,
                    "completed_at": res.completed_at,
                }
        return snapshot

    def items(self) -> list[tuple[Any, Any]]:
        return [(step.name, res) for step, res in self._results.items()]

    def values(self) -> Any:
        return self._results.values()
