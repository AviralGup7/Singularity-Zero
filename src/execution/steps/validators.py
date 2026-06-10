"""Step assertion validation helpers.

Split out of ``scenario_engine.py`` so that the ``_revalidate_wave_assertions``
routine can be overridden or unit-tested in isolation.
"""

from __future__ import annotations

from typing import Any

from src.execution.scenario_models import ScenarioStep, ScenarioStepResult


def validate_step_result(
    result: ScenarioStepResult,
    step: ScenarioStep | None,
    *,
    steps_by_name: dict[str, ScenarioStep],
    timeline: Any,
) -> ScenarioStepResult:
    """Re-run step assertions and return an updated result with merged errors."""
    if step is None or not step.assertions:
        return result

    timing_snapshot = timeline.get_timing_snapshot(context_step=step)
    merged_errors = list(result.assertion_errors)
    for assertion in step.assertions:
        for error in assertion.validate(
            result.response,
            step_name=result.name,
            timing=timing_snapshot,
        ):
            if error not in merged_errors:
                merged_errors.append(error)

    if tuple(merged_errors) != result.assertion_errors:
        from dataclasses import replace

        result = replace(result, assertion_errors=tuple(merged_errors))
    return result


def reconcile_wave(
    wave_results: list[ScenarioStepResult],
    *,
    steps_by_name: dict[str, ScenarioStep],
    timeline: Any,
) -> list[ScenarioStepResult]:
    """Re-run assertions for every result in a wave."""
    reconciled: list[ScenarioStepResult] = []
    for result in wave_results:
        step = None
        if hasattr(timeline, "_steps"):
            matching_steps = [s for s in timeline._steps if s.name == result.name]
            for s in matching_steps:
                if timeline._results.get(s) == result:
                    step = s
                    break
            if not step and matching_steps:
                step = matching_steps[-1]
        if not step:
            step = steps_by_name.get(result.name)
        reconciled.append(
            validate_step_result(result, step, steps_by_name=steps_by_name, timeline=timeline)
        )
    return reconciled
