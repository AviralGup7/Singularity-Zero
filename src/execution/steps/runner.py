"""Scenario step execution wave helper.

Split out of ``scenario_engine.py`` so that the sequential / parallel runner
can be referenced without importing the full engine module.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import TYPE_CHECKING, Any

from src.core.session import SessionRegistry
from src.execution.scenario_models import ScenarioStep, ScenarioStepResult

if TYPE_CHECKING:
    pass


def execute_wave(
    engine: Any,
    steps: list[ScenarioStep],
    *,
    variables: dict[str, str],
    persisted_headers: dict[str, str],
    session_registry: SessionRegistry,
    cookie_jars: dict[str, Any],
    session_locks: dict[str, Any],
    state_lock: Lock,
    active_session_key: str,
    timeline: Any,
) -> tuple[list[ScenarioStepResult], str]:
    """Execute a ready wave of sequential + parallel steps.

    Returns the ordered results list and the resultant active-session key.
    """
    results: list[ScenarioStepResult] = []

    parallel_groups: dict[str, list[ScenarioStep]] = {}
    sequential_group: list[ScenarioStep] = []
    for step in steps:
        group = str(step.parallel_group).strip()
        if group:
            parallel_groups.setdefault(group, []).append(step)
        else:
            sequential_group.append(step)

    for step in sequential_group:
        result = engine._execute_step(
            step,
            variables=variables,
            persisted_headers=persisted_headers,
            session_registry=session_registry,
            cookie_jars=cookie_jars,
            session_locks=session_locks,
            state_lock=state_lock,
            active_session_key=active_session_key,
            timeline=timeline,
        )
        active_session_key = result.session_key or active_session_key
        results.append(result)
        timeline[step] = result
        if result.extracted_values:
            variables.update(result.extracted_values)

    for group_steps in parallel_groups.values():
        if len(group_steps) == 1:
            result = engine._execute_step(
                group_steps[0],
                variables=variables,
                persisted_headers=persisted_headers,
                session_registry=session_registry,
                cookie_jars=cookie_jars,
                session_locks=session_locks,
                state_lock=state_lock,
                active_session_key=active_session_key,
                timeline=timeline,
            )
            active_session_key = result.session_key or active_session_key
            results.append(result)
            timeline[group_steps[0]] = result
            if result.extracted_values:
                variables.update(result.extracted_values)
            continue

        with ThreadPoolExecutor(max_workers=len(group_steps)) as pool:
            futures = [
                pool.submit(
                    engine._execute_step,
                    step,
                    variables=variables,
                    persisted_headers=dict(persisted_headers),
                    session_registry=session_registry,
                    cookie_jars=cookie_jars,
                    session_locks=session_locks,
                    state_lock=state_lock,
                    active_session_key=active_session_key,
                    timeline=timeline,
                )
                for step in group_steps
            ]
            for future, step in zip(futures, group_steps):
                result = future.result()
                results.append(result)
                timeline[step] = result
                if result.extracted_values:
                    variables.update(result.extracted_values)

    results.sort(key=lambda item: item.started_at)
    return results, active_session_key
