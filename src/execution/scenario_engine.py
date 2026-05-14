"""Scenario execution engine for multi-step HTTP interaction testing.

Provides the ScenarioEngine class for defining and executing ordered sequences
of HTTP requests with assertions, timing checks, and session management.
Supports both sequential and parallel step execution with barrier synchronization.
"""

import logging
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.cookiejar import CookieJar
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener
from urllib.request import Request as UrlRequest

from src.core.models import DEFAULT_USER_AGENT, Request, Response
from src.core.session import Session, SessionRegistry
from src.execution.scenario_models import (
    ScenarioRunResult,
    ScenarioStep,
    ScenarioStepResult,
)

logger = logging.getLogger(__name__)

Transport = Callable[[Request, CookieJar], Response]


class ScenarioExecutionEngine:
    def __init__(
        self,
        *,
        default_timeout_seconds: int = 12,
        default_headers: dict[str, str] | None = None,
        transport: Transport | None = None,
    ) -> None:
        self.default_timeout_seconds = max(1, int(default_timeout_seconds))
        self.default_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            **(default_headers or {}),
        }
        self._transport = transport or self._default_transport

    def execute(
        self,
        steps: list[ScenarioStep],
        *,
        initial_variables: dict[str, str] | None = None,
        session_headers: dict[str, str] | None = None,
        sessions: dict[str, Session] | None = None,
        active_session: str = "default",
        stop_on_failure: bool = True,
    ) -> ScenarioRunResult:
        variables: dict[str, str] = {**(initial_variables or {})}
        step_results: list[ScenarioStepResult] = []
        step_results_by_name: dict[str, ScenarioStepResult] = {}
        persisted_headers: dict[str, str] = {**self.default_headers, **(session_headers or {})}
        session_registry = SessionRegistry(sessions=dict(sessions or {}), active=active_session)
        cookie_jars: dict[str, CookieJar] = {key: CookieJar() for key in session_registry.sessions}
        session_locks: dict[str, Lock] = {key: Lock() for key in session_registry.sessions}
        state_lock = Lock()
        current_session_key = session_registry.active
        barrier_times: dict[str, float] = {}
        pending = list(steps)
        steps_by_name: dict[str, ScenarioStep] = {}
        for step in steps:
            steps_by_name.setdefault(step.name, step)

        while pending:
            ready: list[ScenarioStep] = []
            for step in pending:
                step_deps_met = all(
                    name in step_results_by_name and step_results_by_name[name].passed
                    for name in step.wait_for_steps
                )
                if not step_deps_met:
                    continue
                if any(name and name not in barrier_times for name in step.wait_for_barriers):
                    continue
                ready.append(step)

            if not ready:
                # Break deadlocks by marking the first pending step as failed due to unmet dependencies.
                step = pending.pop(0)
                failed_response = Response(
                    requested_url=step.request.url,
                    final_url=step.request.url,
                    status_code=None,
                    headers={},
                    body="",
                    error="dependency_unmet",
                )
                failed_result = ScenarioStepResult(
                    name=step.name,
                    request=step.request,
                    response=failed_response,
                    extracted_values={},
                    assertion_errors=("dependency_unmet",),
                    actor=step.actor,
                    session_key=step.session_key,
                    started_at=time.monotonic(),
                    completed_at=time.monotonic(),
                    skipped=False,
                )
                step_results.append(failed_result)
                step_results_by_name[step.name] = failed_result
                if stop_on_failure:
                    break
                continue

            ready_names = {step.name for step in ready}
            pending = [step for step in pending if step.name not in ready_names]

            skipped: list[ScenarioStep] = [
                step
                for step in ready
                if not self._should_run_step(step, variables, step_results_by_name)
            ]
            executable = [step for step in ready if step not in skipped]

            for step in skipped:
                skipped_response = Response(
                    requested_url=step.request.url,
                    final_url=step.request.url,
                    status_code=204,
                    headers={},
                    body="",
                    error="",
                )
                skipped_result = ScenarioStepResult(
                    name=step.name,
                    request=step.request,
                    response=skipped_response,
                    extracted_values={},
                    assertion_errors=(),
                    actor=step.actor,
                    session_key=step.session_key,
                    started_at=time.monotonic(),
                    completed_at=time.monotonic(),
                    skipped=True,
                )
                step_results.append(skipped_result)
                step_results_by_name[step.name] = skipped_result

            if not executable:
                continue

            parallel_groups: dict[str, list[ScenarioStep]] = {}
            sequential_group: list[ScenarioStep] = []
            for step in executable:
                group = str(step.parallel_group).strip()
                if group:
                    parallel_groups.setdefault(group, []).append(step)
                else:
                    sequential_group.append(step)

            wave_results: list[ScenarioStepResult] = []
            for step in sequential_group:
                result = self._execute_step(
                    step,
                    variables=variables,
                    persisted_headers=persisted_headers,
                    session_registry=session_registry,
                    cookie_jars=cookie_jars,
                    session_locks=session_locks,
                    state_lock=state_lock,
                    active_session_key=current_session_key,
                    timeline=step_results_by_name,
                )
                current_session_key = result.session_key or current_session_key
                wave_results.append(result)
                step_results_by_name[result.name] = result
                if result.extracted_values:
                    variables.update(result.extracted_values)
                if step.publish_barrier:
                    barrier_times[step.publish_barrier] = result.completed_at
                if stop_on_failure and not result.passed:
                    step_results.extend(wave_results)
                    return ScenarioRunResult(
                        steps=tuple(step_results),
                        variables=variables,
                        active_session=current_session_key,
                    )

            for group_steps in parallel_groups.values():
                if len(group_steps) == 1:
                    result = self._execute_step(
                        group_steps[0],
                        variables=variables,
                        persisted_headers=persisted_headers,
                        session_registry=session_registry,
                        cookie_jars=cookie_jars,
                        session_locks=session_locks,
                        state_lock=state_lock,
                        active_session_key=current_session_key,
                        timeline=step_results_by_name,
                    )
                    current_session_key = result.session_key or current_session_key
                    wave_results.append(result)
                    step_results_by_name[result.name] = result
                    if result.extracted_values:
                        variables.update(result.extracted_values)
                    source_step = group_steps[0]
                    if source_step.publish_barrier:
                        barrier_times[source_step.publish_barrier] = result.completed_at
                    continue
                with ThreadPoolExecutor(max_workers=len(group_steps)) as pool:
                    futures = [
                        pool.submit(
                            self._execute_step,
                            step,
                            variables=dict(variables),
                            persisted_headers=dict(persisted_headers),
                            session_registry=session_registry,
                            cookie_jars=cookie_jars,
                            session_locks=session_locks,
                            state_lock=state_lock,
                            active_session_key=current_session_key,
                            timeline=step_results_by_name,
                        )
                        for step in group_steps
                    ]
                    group_results = [future.result() for future in futures]
                    group_results.sort(key=lambda item: item.name)
                    wave_results.extend(group_results)

            wave_results.sort(key=lambda item: item.started_at)
            wave_results = self._revalidate_wave_assertions(
                wave_results,
                steps_by_name=steps_by_name,
                timeline=step_results_by_name,
            )
            step_results.extend(wave_results)
            for result in wave_results:
                step_results_by_name[result.name] = result
                if result.extracted_values:
                    variables.update(result.extracted_values)
                if result.session_key:
                    current_session_key = result.session_key
                source_step = steps_by_name.get(result.name)
                if source_step and source_step.publish_barrier:
                    barrier_times[source_step.publish_barrier] = result.completed_at

            if stop_on_failure and any(not item.passed for item in wave_results):
                break

        return ScenarioRunResult(
            steps=tuple(step_results),
            variables=variables,
            active_session=current_session_key,
        )

    def _should_run_step(
        self, step: ScenarioStep, variables: dict[str, str], results: dict[str, ScenarioStepResult]
    ) -> bool:
        clause = str(step.when or "").strip()
        if not clause:
            return True
        normalized = clause.lower()
        if normalized.startswith("step:") and normalized.endswith(".passed"):
            name = clause[5:-7].strip()
            return self._step_passed(results.get(name))
        if normalized.startswith("!"):
            key = clause[1:].strip()
            return not bool(str(variables.get(key, "")).strip())
        return bool(str(variables.get(clause, "")).strip())

    @staticmethod
    def _step_passed(result: ScenarioStepResult | None) -> bool:
        return bool(result and result.passed and not result.skipped)

    def _revalidate_wave_assertions(
        self,
        wave_results: list[ScenarioStepResult],
        *,
        steps_by_name: dict[str, ScenarioStep],
        timeline: dict[str, ScenarioStepResult],
    ) -> list[ScenarioStepResult]:
        if not wave_results:
            return wave_results

        timing_snapshot = {
            key: {
                "started_at": value.started_at,
                "completed_at": value.completed_at,
            }
            for key, value in timeline.items()
        }
        for result in wave_results:
            timing_snapshot[result.name] = {
                "started_at": result.started_at,
                "completed_at": result.completed_at,
            }

        reconciled: list[ScenarioStepResult] = []
        for result in wave_results:
            step = steps_by_name.get(result.name)
            if step is None or not step.assertions:
                reconciled.append(result)
                continue
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
                result = replace(result, assertion_errors=tuple(merged_errors))
            reconciled.append(result)
        return reconciled

    def _execute_step(
        self,
        step: ScenarioStep,
        *,
        variables: dict[str, str],
        persisted_headers: dict[str, str],
        session_registry: SessionRegistry,
        cookie_jars: dict[str, CookieJar],
        session_locks: dict[str, Lock],
        state_lock: Lock,
        active_session_key: str,
        timeline: dict[str, ScenarioStepResult],
    ) -> ScenarioStepResult:
        current_session_key = active_session_key
        actor_key = str(step.actor).strip()
        if actor_key:
            current_session_key = actor_key
        if step.session_key:
            current_session_key = str(step.session_key).strip() or current_session_key

        with state_lock:
            session_registry.switch(current_session_key)
            active = session_registry.ensure(current_session_key)
            step_variables = dict(variables)
            step_variables["session.role"] = active.role
            step_variables["session.identity"] = active.identity
            step_variables["session.auth_token"] = active.auth_token
            resolved_request = self._resolve_request(
                step.request, step_variables, persisted_headers
            )
            resolved_request = active.attach(resolved_request)
            jar = cookie_jars.setdefault(current_session_key, CookieJar())
            lock = session_locks.setdefault(current_session_key, Lock())

        started_at = time.monotonic()
        with lock:
            response = self._transport(resolved_request, jar)

            set_cookie_values = [
                str(value)
                for key, value in response.headers.items()
                if str(key).strip().lower() == "set-cookie"
            ]
            for raw_cookie in set_cookie_values:
                pair = raw_cookie.split(";", 1)[0].strip()
                if "=" not in pair:
                    continue
                cookie_name, cookie_value = pair.split("=", 1)
                if cookie_name.strip():
                    active.cookies[cookie_name.strip()] = cookie_value.strip()

            extracted_values: dict[str, str] = {}
            for extractor in step.extractors:
                value = extractor.extract(response)
                if value is None:
                    continue
                extracted_values[extractor.name] = value
                if extractor.name in {"auth_token", "token"}:
                    active.auth_token = value

        completed_at = time.monotonic()
        with state_lock:
            timing_snapshot = {
                key: {
                    "started_at": value.started_at,
                    "completed_at": value.completed_at,
                }
                for key, value in timeline.items()
            }
        timing_snapshot[step.name] = {"started_at": started_at, "completed_at": completed_at}

        assertion_errors: list[str] = []
        for assertion in step.assertions:
            assertion_errors.extend(
                assertion.validate(response, step_name=step.name, timing=timing_snapshot)
            )

        return ScenarioStepResult(
            name=step.name,
            request=resolved_request,
            response=response,
            extracted_values=extracted_values,
            assertion_errors=tuple(assertion_errors),
            actor=actor_key,
            session_key=current_session_key,
            started_at=started_at,
            completed_at=completed_at,
            skipped=False,
        )

    def _resolve_request(
        self, request: Request, variables: dict[str, str], persisted_headers: dict[str, str]
    ) -> Request:
        url = self._render_text(request.url, variables)
        headers = {**persisted_headers}
        for key, value in request.headers.items():
            headers[key] = self._render_text(str(value), variables)
        params = {
            key: self._render_text(str(value), variables) for key, value in request.params.items()
        }
        body: str | bytes | None = request.body
        if isinstance(body, str):
            body = self._render_text(body, variables)
        timeout = (
            request.timeout_seconds
            if request.timeout_seconds is not None
            else self.default_timeout_seconds
        )
        return Request(
            method=str(request.method or "GET").upper(),
            url=url,
            headers=headers,
            params=params,
            body=body,
            timeout_seconds=timeout,
        )

    @staticmethod
    def _render_text(template: str, variables: dict[str, str]) -> str:
        if "{{" not in template:
            return template

        def replacement(match: re.Match[str]) -> str:
            key = match.group(1).strip()
            if key not in variables:
                logger.warning("Template variable '%s' not found; replacing with empty string", key)
            return str(variables.get(key, ""))

        return re.sub(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}", replacement, template)

    def _default_transport(self, request: Request, cookie_jar: CookieJar) -> Response:
        opener = build_opener(HTTPCookieProcessor(cookie_jar))
        method = str(request.method or "GET").upper()
        url = request.url
        if request.params:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{urlencode(request.params)}"

        data: bytes | None = None
        if isinstance(request.body, bytes):
            data = request.body
        elif isinstance(request.body, str):
            data = request.body.encode("utf-8")

        started = time.monotonic()
        try:
            raw_request = UrlRequest(url, data=data, headers=request.headers, method=method)
            with opener.open(
                raw_request, timeout=request.timeout_seconds or self.default_timeout_seconds
            ) as raw_response:
                final_url = str(getattr(raw_response, "geturl", lambda: url)())
                headers = dict(raw_response.headers.items())
                charset = "utf-8"
                content_type = headers.get("Content-Type", "")
                if "charset=" in content_type.lower():
                    charset = (
                        content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
                    )
                body_bytes = raw_response.read()
                body_text = body_bytes.decode(charset, errors="replace")
                return Response(
                    requested_url=request.url,
                    final_url=final_url,
                    status_code=int(getattr(raw_response, "status", 0) or 0),
                    headers=headers,
                    body=body_text,
                    latency_seconds=round(time.monotonic() - started, 3),
                    error="",
                )
        except HTTPError as exc:
            try:
                error_text = exc.read().decode("utf-8", errors="replace")
            except OSError:
                error_text = ""
            except Exception:
                error_text = ""
            return Response(
                requested_url=request.url,
                final_url=str(getattr(exc, "url", request.url) or request.url),
                status_code=int(getattr(exc, "code", 0) or 0),
                headers=dict(getattr(exc, "headers", {}) or {}),
                body=error_text,
                latency_seconds=round(time.monotonic() - started, 3),
                error=f"http_error:{getattr(exc, 'code', 'unknown')}",
            )
        except URLError as exc:
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=None,
                headers={},
                body="",
                latency_seconds=round(time.monotonic() - started, 3),
                error=f"network_error:{exc.reason}",
            )
