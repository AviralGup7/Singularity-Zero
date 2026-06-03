"""Scenario execution engine for multi-step HTTP interaction testing.

Provides the ScenarioEngine class for defining and executing ordered sequences
of HTTP requests with assertions, timing checks, and session management.
Supports both sequential and parallel step execution with barrier synchronization.
"""

import logging
import re
import time
import weakref
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.cookiejar import CookieJar
from threading import Lock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, build_opener
from urllib.request import Request as UrlRequest

from src.core.models import DEFAULT_USER_AGENT, Request, Response
from src.core.session import Session, SessionRegistry
from src.core.utils.url_validation import is_safe_url, is_safe_url_with_dns_check
from src.execution.scenario_models import (
    ScenarioRunResult,
    ScenarioStep,
    ScenarioStepResult,
)

logger = logging.getLogger(__name__)

_TEMPLATE_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")

Transport = Callable[[Request, CookieJar], Response]


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


class ScenarioExecutionEngine:
    def __init__(
        self,
        *,
        default_timeout_seconds: int = 12,
        max_response_bytes: int = 1_000_000,
        allow_private_networks: bool = False,
        resolve_dns_for_ssrf_protection: bool = True,
        default_headers: dict[str, str] | None = None,
        transport: Transport | None = None,
        session_persistence_handler: Callable[[dict[str, Session]], None] | None = None,
    ) -> None:
        self.default_timeout_seconds = max(1, int(default_timeout_seconds))
        self.max_response_bytes = max(1_024, int(max_response_bytes))
        self.allow_private_networks = bool(allow_private_networks)
        self.resolve_dns_for_ssrf_protection = bool(resolve_dns_for_ssrf_protection)
        self.default_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            **(default_headers or {}),
        }
        self._transport = transport or self._default_transport
        self._openers: weakref.WeakKeyDictionary[CookieJar, Any] = weakref.WeakKeyDictionary()
        self.truncations_count = 0
        self.session_persistence_handler = session_persistence_handler
        self.last_persisted_sessions: dict[str, Session] = {}

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
        step_results_by_name = StepResultsDict(steps)
        persisted_headers: dict[str, str] = {**self.default_headers, **(session_headers or {})}
        session_registry = SessionRegistry(sessions=dict(sessions or {}), active=active_session)
        session_registry.ensure(active_session)
        self._persist_sessions(session_registry)
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
                    name in step_results_by_name
                    for name in step.wait_for_steps
                )
                if not step_deps_met:
                    continue
                if any(name and name not in barrier_times for name in step.wait_for_barriers):
                    continue
                ready.append(step)

            if not ready:
                # Break deadlocks by marking all remaining pending steps as failed due to unmet dependencies.
                while pending:
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
                    step_results_by_name[step] = failed_result
                break

            # Remove only the specific ready step objects; name-based filtering can accidentally
            # drop distinct steps that share a name.
            pending = [step for step in pending if step not in ready]

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
                step_results_by_name[step] = skipped_result

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
                step_results_by_name[step] = result
                if result.extracted_values:
                    variables.update(result.extracted_values)
                if step.publish_barrier:
                    barrier_times[step.publish_barrier] = result.completed_at
                if stop_on_failure and not result.passed:
                    step_results.extend(wave_results)
                    self._persist_sessions(session_registry)
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
                    step_results_by_name[group_steps[0]] = result
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
                            variables=variables,
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
                # Find matching step object
                matching_steps = [s for s in steps if s.name == result.name]
                target_step = None
                for s in matching_steps:
                    if s not in step_results_by_name:
                        target_step = s
                        break
                if target_step is None and matching_steps:
                    target_step = matching_steps[-1]

                if target_step:
                    step_results_by_name[target_step] = result
                else:
                    step_results_by_name[result.name] = result

                if result.extracted_values:
                    variables.update(result.extracted_values)
                if result.session_key:
                    current_session_key = result.session_key
                resolved_step = steps_by_name.get(result.name)
                if resolved_step and resolved_step.publish_barrier:
                    barrier_times[resolved_step.publish_barrier] = result.completed_at

            self._persist_sessions(session_registry)
            if stop_on_failure and any(not item.passed for item in wave_results):
                break

        self._persist_sessions(session_registry, force=True)
        return ScenarioRunResult(
            steps=tuple(step_results),
            variables=variables,
            active_session=current_session_key,
        )

    def _persist_sessions(self, registry: SessionRegistry, force: bool = False) -> None:
        """Batch-persist all sessions to avoid N+1 individual updates if backed by external storage."""
        sessions_changed = force
        if not sessions_changed:
            if len(registry.sessions) != len(self.last_persisted_sessions):
                sessions_changed = True
            else:
                for k, v in registry.sessions.items():
                    if k not in self.last_persisted_sessions or self.last_persisted_sessions[k] != v:
                        sessions_changed = True
                        break

        if not sessions_changed:
            logger.debug("Skipping session persistence: no changes detected.")
            return

        logger.debug(
            "Batch-persisting %d sessions to prevent N+1 storage queries.",
            len(registry.sessions),
        )
        self.last_persisted_sessions = {k: replace(v) for k, v in registry.sessions.items()}
        if self.session_persistence_handler:
            try:
                self.session_persistence_handler(self.last_persisted_sessions)
            except Exception as exc:
                logger.error("Failed to execute session persistence handler: %s", exc)

    def _should_run_step(self, step: ScenarioStep, variables: dict[str, str], results: Any) -> bool:
        clause = str(step.when or "").strip()
        if not clause:
            return True
        normalized = clause.lower()
        if normalized.startswith("step:") and normalized.endswith(".passed"):
            name = clause[5:-7].strip()
            return self._step_passed(results.get_result(name, context_step=step))
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
        timeline: Any,
    ) -> list[ScenarioStepResult]:
        if not wave_results:
            return wave_results

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

            if step is None or not step.assertions:
                reconciled.append(result)
                continue

            timing_snapshot = timeline.get_timing_snapshot(context_step=step)
            for res in wave_results:
                timing_snapshot[res.name] = {
                    "started_at": res.started_at,
                    "completed_at": res.completed_at,
                }

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
        timeline: Any,
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
            variables.update(extracted_values)
            timing_snapshot = timeline.get_timing_snapshot(context_step=step)
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

        return _TEMPLATE_PATTERN.sub(replacement, template)

    def _default_transport(self, request: Request, cookie_jar: CookieJar) -> Response:
        opener = self._openers.get(cookie_jar)
        if opener is None:
            opener = build_opener(HTTPCookieProcessor(cookie_jar), self._redirect_handler())
            self._openers[cookie_jar] = opener

        method = str(request.method or "GET").upper()
        url = request.url
        if request.params:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{urlencode(request.params)}"

        try:
            self._validate_outbound_url(url)
        except ValueError as exc:
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=None,
                headers={},
                body="",
                latency_seconds=0.0,
                error=f"blocked_url:{exc}",
            )

        data: bytes | None = None
        if isinstance(request.body, bytes):
            data = request.body
        elif isinstance(request.body, str):
            data = request.body.encode("utf-8")

        started = time.monotonic()
        try:
            raw_request = UrlRequest(url, data=data, headers=request.headers, method=method)  # noqa: S310
            with opener.open(  # noqa: S310
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

                body_bytes = raw_response.read(self.max_response_bytes + 1)
                truncated = len(body_bytes) > self.max_response_bytes
                if truncated:
                    self.truncations_count += 1
                    logger.warning(
                        "Response body from %s exceeded %d bytes limit and was truncated.",
                        url,
                        self.max_response_bytes,
                    )
                    # Telemetry metric for response truncation event
                    pass
                    body_bytes = body_bytes[: self.max_response_bytes]

                body_text = body_bytes.decode(charset, errors="replace")
                if truncated:
                    body_text = f"{body_text}\n...[truncated after {self.max_response_bytes} bytes]"
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
                logger.exception("Failed reading HTTPError body for %s", url)
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

    def _redirect_handler(self) -> HTTPRedirectHandler:
        engine = self

        class _SafeRedirectHandler(HTTPRedirectHandler):
            def redirect_request(
                self,
                req: Any,
                fp: Any,
                code: int,
                msg: str,
                headers: Any,
                newurl: str,
            ) -> Any:  # type: ignore[override]
                try:
                    engine._validate_outbound_url(str(newurl))
                except ValueError:
                    return None
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        return _SafeRedirectHandler()

    def _validate_outbound_url(self, url: str) -> None:
        parsed = urlparse(str(url))
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"unsupported_scheme:{scheme or 'missing'}")
        if parsed.username or parsed.password:
            raise ValueError("userinfo_not_allowed")
        if not (parsed.hostname or "").strip():
            raise ValueError("missing_host")

        if self.allow_private_networks:
            return

        safe = (
            is_safe_url_with_dns_check(str(url))
            if self.resolve_dns_for_ssrf_protection
            else is_safe_url(str(url))
        )
        if not safe:
            raise ValueError("unsafe_target")
