"""Automation task executor.

Consumes the task descriptors produced by
:func:`src.analysis.automation.manual_queue.build_automation_tasks` and
dispatches each one through the canonical
:func:`src.pipeline.services.tool_execution.run_external_tool` entrypoint.

Supported task kinds (see :data:`SUPPORTED_TASK_KINDS`):

* ``run_curl_poc``            — execute a stored curl PoC command
* ``run_python_poc``          — execute a stored Python PoC script
* ``replay_variant_inherit``  — replay a previously captured request with
                                the inheriting auth context
* ``replay_variant_anonymous``— replay with the anonymous context
* ``collect_api_baseline``    — capture a fresh baseline of API statuses
                                so a future run can diff against it

The executor never mutates a task descriptor.  Each invocation returns a
:class:`TaskExecutionResult` that records the outcome, the captured
stdout/stderr snippet, the exit code, and any error.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.pipeline.services.tool_execution import (
    CompletedToolRun,
    ToolInvocation,
    run_external_tool,
)

logger = logging.getLogger(__name__)


SUPPORTED_TASK_KINDS: frozenset[str] = frozenset(
    {
        "run_curl_poc",
        "run_python_poc",
        "replay_variant_inherit",
        "replay_variant_anonymous",
        "collect_api_baseline",
    }
)


@dataclass(frozen=True, slots=True)
class TaskExecutionResult:
    """Outcome of a single automation task execution."""

    kind: str
    title: str
    ok: bool
    exit_code: int = 0
    timed_out: bool = False
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    duration_seconds: float = 0.0
    error: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_excerpt": self.stdout_excerpt,
            "stderr_excerpt": self.stderr_excerpt,
            "duration_seconds": round(self.duration_seconds, 3),
            "error": self.error,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class AutomationTaskExecutor:
    """Execute automation task descriptors produced by the manual-queue builder.

    Attributes:
        max_concurrency: Maximum number of tasks executed in parallel.
            Default 4 — picked to be friendly to LLM-rate-limited and
            rate-limited API backends while still keeping CPU busy.
        per_task_timeout_seconds: Wall-clock cap per task.  ``0`` disables
            the cap (delegates to ``run_external_tool`` defaults).
        max_stdout_bytes: Cap on captured stdout per task.  Helps prevent
            huge replay responses from blowing up the executor log.
        replay_base_url: Base URL used to materialise
            ``replay_variant_*`` URLs that arrive as relative paths.
            Falls back to ``http://127.0.0.1:8000`` for local
            development.
    """

    max_concurrency: int = 4
    per_task_timeout_seconds: int = 60
    max_stdout_bytes: int = 8_000
    replay_base_url: str = "http://127.0.0.1:8000"

    def __post_init__(self) -> None:
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if self.per_task_timeout_seconds < 0:
            raise ValueError("per_task_timeout_seconds must be >= 0")

    async def execute_all(
        self, tasks: Sequence[Mapping[str, Any]]
    ) -> list[TaskExecutionResult]:
        """Execute every supported task, returning one result per task.

        Tasks with unsupported ``kind`` values are returned as failed
        results carrying an explanatory ``error`` so callers can log
        them without crashing the batch.
        """
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _run(task: Mapping[str, Any]) -> TaskExecutionResult:
            async with semaphore:
                return await self._execute_one(task)

        return await asyncio.gather(*[_run(t) for t in tasks])

    async def _execute_one(self, task: Mapping[str, Any]) -> TaskExecutionResult:
        kind = str(task.get("kind", "")).strip()
        title = str(task.get("title", kind)) or kind

        if not kind:
            return TaskExecutionResult(
                kind=kind,
                title=title,
                ok=False,
                error="missing 'kind' attribute on task descriptor",
            )

        if kind not in SUPPORTED_TASK_KINDS:
            return TaskExecutionResult(
                kind=kind,
                title=title,
                ok=False,
                error=f"unsupported task kind: {kind!r}",
            )

        try:
            if kind == "run_curl_poc":
                return await self._run_curl_poc(task)
            if kind == "run_python_poc":
                return await self._run_python_poc(task)
            if kind in {"replay_variant_inherit", "replay_variant_anonymous"}:
                return await self._run_replay(task)
            if kind == "collect_api_baseline":
                return await self._collect_api_baseline(task)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Automation task %s raised: %s", kind, exc)
            return TaskExecutionResult(
                kind=kind,
                title=title,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        return TaskExecutionResult(
            kind=kind,
            title=title,
            ok=False,
            error=f"unhandled task kind: {kind!r}",
        )

    def _truncate(self, text: str) -> str:
        if len(text) <= self.max_stdout_bytes:
            return text
        return text[: self.max_stdout_bytes] + f"... [truncated {len(text) - self.max_stdout_bytes} bytes]"

    def _invocation_from_command(
        self, *, tool_name: str, command: str, timeout: int | None
    ) -> ToolInvocation:
        """Wrap a free-form command string in a :class:`ToolInvocation`.

        ``shlex.split`` is used so multi-argument commands survive
        transport intact.  Commands containing shell metacharacters
        (``; | & $ ` \\n``) are rejected — the executor never passes
        commands through a shell.
        """
        if not command or not command.strip():
            raise ValueError("empty command")
        meta = re_shell_meta()
        if meta.search(command):
            raise ValueError(
                "command rejected by shell-metacharacter guard; "
                "automation tasks must not contain ';', '|', '&', '$', '`', or newlines"
            )
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            raise ValueError(f"could not parse command: {exc}") from exc
        if not parts:
            raise ValueError("command parsed to zero tokens")
        return ToolInvocation(
            tool_name=parts[0] or tool_name,
            args=parts[1:],
            timeout_seconds=(
                self.per_task_timeout_seconds
                if timeout is None and self.per_task_timeout_seconds > 0
                else timeout
            ),
        )

    async def _dispatch(
        self, invocation: ToolInvocation, metadata: Mapping[str, Any] | None = None
    ) -> CompletedToolRun:
        return await run_external_tool(invocation)

    def _wrap_result(
        self,
        *,
        kind: str,
        title: str,
        run: CompletedToolRun,
        metadata: Mapping[str, Any] | None = None,
    ) -> TaskExecutionResult:
        return TaskExecutionResult(
            kind=kind,
            title=title,
            ok=run.ok,
            exit_code=run.exit_code,
            timed_out=run.timed_out,
            stdout_excerpt=self._truncate(run.stdout),
            stderr_excerpt=self._truncate(run.stderr),
            duration_seconds=run.duration_seconds,
            metadata=dict(metadata or {}),
        )

    async def _run_curl_poc(self, task: Mapping[str, Any]) -> TaskExecutionResult:
        command = str(task.get("command", "") or "").strip()
        title = str(task.get("title", "Run curl PoC"))
        if not command:
            return TaskExecutionResult(
                kind="run_curl_poc",
                title=title,
                ok=False,
                error="no curl command attached to task",
            )
        try:
            invocation = self._invocation_from_command(
                tool_name="curl", command=command, timeout=None
            )
        except ValueError as exc:
            return TaskExecutionResult(
                kind="run_curl_poc",
                title=title,
                ok=False,
                error=str(exc),
            )
        started = time.monotonic()
        run = await self._dispatch(invocation)
        result = self._wrap_result(
            kind="run_curl_poc",
            title=title,
            run=run,
            metadata={"command": command},
        )
        if result.duration_seconds == 0.0:
            result = TaskExecutionResult(
                kind=result.kind,
                title=result.title,
                ok=result.ok,
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                stdout_excerpt=result.stdout_excerpt,
                stderr_excerpt=result.stderr_excerpt,
                duration_seconds=round(time.monotonic() - started, 3),
                metadata=result.metadata,
            )
        return result

    async def _run_python_poc(self, task: Mapping[str, Any]) -> TaskExecutionResult:
        command = str(task.get("command", "") or "").strip()
        title = str(task.get("title", "Run Python PoC"))
        if not command:
            return TaskExecutionResult(
                kind="run_python_poc",
                title=title,
                ok=False,
                error="no Python script attached to task",
            )
        try:
            invocation = self._invocation_from_command(
                tool_name="python",
                command=command,
                timeout=None,
            )
        except ValueError as exc:
            return TaskExecutionResult(
                kind="run_python_poc",
                title=title,
                ok=False,
                error=str(exc),
            )
        run = await self._dispatch(invocation)
        return self._wrap_result(
            kind="run_python_poc",
            title=title,
            run=run,
            metadata={"command": command},
        )

    async def _run_replay(self, task: Mapping[str, Any]) -> TaskExecutionResult:
        kind = str(task.get("kind", ""))
        title = str(task.get("title", "Replay"))
        url = str(task.get("url", "") or "").strip()
        if not url:
            return TaskExecutionResult(
                kind=kind,
                title=title,
                ok=False,
                error="replay task missing 'url' attribute",
            )
        full_url = self._materialise_replay_url(url)
        auth_mode = "anonymous" if kind == "replay_variant_anonymous" else "inherit"
        command = f"curl -sS -i -X GET --max-time 30 {shlex.quote(full_url)}"
        try:
            invocation = self._invocation_from_command(
                tool_name="curl", command=command, timeout=None
            )
        except ValueError as exc:
            return TaskExecutionResult(
                kind=kind,
                title=title,
                ok=False,
                error=str(exc),
            )
        run = await self._dispatch(invocation)
        return self._wrap_result(
            kind=kind,
            title=title,
            run=run,
            metadata={"url": full_url, "auth_mode": auth_mode},
        )

    async def _collect_api_baseline(
        self, task: Mapping[str, Any]
    ) -> TaskExecutionResult:
        kind = "collect_api_baseline"
        title = str(task.get("title", "Collect API baseline"))
        target_url = str(task.get("url", "") or "").strip()
        if not target_url:
            return TaskExecutionResult(
                kind=kind,
                title=title,
                ok=False,
                error="collect_api_baseline task missing 'url' attribute",
            )
        command = f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 20 {shlex.quote(target_url)}"
        try:
            invocation = self._invocation_from_command(
                tool_name="curl", command=command, timeout=None
            )
        except ValueError as exc:
            return TaskExecutionResult(
                kind=kind,
                title=title,
                ok=False,
                error=str(exc),
            )
        run = await self._dispatch(invocation)
        status_code = -1
        try:
            status_code = int(str(run.stdout).strip().splitlines()[-1].strip())
        except (ValueError, IndexError):
            pass
        return self._wrap_result(
            kind=kind,
            title=title,
            run=run,
            metadata={
                "url": target_url,
                "status_code": status_code,
                "baseline_recorded_at": time.time(),
            },
        )

    def _materialise_replay_url(self, url: str) -> str:
        """Resolve a replay descriptor into an absolute URL.

        Replay URLs produced by ``attach_queue_replay_links`` are
        relative paths such as ``/api/replay?target=...``.  When the
        executor runs in a CI environment we want to be able to point
        at a different host, so the executor exposes ``replay_base_url``
        as an instance knob.
        """
        if url.lower().startswith(("http://", "https://")):
            return url
        base = self.replay_base_url.rstrip("/")
        if not url.startswith("/"):
            url = "/" + url
        return f"{base}{url}"


_SHELL_META: Any = None


def re_shell_meta() -> Any:
    """Lazily compiled shell-metacharacter guard (cached at module level)."""
    global _SHELL_META
    if _SHELL_META is None:
        import re

        _SHELL_META = re.compile(r"[;|&$`\n\r]")
    return _SHELL_META


def execute_queue_tasks(
    tasks: Iterable[Mapping[str, Any]],
    *,
    executor: AutomationTaskExecutor | None = None,
) -> list[TaskExecutionResult]:
    """Convenience helper: run ``tasks`` synchronously from a queue.

    Used by ad-hoc scripts and test harnesses that need to drain a
    queue without spinning up the full pipeline.
    """
    ex = executor or AutomationTaskExecutor()
    return asyncio.run(ex.execute_all(list(tasks)))


def results_to_json(results: Sequence[TaskExecutionResult]) -> str:
    """Serialize :class:`TaskExecutionResult` list to a JSON string."""
    return json.dumps([r.to_dict() for r in results], indent=2, default=str)
