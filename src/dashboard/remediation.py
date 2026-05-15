"""Remediation suggestion engine backed by .ai/remediation_logic.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_remediation_logic(path: Path | None = None) -> dict[str, Any]:
    logic_path = path or _repo_root() / ".ai" / "remediation_logic.json"
    try:
        payload = json.loads(logic_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"strategies": [], "fix_commands": []}
    if not isinstance(payload, dict):
        return {"strategies": [], "fix_commands": []}
    return payload


def _haystack(payload: dict[str, Any]) -> str:
    keys = (
        "id",
        "type",
        "category",
        "title",
        "description",
        "module",
        "severity",
        "url",
        "target",
        "error",
        "failure_reason",
        "failure_reason_code",
        "failed_stage",
        "status_message",
    )
    return " ".join(str(payload.get(key, "")) for key in keys).lower()


def _action_to_command(action: dict[str, Any]) -> dict[str, Any]:
    action_name = str(action.get("action", "")).strip()
    if not action_name:
        return {}

    command_map = {
        "increase_timeout": "cyber scan run --config configs/config.example.json --scope configs/scope.example.txt --force-fresh-run",
        "reduce_concurrency": "Set the scan concurrency override to a lower value, then rerun the job.",
        "verify_service_health": f"kubectl get pods,svc -l app={action.get('service', 'redis')}",
        "retry_with_backoff": "cyber scan run --config configs/config.example.json --scope configs/scope.example.txt --refresh-cache",
        "reduce_batch_size": "Lower batch size in the runtime overrides and restart the job.",
        "clear_in_memory_cache": "Restart the worker or dashboard process to clear process-local cache.",
        "log_missing_dependency": "Install the missing scanner binary, then run cyber scan run again.",
        "disable_dependent_stages": "Disable stages that require the missing dependency until the tool is installed.",
    }
    return {
        "id": action_name,
        "title": action_name.replace("_", " ").title(),
        "command": command_map.get(action_name, action_name),
        "rationale": "Suggested from the pipeline recovery strategy table.",
        "safety_note": "Review the command against the target environment before running it.",
    }


def suggest_for_job(job: dict[str, Any]) -> list[dict[str, Any]]:
    logic = load_remediation_logic()
    text = _haystack(job)
    status = str(job.get("status", "")).lower()
    suggestions: list[dict[str, Any]] = []

    for strategy in logic.get("strategies", []):
        if not isinstance(strategy, dict):
            continue
        trigger = strategy.get("trigger")
        if not isinstance(trigger, dict):
            continue
        outcome = str(trigger.get("stage_outcome", "")).lower()
        pattern = str(trigger.get("error_pattern", trigger.get("reason", ""))).lower()
        if outcome and outcome != status:
            continue
        if pattern and pattern not in text:
            continue
        for action in strategy.get("actions", []):
            if isinstance(action, dict):
                suggestion = _action_to_command(action)
                if suggestion:
                    suggestions.append(suggestion)

    return _dedupe_suggestions(suggestions)


def suggest_for_finding(finding: dict[str, Any]) -> list[dict[str, Any]]:
    logic = load_remediation_logic()
    text = _haystack(finding)
    suggestions: list[dict[str, Any]] = []

    for entry in logic.get("fix_commands", []):
        if not isinstance(entry, dict):
            continue
        match = entry.get("match")
        keywords = match.get("keywords", []) if isinstance(match, dict) else []
        if not any(str(keyword).lower() in text for keyword in keywords):
            continue
        for command in entry.get("commands", []):
            command_text = str(command).strip()
            if not command_text:
                continue
            suggestions.append(
                {
                    "id": entry.get("id", command_text),
                    "title": entry.get("title", "Fix Command"),
                    "command": command_text,
                    "rationale": entry.get("rationale", ""),
                    "safety_note": entry.get("safety_note", ""),
                }
            )

    return _dedupe_suggestions(suggestions)


def _dedupe_suggestions(suggestions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for suggestion in suggestions:
        key = (str(suggestion.get("id", "")), str(suggestion.get("command", "")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(suggestion)
    return unique[:6]
