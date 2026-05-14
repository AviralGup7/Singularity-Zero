import json
from pathlib import Path
from typing import Any


def tail_lines(path: Path, *, limit: int = 40) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [line.strip() for line in lines[-limit:] if line.strip()]


def read_all_lines(path: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def normalize_progress_status(value: object) -> str:
    status = str(value or "").strip().lower()
    if status in {"error", "failed", "timeout"}:
        return "error"
    if status in {"completed", "done", "success"}:
        return "completed"
    if status in {"skipped", "skip"}:
        return "skipped"
    return "running"


def last_progress_payload(lines: list[str], *, progress_prefix: str) -> dict[str, Any]:
    last_payload: dict[str, Any] = {}
    for line in lines:
        if not line.startswith(progress_prefix):
            continue
        try:
            parsed = json.loads(line[len(progress_prefix) :])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            last_payload = parsed
    return last_payload


def stage_from_transition_message(message: str, *, stage_labels: dict[str, str]) -> str:
    text = str(message or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered.startswith("entering stage:"):
        lowered = lowered.split(":", 1)[1].strip()

    for stage_name, stage_label in stage_labels.items():
        label_text = str(stage_label or "").strip().lower()
        if label_text and lowered == label_text:
            return str(stage_name)
    return ""


def last_progress_payload_from_file(path: Path, *, progress_prefix: str) -> dict[str, Any]:
    return last_progress_payload(read_all_lines(path), progress_prefix=progress_prefix)


def last_entered_stage_from_file(
    path: Path,
    *,
    progress_prefix: str,
    stage_labels: dict[str, str],
) -> str:
    last_stage = ""
    for line in read_all_lines(path):
        if line.startswith(progress_prefix):
            try:
                payload = json.loads(line[len(progress_prefix) :])
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            stage = str(payload.get("stage", "") or "").strip()
            message = str(payload.get("message", "") or "").strip()
            if stage and message.lower().startswith("entering stage:"):
                last_stage = stage
                continue

        if "Entering stage:" in line:
            derived = stage_from_transition_message(line, stage_labels=stage_labels)
            if derived:
                last_stage = derived
    return last_stage
