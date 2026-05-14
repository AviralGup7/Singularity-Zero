"""Storage utilities for pipeline configuration, scope, and output persistence.

Provides functions for loading configs, reading scope files, managing
directories, and writing various output formats (lines, JSON, JSONL).
"""

import json
import shutil
from collections.abc import Iterable, Mapping
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from src.core.config import load_config as load_core_config
from src.core.contracts.pipeline import JSON_FORMAT
from src.core.models import Config

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

DISK_SPACE_WARN_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB


def load_config(path: Path) -> Config:
    return load_core_config(path)


def read_scope(path: Path) -> list[str]:
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        entries.append(value)
    if not entries:
        raise ValueError("Scope file is empty.")
    return entries


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def format_lines(items: Iterable[str]) -> str:
    normalized = sorted({item.strip() for item in items if item and item.strip()})
    return "\n".join(normalized) + ("\n" if normalized else "")


def format_ranked_lines(items: Iterable[str]) -> str:
    seen: set[str] = set()
    ordered = []
    for item in items:
        value = item.strip()
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return "\n".join(ordered) + ("\n" if ordered else "")


def format_json(payload: dict[str, Any] | list[Any]) -> str:
    return json.dumps(_to_json_safe(payload), indent=int(JSON_FORMAT["indent"]))


def format_jsonl(records: Iterable[dict[str, Any]]) -> str:
    lines = []
    for record in records:
        lines.append(
            json.dumps(
                _to_json_safe(record),
                ensure_ascii=bool(JSON_FORMAT["ensure_ascii"]),
            )
        )
    return "\n".join(lines) + ("\n" if lines else "")


def write_lines(path: Path, items: Iterable[str]) -> None:
    path.write_text(format_lines(items), encoding="utf-8")


def write_ranked_lines(path: Path, items: Iterable[str]) -> None:
    path.write_text(format_ranked_lines(items), encoding="utf-8")


def write_json(path: Path, payload: dict[str, Any] | list[Any]) -> None:
    path.write_text(format_json(payload), encoding="utf-8")


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.write_text(format_jsonl(records), encoding="utf-8")


def _to_json_safe(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return {str(k): _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, Mapping):
        return {str(k): _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_to_json_safe(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    return value


def validate_storage(output_dir: Path) -> dict[str, Any]:
    """Verify that the output directory is writable and has adequate space.

    Returns a status dict with keys: writable, free_bytes, free_gb,
    warnings, errors.
    """
    result: dict[str, Any] = {
        "output_dir": str(output_dir),
        "writable": False,
        "free_bytes": 0,
        "free_gb": 0.0,
        "warnings": [],
        "errors": [],
    }

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result["errors"].append(f"Cannot create output directory: {exc}")
        return result

    test_file = output_dir / ".storage_validation_test"
    try:
        test_file.write_text("validation", encoding="utf-8")
        test_file.unlink()
        result["writable"] = True
    except OSError as exc:
        result["errors"].append(f"Output directory is not writable: {exc}")
        return result

    try:
        usage = shutil.disk_usage(str(output_dir))
        result["free_bytes"] = usage.free
        result["free_gb"] = round(usage.free / (1024**3), 2)
        if usage.free < DISK_SPACE_WARN_BYTES:
            result["warnings"].append(
                f"Low disk space: {result['free_gb']} GB free (threshold: 1 GB)"
            )
            logger.warning(
                "Low disk space on %s: %.2f GB free",
                output_dir,
                result["free_gb"],
            )
    except OSError as exc:
        result["warnings"].append(f"Could not determine disk space: {exc}")

    return result


def preflight_storage_check(output_dir: Path) -> bool:
    """Run a pre-flight storage check before pipeline runs.

    Returns True if storage is ready, False otherwise.
    Logs warnings for non-fatal issues.
    """
    result = validate_storage(output_dir)

    if result["errors"]:
        for error in result["errors"]:
            logger.error("Storage pre-flight check failed: %s", error)
        return False

    if result["warnings"]:
        for warning in result["warnings"]:
            logger.warning("Storage pre-flight warning: %s", warning)

    return True


def check_disk_space(path: Path, min_bytes: int = DISK_SPACE_WARN_BYTES) -> dict[str, Any]:
    """Check available disk space at the given path.

    Returns a dict with free_bytes, free_gb, sufficient (bool), and warnings.
    """
    result: dict[str, Any] = {
        "path": str(path),
        "free_bytes": 0,
        "free_gb": 0.0,
        "min_required_bytes": min_bytes,
        "sufficient": False,
        "warnings": [],
    }

    try:
        usage = shutil.disk_usage(str(path))
        result["free_bytes"] = usage.free
        result["free_gb"] = round(usage.free / (1024**3), 2)
        result["sufficient"] = usage.free >= min_bytes
    except OSError as exc:
        result["free_bytes"] = -1
        result["warnings"] = [f"Could not determine disk space: {exc}"]

    return result
