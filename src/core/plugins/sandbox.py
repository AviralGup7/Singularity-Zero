from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

from src.core.plugins.sdk import PluginManifest


class PluginSandboxError(RuntimeError):
    """Raised when a dynamic plugin fails inside its isolation boundary."""


class ProcessSandboxCallable:
    """JSON-only process boundary for dynamic Python plugins."""

    def __init__(self, manifest: PluginManifest, path: Path) -> None:
        self.manifest = manifest
        self.path = path

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if len(args) == 1 and not kwargs and isinstance(args[0], dict):
            payload = args[0]
        else:
            payload = {"args": args, "kwargs": kwargs}
        return run_python_plugin_process(
            self.path, self.manifest.entrypoint, payload, self.manifest.timeout_seconds
        )


def run_python_plugin_process(
    path: Path,
    entrypoint: str,
    payload: dict[str, Any],
    timeout_seconds: int,
) -> Any:
    command = [
        sys.executable,
        "-m",
        "src.core.plugins.sandbox",
        str(path),
        entrypoint,
    ]
    completed = subprocess.run(  # noqa: S603 - command is fixed and argument-vector based.
        command,
        input=json.dumps(payload, separators=(",", ":")),
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "plugin process failed").strip()
        raise PluginSandboxError(detail)
    try:
        return json.loads(completed.stdout or "null")
    except json.JSONDecodeError as exc:
        raise PluginSandboxError("plugin returned non-JSON output") from exc


def _run_child(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: python -m src.core.plugins.sandbox <plugin.py> <entrypoint>", file=sys.stderr)
        return 2

    plugin_path = Path(argv[1]).resolve()
    entrypoint = argv[2]
    payload = json.loads(sys.stdin.read() or "{}")
    namespace = runpy.run_path(str(plugin_path), run_name="__dynamic_plugin__")
    fn = namespace.get(entrypoint)
    if not callable(fn):
        print(f"entrypoint '{entrypoint}' is not callable", file=sys.stderr)
        return 3
    result = fn(payload)
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_child(sys.argv))
