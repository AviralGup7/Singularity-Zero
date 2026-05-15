"""Opt-in sandbox runners for active scanner and validator plugins."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DockerSandboxConfig:
    """Configuration for running a JSON-callable plugin in Docker."""

    image: str = "python:3.14-slim"
    workdir: Path = field(default_factory=lambda: Path.cwd())
    timeout_seconds: int = 300
    network: str = "none"
    memory: str = "512m"
    cpus: str = "1.0"


class DockerSandboxRunner:
    """Run a Python callable in a lightweight Docker container.

    The callable must accept one JSON-serializable payload argument and return a
    JSON-serializable result. This keeps the isolation boundary explicit and
    avoids passing live orchestrator objects into an untrusted plugin process.
    """

    def __init__(self, config: DockerSandboxConfig | None = None) -> None:
        self.config = config or DockerSandboxConfig()

    def build_command(self, module: str, callable_name: str, payload: dict[str, Any]) -> list[str]:
        encoded_payload = json.dumps(payload, separators=(",", ":"))
        code = (
            "import importlib,json;"
            f"mod=importlib.import_module({module!r});"
            f"fn=getattr(mod,{callable_name!r});"
            f"print(json.dumps(fn(json.loads({encoded_payload!r}))))"
        )
        return [
            "docker",
            "run",
            "--rm",
            "--network",
            self.config.network,
            "--memory",
            self.config.memory,
            "--cpus",
            self.config.cpus,
            "-v",
            f"{self.config.workdir}:/workspace:ro",
            "-w",
            "/workspace",
            self.config.image,
            "python",
            "-c",
            code,
        ]

    def run(self, module: str, callable_name: str, payload: dict[str, Any]) -> Any:
        command = self.build_command(module, callable_name, payload)
        completed = subprocess.run(  # noqa: S603 - command is an argument list built by this runner.
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=self.config.timeout_seconds,
        )
        return json.loads(completed.stdout or "null")
