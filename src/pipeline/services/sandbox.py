"""Opt-in sandbox runners for active scanner and validator plugins."""

from __future__ import annotations

import json
import re
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
    allowed_networks: tuple[str, ...] = ("none",)
    memory: str = "512m"
    cpus: str = "1.0"
    # Allowlist to restrict what module/callable may run inside the sandbox.
    # Entries ending in '.' are treated as prefixes.
    allowed_modules: tuple[str, ...] = ("src.", "sample.")
    allowed_callables: tuple[str, ...] = ("run",)


class DockerSandboxRunner:
    """Run a Python callable in a lightweight Docker container.

    The callable must accept one JSON-serializable payload argument and return a
    JSON-serializable result. This keeps the isolation boundary explicit and
    avoids passing live orchestrator objects into an untrusted plugin process.
    """

    def __init__(self, config: DockerSandboxConfig | None = None) -> None:
        self.config = config or DockerSandboxConfig()

    _MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
    _CALLABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def _is_allowed(self, value: str, allowed: tuple[str, ...]) -> bool:
        for entry in allowed:
            if entry.endswith("."):
                if value.startswith(entry):
                    return True
            elif value == entry:
                return True
        return False

    def _validate_target(self, module: str, callable_name: str) -> None:
        module_clean = module.strip()
        callable_clean = callable_name.strip()
        if not self._MODULE_RE.match(module_clean):
            raise ValueError(f"Invalid module name for sandbox execution: {module!r}")
        if not self._CALLABLE_RE.match(callable_clean):
            raise ValueError(f"Invalid callable name for sandbox execution: {callable_name!r}")

        if not self._is_allowed(module_clean, self.config.allowed_modules):
            raise ValueError(
                f"Module '{module_clean}' is not allowlisted for sandbox execution"
            )
        if not self._is_allowed(callable_clean, self.config.allowed_callables):
            raise ValueError(
                f"Callable '{callable_clean}' is not allowlisted for sandbox execution"
            )

    def build_command(self, module: str, callable_name: str, payload: dict[str, Any]) -> list[str]:
        self._validate_target(module, callable_name)
        if self.config.network not in self.config.allowed_networks:
            raise ValueError(
                f"Docker network '{self.config.network}' is not allowlisted for sandbox execution"
            )
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
