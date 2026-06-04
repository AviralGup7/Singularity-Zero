"""
Interactive 3D Exploit Sandbox & Time-Travel Replay Service.

.. warning::

    This service is currently a **front-end mock** used to drive the 3D
    exploit cockpit and the time-travel replay UI. It does **not** spawn
    a real Docker container, and ``execute_terminal_command`` returns
    hard-coded strings for a small set of well-known commands and a
    generic "command not found" message for everything else. Do **not**
    rely on the output as evidence of any real interaction with the
    target system. A real, isolated execution backend (e.g.
    ``DockerSandboxRunner`` from ``src.pipeline.services.sandbox``) must
    be wired in before this service is used for any actual command
    execution against a production target.
"""

import time
import uuid
from typing import Any


class SandboxService:
    """Service to manage safe dockerized sandbox environments and time-travel replay.

    See the module-level docstring: this is a front-end mock. The methods
    on this class do not perform real system calls, network requests, or
    container lifecycle operations.
    """

    def __init__(self) -> None:
        self._sandboxes: dict[str, dict[str, Any]] = {}
        self._mock = True

    def launch_sandbox(self, target_node: str, image: str = "ubuntu:latest") -> str:
        """Launch a mock dockerized sandbox for a specific graph node."""
        sandbox_id = f"sandbox-{uuid.uuid4().hex[:8]}"
        self._sandboxes[sandbox_id] = {
            "id": sandbox_id,
            "target_node": target_node,
            "image": image,
            "status": "running",
            "created_at": time.time(),
            "history": [],
            "current_state": "Initialized secure enclave.",
            "is_mock": True,
        }
        self._record_event(sandbox_id, "Sandbox launched (MOCK)")
        return sandbox_id

    def _record_event(self, sandbox_id: str, action: str, output: str = "") -> None:
        sandbox = self._sandboxes.get(sandbox_id)
        if sandbox:
            history = sandbox.setdefault("history", [])
            if isinstance(history, list):
                history.append(
                    {
                        "timestamp": time.time(),
                        "action": action,
                        "output": output,
                        "is_mock": True,
                    }
                )

    def get_chronological_state(self, sandbox_id: str) -> list[dict[str, Any]]:
        """Retrieve the time-travel replay history of the sandbox."""
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            return []
        history = sandbox.get("history", [])
        return history if isinstance(history, list) else []

    def execute_terminal_command(self, sandbox_id: str, command: str) -> str:
        """Return a mock response for a small set of well-known commands.

        The returned string is **not** the result of any real execution.
        Callers that need real command execution must use a hardened
        execution backend instead of this service.
        """
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            raise ValueError(f"Sandbox {sandbox_id} not found")

        if sandbox["status"] != "running":
            raise ValueError(f"Sandbox {sandbox_id} is not running")

        prefix_marker = "[MOCK] "
        if command.startswith("ls"):
            output = (
                f"{prefix_marker}bin  boot  dev  etc  home  lib  opt  root  run  sbin  "
                "tmp  usr  var\n"
            )
        elif command.startswith("whoami"):
            output = f"{prefix_marker}root\n"
        elif command == "env":
            output = (
                f"{prefix_marker}PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
                "/sbin:/bin\n"
            )
        else:
            output = f"{prefix_marker}bash: {command}: command not found\n"

        self._record_event(sandbox_id, f"Executed: {command}", output)
        return output


# Singleton instance
sandbox_manager = SandboxService()
