from pathlib import Path

from src.pipeline.services.sandbox import DockerSandboxConfig, DockerSandboxRunner


def test_docker_sandbox_command_is_restricted() -> None:
    runner = DockerSandboxRunner(
        DockerSandboxConfig(
            image="python:test",
            workdir=Path("D:/workspace"),
            network="none",
            memory="256m",
            cpus="0.5",
        )
    )

    command = runner.build_command("sample.plugin", "run", {"target": "example.com"})

    assert command[:5] == ["docker", "run", "--rm", "--network", "none"]
    assert "--memory" in command
    assert "256m" in command
    assert "--cpus" in command
    assert "0.5" in command
    assert "python:test" in command
    assert "/workspace:ro" in command[command.index("-v") + 1]
