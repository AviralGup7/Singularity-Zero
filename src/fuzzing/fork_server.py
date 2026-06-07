import asyncio
import os
import secrets
import shutil
import subprocess
import tempfile
from typing import Any


class ForkServer:
    def __init__(self, target_cmd: list[str], corpus_dir: str = ".fuzz_corpus") -> None:
        self.target_cmd = target_cmd
        self.corpus_dir = corpus_dir
        self.alive: bool = False
        self._process: subprocess.Popen | None = None

    async def start(self) -> None:
        os.makedirs(self.corpus_dir, exist_ok=True)
        for i in range(4):
            seed = secrets.token_bytes(64)
            with open(os.path.join(self.corpus_dir, f"seed_{i}.bin"), "wb") as f:
                f.write(seed)
        self._process = subprocess.Popen(
            self.target_cmd,
            cwd=self.corpus_dir,
        )
        self.alive = True

    async def run_iteration(self, payload: bytes) -> dict[str, Any]:
        tmp_path = os.path.join(self.corpus_dir, f"tmp_{secrets.token_hex(8)}.bin")
        with open(tmp_path, "wb") as f:
            f.write(payload)
        try:
            cmd = self.target_cmd + [tmp_path]
            proc = subprocess.run(cmd, capture_output=True, timeout=5)
            return {
                "exit_code": proc.returncode,
                "output": proc.stdout.decode("utf-8", errors="ignore"),
                "timed_out": False,
            }
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "output": "",
                "timed_out": True,
            }
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    async def stop(self) -> None:
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self.alive = False
        if os.path.isdir(self.corpus_dir):
            shutil.rmtree(self.corpus_dir, ignore_errors=True)
