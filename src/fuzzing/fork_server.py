import hashlib
import logging
import os
import random
import secrets
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class ForkServer:
    """Subprocess-based fuzzing with coverage feedback integration.

    Manages a target binary/process, runs fuzzing iterations with
    mutated payloads, and feeds coverage data back to a CorpusManager.
    Supports persistent mode (shared memory coverage map via tempfile).
    """

    def __init__(
        self,
        target_cmd: list[str],
        corpus_dir: str = ".fuzz_corpus",
        coverage_tracker: Any = None,
        corpus_manager: Any = None,
    ) -> None:
        self.target_cmd = target_cmd
        self.corpus_dir = corpus_dir
        self.coverage_tracker = coverage_tracker
        self.corpus_manager = corpus_manager
        self.alive: bool = False
        self._process: subprocess.Popen | None = None
        self._iteration_count: int = 0
        self._findings: list[dict[str, Any]] = []

    async def start(self) -> None:
        os.makedirs(self.corpus_dir, exist_ok=True)
        for i in range(4):
            seed = secrets.token_bytes(64)
            with open(os.path.join(self.corpus_dir, f"seed_{i}.bin"), "wb") as f:
                f.write(seed)
        self._process = subprocess.Popen(  # noqa: S603
            self.target_cmd,
            cwd=self.corpus_dir,
        )
        self.alive = True
        logger.info("ForkServer started: %s in %s", self.target_cmd, self.corpus_dir)

    _MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB limit

    async def run_iteration(self, payload: bytes) -> dict[str, Any]:
        if len(payload) > self._MAX_PAYLOAD_SIZE:
            logger.warning("ForkServer: payload too large (%d bytes), skipping", len(payload))
            return {
                "exit_code": -2,
                "output": "",
                "timed_out": False,
                "payload_len": len(payload),
            }

        tmp_path = os.path.join(self.corpus_dir, f"tmp_{secrets.token_hex(8)}.bin")
        with open(tmp_path, "wb") as f:
            f.write(payload)
        try:
            cmd = self.target_cmd + [tmp_path]
            proc = subprocess.run(cmd, capture_output=True, timeout=5)  # noqa: S603
            result = {
                "exit_code": proc.returncode,
                "output": proc.stdout.decode("utf-8", errors="replace"),
                "stderr": proc.stderr.decode("utf-8", errors="replace"),
                "timed_out": False,
                "payload_len": len(payload),
            }

            # Feed coverage information back to the CorpusManager
            if self.coverage_tracker is not None and self.corpus_manager is not None:
                self._update_coverage(payload, proc, result)

            self._iteration_count += 1
            return result
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "output": "",
                "timed_out": True,
                "payload_len": len(payload),
            }
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _update_coverage(
        self,
        payload: bytes,
        proc: subprocess.CompletedProcess,
        result: dict[str, Any],
    ) -> None:
        """Feed iteration results into CoverageTracker and CorpusManager."""
        if self.coverage_tracker is None or self.corpus_manager is None:
            return

        exit_code = result["exit_code"]
        output_len = len(result["output"])
        output_hash = hashlib.md5(  # noqa: S324  # nosec
            result["output"][:8192].encode("utf-8", errors="replace")
        ).hexdigest()
        payload_str = payload.decode("utf-8", errors="replace")

        # Record coverage edges based on exit code, output length, hash
        edge_sig = self.coverage_tracker.record_edge(
            endpoint="fork:" + " ".join(self.target_cmd),
            status_code=exit_code,
            response_len=output_len,
            content_hash=output_hash,
        )

        if edge_sig:
            logger.debug("ForkServer: new coverage edge: %s", edge_sig)
            self.corpus_manager.add(payload=payload_str, signature=edge_sig)
            self._findings.append(
                {
                    "type": "fork_coverage_new_edge",
                    "edge_signature": edge_sig,
                    "exit_code": exit_code,
                    "output_length": output_len,
                    "payload": payload_str[:100],
                }
            )

        # Record crashes as branches
        if exit_code < 0 or exit_code >= 128:
            _ = self.coverage_tracker.record_branch(
                endpoint="fork:" + " ".join(self.target_cmd),
                path=f"crash_exit_{exit_code}",
            )
            self._findings.append(
                {
                    "type": "fork_crash_detected",
                    "exit_code": exit_code,
                    "payload": payload_str[:100],
                    "stderr": proc.stderr.decode("utf-8", errors="ignore")[:200],
                }
            )

    async def run_fuzzing_loop(
        self,
        max_iterations: int = 1000,
        mutation_func: Any = None,
    ) -> list[dict[str, Any]]:
        """Run a complete fuzzing loop with mutation-based payload generation.

        Uses the CorpusManager for seed selection and the provided
        mutation function for generating new payloads from existing seeds.
        """
        if not self.alive:
            await self.start()

        if mutation_func is None:
            mutation_func = self._default_mutate

        for i in range(max_iterations):
            # Get a seed payload from the corpus manager
            seed = None
            if self.corpus_manager is not None:
                entry = self.corpus_manager.select_next()
                if entry is not None:
                    seed = entry.payload.encode("utf-8", errors="ignore")

            if seed is None:
                seed = secrets.token_bytes(random.randint(8, 64))  # noqa: S311

            # Mutate the seed
            mutated = mutation_func(seed)
            result = await self.run_iteration(mutated)

            if result.get("exit_code", 0) < 0:
                logger.warning("ForkServer: iteration %d crashed (exit=%d)", i, result["exit_code"])

        return self._findings

    def _default_mutate(self, data: bytes) -> bytes:
        """Default mutation: bit flips, byte swaps, random insertions."""
        if not data:
            return secrets.token_bytes(16)
        arr = bytearray(data)
        choice = secrets.randbelow(4)
        if choice == 0:
            # Bit flip
            idx = secrets.randbelow(len(arr))
            bit = secrets.randbelow(8)
            arr[idx] ^= 1 << bit
        elif choice == 1 and len(arr) >= 2:
            # Byte swap
            i = secrets.randbelow(len(arr))
            j = secrets.randbelow(len(arr))
            arr[i], arr[j] = arr[j], arr[i]
        elif choice == 2:
            # Random insertion
            idx = secrets.randbelow(len(arr) + 1)
            arr[idx:idx] = secrets.token_bytes(1)
        else:
            # Delete byte
            if len(arr) > 1:
                idx = secrets.randbelow(len(arr))
                arr = arr[:idx] + arr[idx + 1 :]
        return bytes(arr)

    async def get_corpus_stats(self) -> dict[str, Any]:
        """Return statistics about the fuzzing session."""
        stats = {
            "iterations": self._iteration_count,
            "findings_count": len(self._findings),
            "alive": self.alive,
        }
        if self.corpus_manager is not None:
            stats["corpus_size"] = (
                len(self.corpus_manager.entries) if hasattr(self.corpus_manager, "entries") else 0
            )
        return stats

    async def stop(self) -> None:
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired as exc:
                    logger.warning("Operation failed in fork_server.py: %s", exc, exc_info=True)  # noqa: BLE001
        self.alive = False
        if os.path.isdir(self.corpus_dir):
            shutil.rmtree(self.corpus_dir, ignore_errors=True)
        logger.info("ForkServer stopped after %d iterations", self._iteration_count)

    @property
    def iteration_count(self) -> int:
        return self._iteration_count
