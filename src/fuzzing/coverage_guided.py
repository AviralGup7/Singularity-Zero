import asyncio
import hashlib
import heapq
import httpx
import logging
import secrets
from typing import Any
from urllib.parse import urlencode, urlparse

logger = logging.getLogger(__name__)


class CorpusEntry:
    def __init__(self, payload: str, signature: str, energy: int = 10) -> None:
        self.payload: str = payload
        self.signature: str = signature
        self.energy: int = energy
        self.birth_time: float = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0.0
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
    if not data:
        return "A"
    byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
    if len(byte_arr) > 0:
        idx = secrets.randbelow(len(byte_arr))
        bit = secrets.randbelow(8)
        byte_arr[idx] ^= 1 << bit
    return byte_arr.decode("utf-8", errors="ignore")


def boundary_values(param_type: str) -> list[str]:
    if param_type == "numeric":
        return ["0", "-1", "2147483647", "-2147483648", "9223372036854775807", "4294967295"]
    if param_type == "id":
        return ["0", "-1", "999999", "00000000-0000-4000-8000-000000000000"]
    if param_type == "json":
        return ['{"$ne": null}', "[]", "{}", '{"a":' * 100 + "1" + "}" * 100]
    return ["A" * 10000, "", " ", "null", "undefined"]


def dictionary_attack() -> list[str]:
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
    ]
    return secrets.SystemRandom().sample(payloads, len(payloads))


async def _execute_coverage_guided_fuzz(
    url: str,
    corpus: CorpusManager,
    tracker: CoverageTracker,
    *,
    client: httpx.AsyncClient,
    timeout_seconds: float = 5.0,
    max_rounds: int = 20,
) -> list[dict[str, Any]]:
    from src.analysis.helpers import endpoint_base_key, endpoint_signature

    parsed = urlparse(url)
    base_payload = parsed.query or parsed.path or "/"
    base_signature = f"seed:{hashlib.md5(base_payload.encode()).hexdigest()[:8]}"
    corpus.add(payload=base_payload, signature=base_signature)

    findings: list[dict[str, Any]] = []

    for _ in range(max_rounds):
        entry = corpus.select_next()
        if entry is None:
            break

        mutated_payloads = [bit_flip(entry.payload)]
        for v in boundary_values("default"):
            mutated_payloads.append(v)
        mutated_payloads.extend(dictionary_attack())

        endpoint_key = endpoint_signature(url)
        endpoint_base = endpoint_base_key(url)

        for mutated in mutated_payloads:
            try:
                if "?" in url:
                    mutated_url = url + "&fuzz=" + mutated
                else:
                    mutated_url = url + "?fuzz=" + mutated
                resp = await client.get(mutated_url, timeout=timeout_seconds)
                status = resp.status_code
                body = resp.text
                resp_len = len(body)
            except Exception:
                continue

            content_hash = hashlib.md5(body[:8192].encode("utf-8", errors="ignore")).hexdigest()
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


async def run_coverage_guided_campaign(
    url: str,
    corpus: CorpusManager,
    tracker: CoverageTracker,
    *,
    client: httpx.AsyncClient,
    timeout_seconds: float = 5.0,
    max_rounds: int = 20,
) -> list[dict[str, Any]]:
    return await _execute_coverage_guided_fuzz(
        url,
        corpus,
        tracker,
        client=client,
        timeout_seconds=timeout_seconds,
        max_rounds=max_rounds,
    )
