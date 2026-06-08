"""Grammar-based parameter fuzzer and mutation campaign orchestrator.

Provides mutation strategies and coverage-guided feedback loops for fuzzing API endpoints.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.mutation_engine import detect_parameter_type
from src.core.utils.url_validation import is_safe_url_with_dns_check
from src.fuzzing.stop_conditions import (
    StopCondition,
    StopOnFirstFinding,
)

try:
    from src.fuzzing.h2_fuzzer import run_h2_fuzzing_campaign
except ImportError:
    run_h2_fuzzing_campaign = None  # type: ignore[misc,assignment]
try:
    from src.fuzzing.quic_fuzzer import run_quic_fuzzing_campaign
except ImportError:
    run_quic_fuzzing_campaign = None  # type: ignore[misc,assignment]

try:
    from src.core.session import Session
except ImportError:
    Session = Any  # type: ignore[misc,assignment]

try:
    from src.fuzzing.stateful_fuzzer import run_stateful_fuzzing_campaign
except ImportError:
    run_stateful_fuzzing_campaign = None  # type: ignore[misc,assignment]
try:
    from src.fuzzing.differential_fuzzer import run_differential_fuzzing_campaign
except ImportError:
    run_differential_fuzzing_campaign = None  # type: ignore[misc,assignment]
try:
    from src.fuzzing.coverage_guided import CorpusManager, CoverageTracker
except ImportError:
    CorpusManager = Any  # type: ignore[misc,assignment]
    CoverageTracker = Any  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


class FIFODict(dict):
    def __init__(self, max_size: int = 500, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.max_size = max_size

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, value)
        if len(self) > self.max_size:
            first_key = next(iter(self))
            self.pop(first_key, None)

    def setdefault(self, key: Any, default: Any = None) -> Any:
        if key not in self:
            self[key] = default
        return self[key]


class FuzzingRequestSender:
    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    async def get_url(
        self, client: httpx.AsyncClient, url: str, timeout_seconds: float | None = None
    ) -> httpx.Response:
        t = timeout_seconds if timeout_seconds is not None else self.timeout_seconds
        return await client.get(url, timeout=t)


class FuzzingFeedbackTracker:
    def __init__(self) -> None:
        self.metrics: dict[str, int] = {
            "total_requests_sent": 0,
            "payloads_tried": 0,
            "anomalies_detected": 0,
        }

        self._covered_paths: set[str] = set()

    def record_request(self) -> None:
        self.metrics["total_requests_sent"] += 1

    def record_payload(self) -> None:
        self.metrics["payloads_tried"] += 1

    def record_anomaly(self) -> None:
        self.metrics["anomalies_detected"] += 1

    def record_covered_path(self, signature: str) -> None:
        self.metrics["covered_paths"] = self.metrics.get("covered_paths", 0) + 1
        self._covered_paths.add(signature)

    def get_coverage_count(self) -> int:
        return len(self._covered_paths)


class FuzzingOrchestrator:
    def __init__(
        self,
        target_endpoints: list[str],
        stop_condition: StopCondition | None = None,
    ) -> None:
        self.target_endpoints = target_endpoints
        self._coverage_feedback = FIFODict(max_size=500)
        self._mutation_history = FIFODict(max_size=500)
        self.request_sender = FuzzingRequestSender()
        self.feedback_tracker = FuzzingFeedbackTracker()
        self.stop_condition = stop_condition if stop_condition is not None else StopOnFirstFinding()
        # Adaptive mutation tracking: records which strategies produce findings
        # to weight future payloads towards more effective strategies.
        self._strategy_effectiveness: dict[str, dict[str, int]] = {}
        self._strategy_total: dict[str, int] = {}

    def _record_strategy_outcome(self, strategy: str, had_finding: bool) -> None:
        """Track whether a mutation strategy produced a finding."""
        if strategy not in self._strategy_effectiveness:
            self._strategy_effectiveness[strategy] = {"findings": 0, "total": 0}
        self._strategy_effectiveness[strategy]["total"] += 1
        self._strategy_total[strategy] = self._strategy_total.get(strategy, 0) + 1
        if had_finding:
            self._strategy_effectiveness[strategy]["findings"] += 1

    def _strategy_weight(self, strategy: str) -> float:
        """Return a weight for a strategy based on past effectiveness."""
        stats = self._strategy_effectiveness.get(strategy)
        if not stats or stats["total"] < 3:
            return 1.0
        success_rate = stats["findings"] / stats["total"]
        return 1.0 + (success_rate * 5.0)

    def _prioritize_payloads(self, payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Reorder payloads based on adaptive strategy effectiveness."""
        for p in payloads:
            p["_weight"] = self._strategy_weight(p.get("strategy", "unknown"))
        payloads.sort(key=lambda x: x.get("_weight", 1.0), reverse=True)
        return payloads

    def bit_flip(self, data: str) -> str:
        if not data:
            return "A"
        byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
        if len(byte_arr) > 0:
            idx = secrets.randbelow(len(byte_arr))
            bit = secrets.randbelow(8)
            byte_arr[idx] ^= 1 << bit
        return byte_arr.decode("utf-8", errors="ignore")

    def boundary_values(self, param_type: str) -> list[str]:
        if param_type == "numeric":
            return ["0", "-1", "2147483647", "-2147483648", "9223372036854775807", "4294967295"]
        if param_type == "id":
            return ["0", "-1", "999999", "00000000-0000-4000-8000-000000000000"]
        if param_type == "json":
            return ['{"$ne": null}', "[]", "{}", '{"a":' * 100 + "1" + "}" * 100]
        return ["A" * 10000, "", " ", "null", "undefined"]

    def dictionary_attack(self) -> list[str]:
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

    def grammar_mutate(self, base_grammar: dict[str, list[str]]) -> dict[str, list[str]]:
        mutated = {}
        for key, values in base_grammar.items():
            new_vals = list(values)
            if isinstance(values, list) and len(values) > 0:
                choice = secrets.choice(values)
                new_vals.append(self.bit_flip(choice))
                dict_attack = self.dictionary_attack()
                if dict_attack:
                    new_vals.append(secrets.choice(dict_attack))
            mutated[key] = new_vals
        return mutated

    def record_feedback(self, endpoint: str, status_code: int, response_len: int) -> bool:
        len_band = response_len // 100
        signature = f"{status_code}:{len_band}"
        self._coverage_feedback.setdefault(endpoint, set())
        history = self._coverage_feedback[endpoint]
        if signature not in history:
            history.add(signature)
            logger.info("Fuzzer: Discovered new coverage feedback path on %s: %s", endpoint, signature)
            return True
        return False

    def generate_campaign_payloads(
        self,
        endpoint: str,
        param_name: str,
        base_value: str,
        param_type: str,
        *,
        max_payloads: int = 15,
    ) -> list[dict[str, Any]]:
        payloads: list[dict[str, Any]] = []
        if param_type == "json":
            try:
                if not hasattr(self, "_ast_mutator"):
                    from src.fuzzing.ast_mutator import JSONASTMutator

                    self._ast_mutator = JSONASTMutator()
                for v in self._ast_mutator.mutate(base_value):
                    payloads.append(
                        {
                            "parameter": param_name,
                            "variant": v,
                            "strategy": "ast_grammar_guided",
                            "reason": "fuzz_ast_boundary",
                        }
                    )
            except Exception as e:
                logger.warning("Fuzzer: AST mutation unavailable: %s", e)
        for v in self.boundary_values(param_type):
            payloads.append(
                {
                    "parameter": param_name,
                    "variant": v,
                    "strategy": "boundary_values",
                    "reason": f"fuzz_boundary_{param_type}",
                }
            )
        for v in self.dictionary_attack():
            payloads.append(
                {
                    "parameter": param_name,
                    "variant": v,
                    "strategy": "dictionary_attack",
                    "reason": "fuzz_injection_bypass",
                }
            )
        payloads.append(
            {
                "parameter": param_name,
                "variant": self.bit_flip(base_value),
                "strategy": "bit_flip",
                "reason": "fuzz_bit_mutation",
            }
        )
        seen = set()
        unique_payloads = []
        for p in payloads:
            var = p["variant"]
            if var not in seen:
                seen.add(var)
                unique_payloads.append(p)
                if len(unique_payloads) >= max_payloads:
                    break
        return self._prioritize_payloads(unique_payloads)

    def _handle_stop_condition(
        self,
        finding: dict[str, Any],
        findings: list[dict[str, Any]],
        stop_container: list[bool],
    ) -> None:
        if self.stop_condition and self.stop_condition(finding, findings):
            stop_container[0] = True
            findings.append(
                {
                    "url": finding["url"],
                    "endpoint_key": finding["endpoint_key"],
                    "endpoint_base_key": finding["endpoint_base_key"],
                    "endpoint_type": finding["endpoint_type"],
                    "issues": ["fuzzing_campaign_stopped_by_policy"],
                    "probe_type": "fuzzing_campaign",
                    "severity": "info",
                    "confidence": 1.0,
                    "evidence": {
                        "reason": "Stop condition triggered",
                        "findings_count": len(findings),
                    },
                }
            )

    async def run_fuzzing_campaign(
        self,
        url: str,
        client: httpx.AsyncClient | None = None,
        *,
        max_payloads: int = 15,
        timeout_seconds: float = 5.0,
        session: Session | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        active_session = session if session is not None else getattr(self, "session", None)

        close_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
            close_client = True

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            if close_client:
                await client.aclose()
            return findings

        if not is_safe_url_with_dns_check(url):
            logger.warning("Fuzzer: URL %s is not safe, skipping fuzzing campaign", url)
            if close_client:
                await client.aclose()
            return findings

        error_re = re.compile(
            r"(?i)(?:sql\s*syntax|mysql_fetch|pg_query|ociexecute|ora-|traceback|stack\s*trace|"
            r"exception|syntax\s*error|unexpected\s+token|unterminated|string\s+literal|"
            r"unclosed\s+quotation|invalid\s*column|invalid\s*object|invalid\s*table|"
            r"division\s+by\s+zero|out\s+of\s+range|constraint\s+violation|duplicate\s*key)"
        )

        endpoint_key = endpoint_signature(url)

        try:
            try:
                if active_session is not None:
                    base_req = active_session.attach(
                        {"method": "GET", "url": url, "timeout_seconds": int(timeout_seconds)}
                    )
                    base_resp = await client.get(
                        base_req.get("url", url),
                        headers=base_req.get("headers", {}),
                        timeout=timeout_seconds,
                    )
                else:
                    base_resp = await self.request_sender.get_url(client, url, timeout_seconds)
                self.feedback_tracker.record_request()
                base_status = base_resp.status_code
                base_len = len(base_resp.text)
            except Exception as e:
                logger.warning("Fuzzer base request failed for %s: %s", url, e)
                if close_client:
                    await client.aclose()
                return findings

            self.record_feedback(url, base_status, base_len)

            stop_container = [False]
            tasks_to_run = []
            for idx, (param_name, param_value) in enumerate(query_pairs):
                param_type = detect_parameter_type(param_name, param_value)
                payload_suggestions = self.generate_campaign_payloads(
                    endpoint=url,
                    param_name=param_name,
                    base_value=param_value,
                    param_type=param_type,
                    max_payloads=max_payloads,
                )
                for payload_dict in payload_suggestions:
                    tasks_to_run.append((idx, param_name, payload_dict))

            sem = asyncio.Semaphore(10)

            async def evaluate_variant(
                idx: int, param_name: str, payload_dict: dict[str, Any]
            ) -> None:
                if stop_container[0]:
                    return
                variant_val = payload_dict["variant"]
                strategy = payload_dict["strategy"]
                mutated_pairs = list(query_pairs)
                mutated_pairs[idx] = (param_name, variant_val)
                mutated_query = urlencode(mutated_pairs, doseq=True)
                mutated_url = urlunparse(parsed._replace(query=mutated_query))
                if not is_safe_url_with_dns_check(mutated_url):
                    logger.warning(
                        "Fuzzer: Mutated URL failed SSRF check, skipping: %s", mutated_url
                    )
                    return
                async with sem:
                    if stop_container[0]:
                        return
                    try:
                        self.feedback_tracker.record_payload()
                        resp = await self.request_sender.get_url(
                            client, mutated_url, timeout_seconds
                        )
                        self.feedback_tracker.record_request()
                        status = resp.status_code
                        body = resp.text
                        resp_len = len(body)
                    except Exception as e:
                        logger.debug("Fuzzer request failed for %s: %s", mutated_url, e)
                        return
                self.record_feedback(url, status, resp_len)
                error_match = error_re.search(body[:50000])
                if error_match:
                    self.feedback_tracker.record_anomaly()
                    self._record_strategy_outcome(strategy, True)
                    findings.append(
                        {
                            "url": url,
                            "endpoint_key": endpoint_key,
                            "endpoint_base_key": endpoint_base_key(url),
                            "endpoint_type": classify_endpoint(url),
                            "issues": ["fuzzing_error_leak_detected"],
                            "probe_type": "fuzzing_campaign",
                            "severity": "high",
                            "confidence": 0.90,
                            "evidence": {
                                "parameter": param_name,
                                "payload": variant_val,
                                "strategy": strategy,
                                "status_code": status,
                                "error_pattern": error_match.group(0),
                                "reason": f"Database or stack trace leak: '{error_match.group(0)}'",
                            },
                        }
                    )
                    logger.info("Fuzzer: Detected vulnerability on %s: Error Leak!", url)
                    self._handle_stop_condition(findings[-1], findings, stop_container)
                    stop_container[0] = True
                    return
                elif base_status in {400, 401, 403} and status in {200, 201}:
                    self.feedback_tracker.record_anomaly()
                    findings.append(
                        {
                            "url": url,
                            "endpoint_key": endpoint_key,
                            "endpoint_base_key": endpoint_base_key(url),
                            "endpoint_type": classify_endpoint(url),
                            "issues": ["fuzzing_structural_bypass_detected"],
                            "probe_type": "fuzzing_campaign",
                            "severity": "high",
                            "confidence": 0.85,
                            "evidence": {
                                "parameter": param_name,
                                "payload": variant_val,
                                "strategy": strategy,
                                "status_code": status,
                                "base_status_code": base_status,
                                "reason": f"Status code transitioned from {base_status} to {status} during mutation",
                            },
                        }
                    )
                    logger.info("Fuzzer: Detected vulnerability on %s: Structural Bypass!", url)
                    self._handle_stop_condition(findings[-1], findings, stop_container)
                    stop_container[0] = True
                    return
                elif status >= 500 and base_status < 500:
                    self.feedback_tracker.record_anomaly()
                    findings.append(
                        {
                            "url": url,
                            "endpoint_key": endpoint_key,
                            "endpoint_base_key": endpoint_base_key(url),
                            "endpoint_type": classify_endpoint(url),
                            "issues": ["fuzzing_unhandled_server_crash"],
                            "probe_type": "fuzzing_campaign",
                            "severity": "medium",
                            "confidence": 0.80,
                            "evidence": {
                                "parameter": param_name,
                                "payload": variant_val,
                                "strategy": strategy,
                                "status_code": status,
                                "reason": "Mutation triggered unhandled Internal Server Error (HTTP 500)",
                            },
                        }
                    )
                    logger.info("Fuzzer: Detected anomaly on %s: Server crash (500)!", url)
                    self._handle_stop_condition(findings[-1], findings, stop_container)
                    stop_container[0] = True
                    return

            if tasks_to_run:
                await asyncio.gather(*(evaluate_variant(idx, p, pl) for idx, p, pl in tasks_to_run))

        finally:
            if close_client:
                await client.aclose()

        return findings
