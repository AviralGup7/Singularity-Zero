"""Grammar-based parameter fuzzer and mutation campaign orchestrator.

Provides mutation strategies and coverage-guided feedback loops for fuzzing API endpoints.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

logger = logging.getLogger(__name__)


class FuzzingOrchestrator:
    """Orchestrates coverage-guided and grammar-based fuzzing campaigns across target endpoints."""

    def __init__(self, target_endpoints: list[str]) -> None:
        self.target_endpoints = target_endpoints
        self._coverage_feedback: dict[
            str, set[str]
        ] = {}  # endpoint -> unique response signatures seen
        self._mutation_history: dict[str, list[dict[str, Any]]] = {}

    def bit_flip(self, data: str) -> str:
        """Apply bit-flipping mutation strategy to a string payload."""
        if not data:
            return "A"
        byte_arr = bytearray(data.encode("utf-8", errors="ignore"))
        if len(byte_arr) > 0:
            idx = secrets.randbelow(len(byte_arr))
            bit = secrets.randbelow(8)
            byte_arr[idx] ^= 1 << bit
        return byte_arr.decode("utf-8", errors="ignore")

    def boundary_values(self, param_type: str) -> list[str]:
        """Generate high-fidelity boundary values based on parameter type classification."""
        if param_type == "numeric":
            return ["0", "-1", "2147483647", "-2147483648", "9223372036854775807", "4294967295"]
        if param_type == "id":
            return ["0", "-1", "999999", "00000000-0000-4000-8000-000000000000"]
        if param_type == "json":
            return ['{"$ne": null}', "[]", "{}", '{"a":' * 100 + "1" + "}" * 100]
        return ["A" * 10000, "", " ", "null", "undefined"]

    def dictionary_attack(self) -> list[str]:
        """Return classic injection and structural bypass payload templates."""
        return [
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

    def grammar_mutate(self, base_grammar: dict[str, list[str]]) -> dict[str, list[str]]:
        """Apply grammar-based expansion mutations on structural parameter templates."""
        mutated = {}
        for key, values in base_grammar.items():
            new_vals = list(values)
            # Add bit-flipped and dictionary variations to expand grammar coverage
            if values:
                choice = secrets.choice(values)
                new_vals.append(self.bit_flip(choice))
                new_vals.append(secrets.choice(self.dictionary_attack()))
            mutated[key] = new_vals
        return mutated

    def record_feedback(self, endpoint: str, status_code: int, response_len: int) -> bool:
        """Record response feedback to guide future fuzzing paths.

        If a new, distinct signature (status code + response length band) is observed,
        it registers as a 'coverage increase' and returns True to prioritize this path.
        """
        # Group lengths into bands of 100 bytes to smooth out dynamic content variance
        len_band = response_len // 100
        signature = f"{status_code}:{len_band}"

        self._coverage_feedback.setdefault(endpoint, set())
        history = self._coverage_feedback[endpoint]

        if signature not in history:
            history.add(signature)
            logger.info(
                "Fuzzer: Discovered new coverage feedback path on %s: %s", endpoint, signature
            )
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
        """Orchestrate mutation sequences combining multiple fuzzer strategies.

        Args:
            endpoint: Target endpoint path.
            param_name: Parameter being fuzzed.
            base_value: Original starting value.
            param_type: Classified parameter type.
            max_payloads: Maximum count of payloads.

        Returns:
            List of generated fuzzer mutation payload dictionaries.
        """
        payloads: list[dict[str, Any]] = []

        # 1. Grammar-Guided AST Mutations (for JSON)
        if param_type == "json":
            try:
                from src.fuzzing.ast_mutator import JSONASTMutator
                ast_mutator = JSONASTMutator()
                for v in ast_mutator.mutate(base_value):
                    payloads.append(
                        {
                            "parameter": param_name,
                            "variant": v,
                            "strategy": "ast_grammar_guided",
                            "reason": "fuzz_ast_boundary",
                        }
                    )
            except Exception:
                pass

        # 2. Base Boundary values
        for v in self.boundary_values(param_type):
            payloads.append(
                {
                    "parameter": param_name,
                    "variant": v,
                    "strategy": "boundary_values",
                    "reason": f"fuzz_boundary_{param_type}",
                }
            )

        # 3. Dictionary injections
        for v in self.dictionary_attack():
            payloads.append(
                {
                    "parameter": param_name,
                    "variant": v,
                    "strategy": "dictionary_attack",
                    "reason": "fuzz_injection_bypass",
                }
            )

        # 4. Bit flipped variants
        payloads.append(
            {
                "parameter": param_name,
                "variant": self.bit_flip(base_value),
                "strategy": "bit_flip",
                "reason": "fuzz_bit_mutation",
            }
        )

        # Deduplicate and limit payloads
        seen = set()
        unique_payloads = []
        for p in payloads:
            var = p["variant"]
            if var not in seen:
                seen.add(var)
                unique_payloads.append(p)
                if len(unique_payloads) >= max_payloads:
                    break

        return unique_payloads

    async def run_fuzzing_campaign(
        self,
        url: str,
        client: Any | None = None,
        *,
        max_payloads: int = 15,
        timeout_seconds: float = 5.0,
    ) -> list[dict[str, Any]]:
        """Run an active fuzzing campaign on the target URL with mutation feedback loops.

        Mutates query parameters and sends HTTP requests. Evaluates status code
        and response size feedback to find anomalies and coverage increases.
        """
        import re
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        import httpx

        from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
        from src.core.mutation_engine import detect_parameter_type
        from src.core.utils.url_validation import is_safe_url_with_dns_check

        findings: list[dict[str, Any]] = []
        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            return findings

        # SSRF protection: validate URL before any HTTP request
        if not is_safe_url_with_dns_check(url):
            logger.warning("Fuzzer: URL failed SSRF safety check, skipping: %s", url)
            return findings

        # Compiled error matching regex
        error_re = re.compile(
            r"(?i)(?:sql\s*syntax|mysql_fetch|pg_query|ociexecute|ora-|traceback|stack\s*trace|"
            r"exception|syntax\s*error|unexpected\s+token|unterminated|string\s+literal|"
            r"unclosed\s+quotation|invalid\s+column|invalid\s+object|invalid\s+table|"
            r"division\s+by\s+zero|out\s+of\s+range|constraint\s+violation|duplicate\s+key)"
        )

        close_client = False
        if client is None:
            # Security Fix: Re-enabled SSL verification (verify=True)
            client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
            close_client = True

        endpoint_key = endpoint_signature(url)

        try:
            # 1. Capture base line response
            try:
                base_resp = await client.get(url)
                base_status = base_resp.status_code
                base_len = len(base_resp.text)
            except Exception as e:
                logger.warning("Fuzzer base request failed for %s: %s", url, e)
                return findings

            # Establish base coverage
            self.record_feedback(url, base_status, base_len)

            # 2. Iterate and mutate each parameter
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
                    variant_val = payload_dict["variant"]
                    strategy = payload_dict["strategy"]

                    # Construct mutated query string
                    mutated_pairs = list(query_pairs)
                    mutated_pairs[idx] = (param_name, variant_val)
                    mutated_query = urlencode(mutated_pairs, doseq=True)
                    mutated_url = urlunparse(parsed._replace(query=mutated_query))

                    if not is_safe_url_with_dns_check(mutated_url):
                        logger.warning("Fuzzer: Mutated URL failed SSRF check, skipping: %s", mutated_url)
                        continue

                    try:
                        resp = await client.get(mutated_url)
                        status = resp.status_code
                        body = resp.text
                        resp_len = len(body)
                    except Exception as e:
                        logger.debug("Fuzzer request failed for %s: %s", mutated_url, e)
                        continue

                    # Record status code + size band feedback
                    self.record_feedback(url, status, resp_len)

                    # Look for security issues/anomalies:
                    # Case A: SQL/Execution Error leak in body
                    error_match = error_re.search(body[:8000])
                    if error_match:
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
                        break  # Stop fuzzing this parameter if critical leak found

                    # Case B: Significant status boundary drift (e.g. bypass validation)
                    # For example, base was 403/401/400 but mutation returned 200/201 (auth bypass or boundary acceptance)
                    elif base_status in {400, 401, 403} and status in {200, 201}:
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
                        break

                    # Case C: Status code 500 crash anomaly
                    elif status >= 500 and base_status < 500:
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
                        break

        finally:
            if close_client:
                await client.aclose()

        return findings
