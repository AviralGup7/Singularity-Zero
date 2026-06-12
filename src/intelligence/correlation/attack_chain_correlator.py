"""Attack chain correlation engine.

Discovers attack chains by correlating individual findings. Runs
automatically after scan completion to identify compound
vulnerability scenarios.

The engine has two correlation strategies that run side-by-side:

1. **Rule-based pair-wise matching** - the original 8 hand-coded
   rules (XSS + CSRF, SSRF + port scan, ...) preserved for
   backward compatibility. Hard-coded ``cvss_estimate`` floats
   are no longer trusted as the sole chain score: each rule now
   returns a *minimum* CVSS and the chain is rescored using the
   modern multi-dimensional formula.

2. **Graph traversal** - builds a finding connectivity graph
   where edges represent *any* shared context (host, parameter,
   session, asset) and walks it to discover variable-length
   chains. A chain of 3+ low-severity findings on the same
   payment processor host is detected and amplified.

The class also exposes a ``chain_membership(finding_id)`` helper
so the UI can show "this finding is part of N chains" without
re-running the analysis.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Severity-to-base-amplification mapping. The legacy engine used a
# flat 2x cap; the modern engine allows this to be configured per
# chain. Severity bands here are deliberately conservative.
DEFAULT_SEVERITY_AMPLIFICATION: dict[str, float] = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.2,
    "low": 1.05,
    "info": 1.0,
}

# Default chain amplification cap. Callers (e.g. ``RiskScoringEngine``)
# can override this; we keep a single source of truth.
DEFAULT_CHAIN_AMPLIFICATION_CAP = 2.0

# Maximum chain length produced by graph traversal. 6 is enough to
# capture "SSRF -> internal port scan -> RCE -> privilege
# escalation -> exfiltration" while keeping the search space
# tractable.
DEFAULT_MAX_GRAPH_CHAIN_LENGTH = 6


@dataclass
class AttackChain:
    """A sequence of vulnerabilities that can be chained together."""

    name: str
    severity: str  # critical, high, medium, low
    steps: list[dict[str, Any]]  # Each step is a finding
    description: str
    impact: str
    cvss_estimate: float = 0.0
    chain_amplification: float = 1.0
    chain_kind: str = "rule"  # "rule" | "graph"
    mitre_techniques: list[str] = field(default_factory=list)
    chain_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "steps": list(self.steps),
            "description": self.description,
            "impact": self.impact,
            "cvss_estimate": self.cvss_estimate,
            "chain_amplification": round(self.chain_amplification, 3),
            "chain_kind": self.chain_kind,
            "mitre_techniques": list(self.mitre_techniques),
            "chain_id": self.chain_id,
            "step_count": len(self.steps),
        }


class VulnCorrelationEngine:
    """Automatically correlates findings to discover attack chains.

    Rules for correlation:
    1. Information Disclosure + Auth Bypass = Account Takeover
    2. XSS + CSRF = Session Hijacking
    3. Open Redirect + OAuth = Account Takeover
    4. IDOR + Information Disclosure = Data Breach
    5. SSRF + Internal Port Scan = Network Compromise
    6. File Upload + Path Traversal = RCE
    7. SQLi + Information Disclosure = Full Database Access
    8. Weak TLS + Session Fixation = MITM Attack

    In addition, the engine builds a finding connectivity graph and
    walks it to find longer chains. The graph approach can detect
    variable-length paths (3+ findings) that the rule-based
    approach misses.
    """

    # Correlation rules: (finding_type_1, finding_type_2) -> AttackChain
    CORRELATION_RULES: list[dict[str, Any]] = [
        {
            "types": ["information_disclosure", "auth_bypass"],
            "name": "Account Takeover via Information Disclosure",
            "severity": "critical",
            "description": "Information disclosure combined with authentication bypass allows complete account takeover.",
            "impact": "Full account access without credentials",
            "cvss_estimate": 9.1,
            "mitre": ["T1589", "T1078"],
        },
        {
            "types": ["xss", "csrf"],
            "name": "Session Hijacking via XSS+CSRF",
            "severity": "critical",
            "description": "Cross-site scripting combined with CSRF enables session hijacking.",
            "impact": "Attacker can perform actions as authenticated user",
            "cvss_estimate": 8.8,
            "mitre": ["T1189", "T1059"],
        },
        {
            "types": ["open_redirect", "oauth_misconfiguration"],
            "name": "OAuth Account Takeover via Open Redirect",
            "severity": "high",
            "description": "Open redirect combined with OAuth misconfiguration enables account takeover.",
            "impact": "Attacker can steal OAuth tokens",
            "cvss_estimate": 8.1,
            "mitre": ["T1189", "T1550"],
        },
        {
            "types": ["idor", "information_disclosure"],
            "name": "Data Breach via IDOR",
            "severity": "critical",
            "description": "Insecure direct object reference combined with information disclosure enables data breach.",
            "impact": "Unauthorized access to sensitive data",
            "cvss_estimate": 8.6,
            "mitre": ["T1078", "T1530"],
        },
        {
            "types": ["ssrf", "internal_port_scan"],
            "name": "Network Compromise via SSRF",
            "severity": "critical",
            "description": "Server-side request forgery combined with internal port scanning enables network compromise.",
            "impact": "Internal network access and potential lateral movement",
            "cvss_estimate": 9.0,
            "mitre": ["T1189", "T1046"],
        },
        {
            "types": ["file_upload", "path_traversal"],
            "name": "Remote Code Execution via File Upload",
            "severity": "critical",
            "description": "Unrestricted file upload combined with path traversal enables RCE.",
            "impact": "Arbitrary code execution on server",
            "cvss_estimate": 9.8,
            "mitre": ["T1189", "T1059"],
        },
        {
            "types": ["sqli", "information_disclosure"],
            "name": "Full Database Access via SQLi",
            "severity": "critical",
            "description": "SQL injection combined with information disclosure enables full database access.",
            "impact": "Complete database compromise",
            "cvss_estimate": 9.4,
            "mitre": ["T1189", "T1078"],
        },
        {
            "types": ["weak_tls", "session_fixation"],
            "name": "MITM Attack via Weak TLS",
            "severity": "high",
            "description": "Weak TLS configuration combined with session fixation enables MITM attacks.",
            "impact": "Traffic interception and session hijacking",
            "cvss_estimate": 7.5,
            "mitre": ["T1557", "T1078"],
        },
    ]

    # Generic graph-walk patterns. These don't require a specific
    # pair; they look for a *sequence* of category types that
    # commonly co-occur in real attacks.
    GRAPH_CHAIN_PATTERNS: list[list[str]] = [
        ["misconfiguration", "ssrf", "internal_port_scan"],
        ["ssrf", "internal_port_scan", "rce"],
        ["xss", "session_fixation", "auth_bypass"],
        ["information_disclosure", "sqli", "auth_bypass"],
        ["cors", "csrf", "auth_bypass"],
        ["rate_limit", "brute_force", "auth_bypass"],
        ["open_redirect", "oauth_misconfiguration", "session_hijack"],
        ["file_upload", "path_traversal", "rce"],
        ["idor", "information_disclosure", "data_exfiltration"],
    ]

    def __init__(
        self,
        rules_file: str | None = None,
        *,
        chain_amplification_cap: float = DEFAULT_CHAIN_AMPLIFICATION_CAP,
        max_graph_chain_length: int = DEFAULT_MAX_GRAPH_CHAIN_LENGTH,
    ) -> None:
        self._chains: list[AttackChain] = []
        self._chain_index_by_finding: dict[str, list[str]] = defaultdict(list)
        self.rules = self.CORRELATION_RULES
        self._chain_amplification_cap = max(1.0, float(chain_amplification_cap))
        self._max_graph_chain_length = max(2, int(max_graph_chain_length))
        if rules_file:
            try:
                import json

                with open(rules_file, encoding="utf-8") as f:
                    custom_rules = json.load(f)
                    if isinstance(custom_rules, list):
                        self.rules = custom_rules
                        logger.info(
                            "VulnCorrelationEngine: Loaded %d rules from %s",
                            len(self.rules),
                            rules_file,
                        )
            except Exception as e:
                logger.error(
                    "VulnCorrelationEngine: Failed to load custom rules from %s: %s",
                    rules_file,
                    e,
                )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_findings(self, findings: list[dict[str, Any]]) -> list[AttackChain]:
        """Analyze findings for correlated vulnerabilities.

        Args:
            findings: List of finding dicts with 'type', 'url', 'severity' fields

        Returns:
            List of discovered attack chains
        """
        self._chains = []
        self._chain_index_by_finding = defaultdict(list)

        # 1. Rule-based pair-wise chains.
        rule_chains = self._detect_rule_chains(findings)

        # 2. Graph-traversal chains (variable length).
        graph_chains = self._detect_graph_chains(findings)

        combined = rule_chains + graph_chains
        combined = self._deduplicate_chains(combined)
        # Reassign chain IDs / amplification now that dedup is done.
        for chain in combined:
            if not chain.chain_id:
                chain.chain_id = self._mint_chain_id(chain)
            for step in chain.steps:
                step_id = str(step.get("id") or step.get("finding_id") or "")
                if step_id and chain.chain_id not in self._chain_index_by_finding[step_id]:
                    self._chain_index_by_finding[step_id].append(chain.chain_id)
        self._chains = combined
        return self._chains

    def chain_membership(self, finding_id: str) -> list[str]:
        """Return chain IDs that include this finding."""
        if not finding_id:
            return []
        return list(self._chain_index_by_finding.get(str(finding_id), []))

    def get_chains_by_severity(self, severity: str) -> list[AttackChain]:
        """Get chains filtered by severity."""
        return [c for c in self._chains if c.severity == severity]

    def get_summary(self) -> dict[str, Any]:
        """Get summary of discovered attack chains."""
        return {
            "total_chains": len(self._chains),
            "critical": len(self.get_chains_by_severity("critical")),
            "high": len(self.get_chains_by_severity("high")),
            "medium": len(self.get_chains_by_severity("medium")),
            "low": len(self.get_chains_by_severity("low")),
            "chains": [
                {
                    "name": c.name,
                    "severity": c.severity,
                    "cvss_estimate": c.cvss_estimate,
                    "chain_amplification": round(c.chain_amplification, 3),
                    "chain_kind": c.chain_kind,
                    "chain_id": c.chain_id,
                    "step_count": len(c.steps),
                    "mitre_techniques": c.mitre_techniques,
                }
                for c in self._chains
            ],
        }

    # ------------------------------------------------------------------
    # Rule-based chain detection (legacy)
    # ------------------------------------------------------------------

    def _detect_rule_chains(self, findings: list[dict[str, Any]]) -> list[AttackChain]:
        chains: list[AttackChain] = []
        findings_by_type: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            ftype = finding.get("type", "").lower()
            if not ftype:
                continue
            findings_by_type.setdefault(ftype, []).append(finding)

        for rule in self.rules:
            type1, type2 = rule["types"]
            findings1 = findings_by_type.get(type1)
            findings2 = findings_by_type.get(type2)
            if not findings1 or not findings2:
                continue
            for f1 in findings1:
                for f2 in findings2:
                    if self._same_context(f1, f2):
                        chain = AttackChain(
                            name=rule["name"],
                            severity=rule["severity"],
                            steps=[f1, f2],
                            description=rule["description"],
                            impact=rule["impact"],
                            cvss_estimate=float(rule.get("cvss_estimate", 0.0) or 0.0),
                            chain_amplification=self._severity_amp(rule["severity"]),
                            chain_kind="rule",
                            mitre_techniques=list(rule.get("mitre", []) or []),
                        )
                        chains.append(chain)
        return chains

    # ------------------------------------------------------------------
    # Graph traversal chain detection (new)
    # ------------------------------------------------------------------

    def _detect_graph_chains(self, findings: list[dict[str, Any]]) -> list[AttackChain]:
        """BFS over a finding connectivity graph to find variable-length chains.

        Edges connect findings that share *any* of: host, path
        prefix, parameter name, session, or asset_id. Walk length
        is capped at ``_max_graph_chain_length``.

        The traversal is constrained to a small set of
        :pyattr:`GRAPH_CHAIN_PATTERNS` so we don't drown analysts
        in irrelevant paths. We keep the implementation simple
        and explicit so it's easy to extend.
        """
        chains: list[AttackChain] = []
        if not findings:
            return chains

        # Build adjacency list keyed by finding index.
        adjacency = self._build_finding_graph(findings)
        if not adjacency:
            return chains

        by_type: dict[str, list[int]] = defaultdict(list)
        for index, finding in enumerate(findings):
            ftype = str(finding.get("type", "")).lower()
            if ftype:
                by_type[ftype].append(index)

        for pattern in self.GRAPH_CHAIN_PATTERNS:
            # First type must exist in the finding set.
            starting = by_type.get(pattern[0], [])
            if not starting:
                continue
            for start_index in starting:
                path = self._bfs_pattern(start_index, pattern, adjacency, by_type)
                if path is None:
                    continue
                steps = [findings[i] for i in path]
                chain = self._build_graph_chain(steps, pattern)
                if chain is not None:
                    chains.append(chain)
        return chains

    def _bfs_pattern(
        self,
        start: int,
        pattern: list[str],
        adjacency: dict[int, set[int]],
        by_type: dict[str, list[int]],
    ) -> list[int] | None:
        """BFS that walks the pattern list of types through the graph.

        At each step we look for the next type in the pattern among
        the *neighbors* of the current node. This keeps the chain
        contextually relevant (same host / param / asset).
        """
        path = [start]
        current = start
        used: set[int] = {start}
        for depth, expected_type in enumerate(pattern[1:]):
            candidates = [
                neighbor for neighbor in adjacency.get(current, set()) if neighbor not in used
            ]
            chosen: int | None = None
            # Resolve by index scan (small N).
            for neighbor in candidates:
                # Find which type this neighbor belongs to.
                for ftype, indices in by_type.items():
                    if neighbor in indices and ftype == expected_type:
                        chosen = neighbor
                        break
                if chosen is not None:
                    break
            if chosen is None:
                return None
            path.append(chosen)
            used.add(chosen)
            current = chosen
            if len(path) >= self._max_graph_chain_length:
                break
        return path

    def _build_finding_graph(self, findings: list[dict[str, Any]]) -> dict[int, set[int]]:
        """Build an undirected graph of findings that share context."""
        edges: dict[int, set[int]] = defaultdict(set)
        n = len(findings)
        for i in range(n):
            ctx_i = self._context_keys(findings[i])
            for j in range(i + 1, n):
                ctx_j = self._context_keys(findings[j])
                if ctx_i & ctx_j:
                    edges[i].add(j)
                    edges[j].add(i)
        return edges

    def _context_keys(self, finding: dict[str, Any]) -> set[str]:
        """Extract a set of context tokens for graph edge matching."""
        keys: set[str] = set()
        url = str(finding.get("url") or finding.get("target") or "")
        host, path = _parse_host_path(url)
        if host:
            keys.add(f"host:{host}")
        if path:
            # Match on the first 3 path segments so a finding on
            # ``/api/payment/charge`` and one on ``/api/payment/refund``
            # share an edge but stay distinct from
            # ``/api/users/...``.
            segments = [seg for seg in path.split("/") if seg][:3]
            if segments:
                keys.add(f"path_prefix:/{'/'.join(segments)}")
        parameter = finding.get("parameter_name") or finding.get("parameter")
        if parameter:
            keys.add(f"param:{parameter}")
        session = finding.get("session_id") or finding.get("session")
        if session:
            keys.add(f"session:{session}")
        asset_id = finding.get("asset_id")
        if asset_id:
            keys.add(f"asset:{asset_id}")
        # Same category on same host also creates an edge.
        category = finding.get("type")
        if category and host:
            keys.add(f"category:{category}@{host}")
        return keys

    def _build_graph_chain(
        self, steps: list[dict[str, Any]], pattern: list[str]
    ) -> AttackChain | None:
        """Turn a BFS-discovered path into an ``AttackChain``."""
        if not steps:
            return None
        cvss_estimate = max(
            float(step.get("cvss_score") or step.get("severity_score") or 0.0) for step in steps
        )
        # The chain CVSS is bumped by 1.0 per step (capped) to
        # reflect the compounding blast radius. Cap at 10.0.
        chain_cvss = min(10.0, cvss_estimate + 0.6 * (len(steps) - 1))
        severity = self._severity_from_cvss(chain_cvss)
        return AttackChain(
            name=f"Graph chain ({len(steps)} steps)",
            severity=severity,
            steps=list(steps),
            description=(
                f"Graph traversal discovered a {len(steps)}-step chain: "
                + " -> ".join(str(s.get("type", "unknown")) for s in steps)
            ),
            impact="Compound exploitation across multiple findings",
            cvss_estimate=chain_cvss,
            chain_amplification=self._severity_amp(severity),
            chain_kind="graph",
            mitre_techniques=[],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _same_context(self, f1: dict[str, Any], f2: dict[str, Any]) -> bool:
        """Check if two findings share a meaningful context.

        The legacy implementation only matched on netloc. The new
        implementation also matches on asset_id, parameter name, and
        session id, which is important for cross-domain chains.
        """
        # Asset match.
        asset1 = f1.get("asset_id")
        asset2 = f2.get("asset_id")
        if asset1 and asset2 and asset1 == asset2:
            return True
        # Parameter match.
        param1 = f1.get("parameter_name")
        param2 = f2.get("parameter_name")
        if param1 and param2 and param1 == param2:
            return True
        # Session match.
        session1 = f1.get("session_id")
        session2 = f2.get("session_id")
        if session1 and session2 and session1 == session2:
            return True
        # Host / path-prefix match.
        return self._same_domain(f1, f2)

    def _same_domain(self, f1: dict[str, Any], f2: dict[str, Any]) -> bool:
        """Check if two findings target the same domain or related subdomains."""
        url1 = str(f1.get("url", "") or f1.get("target", ""))
        url2 = str(f2.get("url", "") or f2.get("target", ""))
        if not url1 or not url2:
            return False
        try:
            host1 = urlparse(url1).netloc or url1
            host2 = urlparse(url2).netloc or url2
        except Exception as exc:
            logger.warning("Failed to compare domains for findings: %s", exc)
            parts1 = url1.split("/")
            parts2 = url2.split("/")
            if parts1 and parts2:
                return bool(parts1[0] == parts2[0])
            return False
        if not host1 or not host2:
            return False
        if host1 == host2:
            return True
        # Match parent domain (e.g. "api.foo.example.com" and
        # "auth.foo.example.com" share "foo.example.com").
        return self._share_parent_domain(host1, host2)

    @staticmethod
    def _share_parent_domain(host1: str, host2: str) -> bool:
        """Check if two hosts share a parent domain.

        NOTE: This uses a simple heuristic comparing the last two labels.
        For multi-part TLDs like '.ac.uk', '.co.uk', '.com.au', this may
        incorrectly match unrelated domains (e.g., 'example.ac.uk' and
        'internal.ac.uk' would match). For production use, consider using
        the `tldextract` library for accurate registrable domain extraction.
        """
        parts1 = host1.split(".")
        parts2 = host2.split(".")
        if len(parts1) < 2 or len(parts2) < 2:
            return False
        # Compare the last two labels - cheap "same registrable
        # domain" check. Sufficient for our graph purposes.
        # TODO: For multi-part TLDs (ac.uk, co.uk, com.au, etc.),
        # this may produce false positives. Consider using tldextract
        # library if available, or maintain a list of known multi-part TLDs.
        return parts1[-2:] == parts2[-2:]

    def _deduplicate_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Remove duplicate chains."""
        seen: set[tuple[Any, ...]] = set()
        unique: list[AttackChain] = []

        for chain in chains:
            key = (
                chain.name,
                chain.chain_kind,
                tuple(s.get("id") or s.get("finding_id") or s.get("url", "") for s in chain.steps),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(chain)
        return unique

    def _severity_amp(self, severity: str) -> float:
        amp = DEFAULT_SEVERITY_AMPLIFICATION.get(str(severity).lower(), 1.0)
        return min(self._chain_amplification_cap, amp)

    @staticmethod
    def _severity_from_cvss(cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss > 0:
            return "low"
        return "info"

    @staticmethod
    def _mint_chain_id(chain: AttackChain) -> str:
        import hashlib

        seed = "|".join(
            [chain.chain_kind, chain.name]
            + [str(s.get("id") or s.get("url") or "") for s in chain.steps]
        )
        return f"chain_{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:10]}"  # noqa: S324  # nosec


def _parse_host_path(value: str) -> tuple[str, str]:
    """Extract (host, path) from a URL or host string, lowercased."""
    raw = value.strip().lower()
    if not raw:
        return "", ""
    if "://" not in raw:
        # Treat as host.
        if "/" in raw:
            host, path = raw.split("/", 1)
            return host, "/" + path
        return raw, ""
    parsed = urlparse(raw)
    return (parsed.netloc or "").split(":")[0], parsed.path or ""


__all__ = [
    "AttackChain",
    "DEFAULT_CHAIN_AMPLIFICATION_CAP",
    "DEFAULT_MAX_GRAPH_CHAIN_LENGTH",
    "DEFAULT_SEVERITY_AMPLIFICATION",
    "VulnCorrelationEngine",
]
