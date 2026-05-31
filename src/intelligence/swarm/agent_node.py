"""
Agent Node for the Collaborative AI Swarm.
Negotiates and passes state synchronously using the platform's Vector-Clocked CRDTs.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

try:
    from src.core.frontier.state import NeuralState
except ImportError:

    class NeuralState:  # type: ignore[no-redef]
        """Fallback mock for environments without Cython/Frontier."""

        def __init__(self) -> None:
            class MockHLC:
                def __init__(self, node_id: str | None = None) -> None:
                    self.node_id = node_id

            self.hlc = MockHLC()
            self.urls = self
            self.findings = self

        def apply_delta(self, delta: dict[str, Any]) -> None:
            pass

        def to_set(self) -> set[str]:
            return set()

        def values(self) -> list[Any]:
            return []


try:
    from src.core.logging.trace_logging import get_pipeline_logger
except ImportError:
    import logging

    def get_pipeline_logger(name: str) -> Any:  # type: ignore[misc]
        return logging.getLogger(name)


logger = get_pipeline_logger(__name__)


from src.intelligence.swarm.p2p.consensus import BFTMessageValidator, NoiseChannel


class AgentNode:
    """An autonomous LLM-powered agent node representing a specific red-team role."""

    def __init__(self, role: str, node_id: str | None = None) -> None:
        self.role = role
        self.node_id = node_id or f"{role}-{uuid.uuid4().hex[:8]}"
        self.state = NeuralState()
        # Ensure our state HLC and vectors track this node's identity
        self.state.hlc = self.state.hlc.__class__(node_id=self.node_id)

        # BFT & P2P Noise configuration
        # NOTE: This uses a simulated symmetric PKI for simple prototype/simulation.
        # A real production deployment must utilize asymmetric cryptographic signatures
        # (e.g., Ed25519) to securely verify messages in the P2P gossip network.
        self.secret_key = f"secret-{self.node_id}"
        self.public_key = self.secret_key  # Simulated symmetric PKI
        self.noise_channel = NoiseChannel()
        self.bft_peers: dict[str, str] = {}  # node_id -> public_key

    def discover_url(self, url: str) -> None:
        """Simulate the agent finding a new URL and adding it to its local CRDT."""
        self.state.apply_delta({"node_id": self.node_id, "urls": [url], "_ts": time.time()})
        logger.debug("Agent %s (%s) discovered URL: %s", self.node_id, self.role, url)

    def discover_finding(self, finding: dict[str, Any]) -> None:
        """Simulate the agent confirming a vulnerability and adding it to its local CRDT."""
        self.state.apply_delta({"node_id": self.node_id, "findings": [finding], "_ts": time.time()})
        logger.debug(
            "Agent %s (%s) discovered finding: %s", self.node_id, self.role, finding.get("title")
        )

    def register_peer(self, peer_node_id: str, public_key: str) -> None:
        """Register a peer's public key for BFT validation."""
        self.bft_peers[peer_node_id] = public_key

    def _export_bft_payload(self) -> bytes:
        """Export state encrypted and signed for P2P transmission."""
        # Simple extraction for prototype. Real CRDTs serialize their vector clocks.
        state_dict = {"urls": list(self.get_known_urls()), "findings": self.get_known_findings()}
        signature = BFTMessageValidator.sign_state(state_dict, self.secret_key)
        payload = {"sender_id": self.node_id, "state": state_dict, "signature": signature}
        return self.noise_channel.encrypt_payload(payload)

    def _import_bft_payload(self, encrypted_payload: bytes, shared_channel: NoiseChannel) -> None:
        """Import, verify, and merge state from a P2P peer."""
        try:
            payload = shared_channel.decrypt_payload(encrypted_payload)
            sender_id = payload["sender_id"]

            if sender_id not in self.bft_peers:
                logger.warning("Rejecting gossip from unknown peer: %s", sender_id)
                return

            public_key = self.bft_peers[sender_id]
            if not BFTMessageValidator.verify_state(
                payload["state"], payload["signature"], public_key
            ):
                logger.warning("BFT Validation Failed: Byzantine fault detected from %s", sender_id)
                return

            # Convert verified state dictionary back to CRDT deltas
            for url in payload["state"]["urls"]:
                self.state.apply_delta({"node_id": sender_id, "urls": [url], "_ts": time.time()})
            for finding in payload["state"]["findings"]:
                self.state.apply_delta(
                    {"node_id": sender_id, "findings": [finding], "_ts": time.time()}
                )

        except Exception as e:
            logger.error("Failed to process P2P gossip message: %s", e)

    def sync_with(self, other: AgentNode) -> None:
        """Synchronously negotiate and pass state CRDTs between agents using P2P Noise."""
        logger.debug("Syncing state between %s and %s", self.node_id, other.node_id)

        # Exchange keys for BFT
        self.register_peer(other.node_id, other.public_key)
        other.register_peer(self.node_id, self.public_key)

        # Export and exchange
        my_payload = self._export_bft_payload()
        their_payload = other._export_bft_payload()

        self._import_bft_payload(their_payload, other.noise_channel)
        other._import_bft_payload(my_payload, self.noise_channel)

    def get_known_urls(self) -> set[str]:
        return self.state.urls.to_set()

    def get_known_findings(self) -> list[dict[str, Any]]:
        return self.state.findings.values()


class SwarmOrchestrator:
    """Orchestrates the collaborative AI swarm."""

    def __init__(self) -> None:
        self.agents: list[AgentNode] = []

    def register_agent(self, agent: AgentNode) -> None:
        self.agents.append(agent)

    def global_sync(self) -> None:
        """Perform a full gossip sync across the entire swarm."""
        # Simple full mesh sync
        for i in range(len(self.agents)):
            for j in range(i + 1, len(self.agents)):
                self.agents[i].sync_with(self.agents[j])
