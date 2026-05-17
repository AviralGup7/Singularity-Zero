"""
Cyber Security Test Pipeline - Neural-Mesh Consensus (Leader Election)
Implements a lightweight leader election protocol to ensure the mesh always has
exactly one active orchestrator.
"""

from __future__ import annotations

import asyncio
import logging

from src.infrastructure.mesh.gossip import GossipEngine

logger = logging.getLogger(__name__)


class MeshConsensus:
    """
    Handles leader election and role assignment within the mesh.
    Uses node IDs for deterministic tie-breaking.
    """

    def __init__(self, gossip: GossipEngine):
        self.gossip = gossip
        self.leader_id: str | None = None
        self._election_in_progress = False

    async def run_maintenance(self) -> None:
        """Periodic check to ensure a leader exists."""
        while True:
            await asyncio.sleep(10.0)

            # If no leader known or leader is dead
            if not self.leader_id or self.leader_id not in self.gossip.peers:
                if self.leader_id != self.gossip.local_node.id:
                    await self.start_election()

    async def start_election(self) -> None:
        """Initiate leader election using the RAFT-lite approach."""
        if self._election_in_progress:
            return

        self._election_in_progress = True
        logger.info("Initiating mesh leader election...")

        # 1. Identify candidates (all alive nodes)
        nodes = list(self.gossip.peers.values())
        nodes.append(self.gossip.local_node)

        # 2. Highest ID becomes leader (Deterministic Bully Algorithm)
        sorted_nodes = sorted(nodes, key=lambda x: x.id, reverse=True)
        winner = sorted_nodes[0]

        self.leader_id = winner.id
        self._election_in_progress = False

        if self.leader_id == self.gossip.local_node.id:
            logger.info("Local node ELECTED as Mesh Leader (Orchestrator)")
            await self._promote_to_leader()
        else:
            logger.info("Mesh Leader elected: %s", self.leader_id)

    async def _promote_to_leader(self) -> None:
        """Transition local node to orchestrator role."""
        # In a real system, this would trigger the Orchestrator.run() loop
        # for any pending jobs in the Redis queue.
        pass

    def is_leader(self) -> bool:
        return self.leader_id == self.gossip.local_node.id
