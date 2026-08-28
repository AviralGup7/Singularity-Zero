"""Raft RPC Messages, Transport Protocol, and Multi-Node Cluster Coordination (Level 0 Transport).

Implements the formal Raft replication and consensus boundary:
- Strongly-typed AppendEntries and RequestVote RPC request/response envelopes
- Quorum calculation (N // 2 + 1) and term-based stepdown semantics
- Transport abstraction supporting both in-process and network RPC routers
- Cluster configuration management and dynamic peer membership
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Protocol, cast

from src.core.contracts.command_envelope import CommittedEntry

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AppendEntriesRequest:
    """Raft AppendEntries RPC request envelope."""

    term: int
    leader_id: str
    prev_log_index: int
    prev_log_term: int
    entries: tuple[CommittedEntry, ...]
    leader_commit: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "leader_id": self.leader_id,
            "prev_log_index": self.prev_log_index,
            "prev_log_term": self.prev_log_term,
            "entries": [e.to_dict() for e in self.entries],
            "leader_commit": self.leader_commit,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppendEntriesRequest:
        entries = tuple(CommittedEntry.from_dict(e) for e in data.get("entries", []))
        return cls(
            term=int(data.get("term", 1)),
            leader_id=str(data.get("leader_id", "")),
            prev_log_index=int(data.get("prev_log_index", 0)),
            prev_log_term=int(data.get("prev_log_term", 0)),
            entries=entries,
            leader_commit=int(data.get("leader_commit", 0)),
        )


@dataclass(frozen=True, slots=True)
class AppendEntriesResponse:
    """Raft AppendEntries RPC response envelope."""

    term: int
    node_id: str
    success: bool
    match_index: int
    error_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "node_id": self.node_id,
            "success": self.success,
            "match_index": self.match_index,
            "error_code": self.error_code,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppendEntriesResponse:
        return cls(
            term=int(data.get("term", 1)),
            node_id=str(data.get("node_id", "")),
            success=bool(data.get("success", False)),
            match_index=int(data.get("match_index", 0)),
            error_code=str(data.get("error_code", "")),
        )


@dataclass(frozen=True, slots=True)
class RequestVoteRequest:
    """Raft RequestVote RPC request envelope."""

    term: int
    candidate_id: str
    last_log_index: int
    last_log_term: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "candidate_id": self.candidate_id,
            "last_log_index": self.last_log_index,
            "last_log_term": self.last_log_term,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestVoteRequest:
        return cls(
            term=int(data.get("term", 1)),
            candidate_id=str(data.get("candidate_id", "")),
            last_log_index=int(data.get("last_log_index", 0)),
            last_log_term=int(data.get("last_log_term", 0)),
        )


@dataclass(frozen=True, slots=True)
class RequestVoteResponse:
    """Raft RequestVote RPC response envelope."""

    term: int
    node_id: str
    vote_granted: bool
    error_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "node_id": self.node_id,
            "vote_granted": self.vote_granted,
            "error_code": self.error_code,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestVoteResponse:
        return cls(
            term=int(data.get("term", 1)),
            node_id=str(data.get("node_id", "")),
            vote_granted=bool(data.get("vote_granted", False)),
            error_code=str(data.get("error_code", "")),
        )


@dataclass(frozen=True, slots=True)
class PreVoteRequest:
    """Raft PreVote RPC request envelope (prevents disruptive partitioned election storms)."""

    next_term: int
    candidate_id: str
    last_log_index: int
    last_log_term: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "next_term": self.next_term,
            "candidate_id": self.candidate_id,
            "last_log_index": self.last_log_index,
            "last_log_term": self.last_log_term,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PreVoteRequest:
        return cls(
            next_term=int(data.get("next_term", 1)),
            candidate_id=str(data.get("candidate_id", "")),
            last_log_index=int(data.get("last_log_index", 0)),
            last_log_term=int(data.get("last_log_term", 0)),
        )


@dataclass(frozen=True, slots=True)
class PreVoteResponse:
    """Raft PreVote RPC response envelope."""

    term: int
    node_id: str
    pre_vote_granted: bool
    error_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "node_id": self.node_id,
            "pre_vote_granted": self.pre_vote_granted,
            "error_code": self.error_code,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PreVoteResponse:
        return cls(
            term=int(data.get("term", 1)),
            node_id=str(data.get("node_id", "")),
            pre_vote_granted=bool(data.get("pre_vote_granted", False)),
            error_code=str(data.get("error_code", "")),
        )


class RaftTransportProtocol(Protocol):
    """Protocol interface for dispatching Raft RPCs across nodes."""

    def send_append_entries(
        self, target_node_id: str, request: AppendEntriesRequest
    ) -> AppendEntriesResponse:
        """Send AppendEntries RPC synchronously or via network timeout."""
        ...

    def send_request_vote(
        self, target_node_id: str, request: RequestVoteRequest
    ) -> RequestVoteResponse:
        """Send RequestVote RPC synchronously or via network timeout."""
        ...

    def send_pre_vote(self, target_node_id: str, request: PreVoteRequest) -> PreVoteResponse:
        """Send PreVote RPC synchronously or via network timeout."""
        ...


class InMemoryRaftTransport:
    """In-memory, thread-safe Raft RPC router connecting peer ReplicatedPartitionLog nodes."""

    def __init__(self) -> None:
        self._endpoints: dict[str, Any] = {}
        self._partition_map: dict[str, set[str]] = {}  # partition_id -> set of node_ids
        self._partitions_isolated: set[str] = set()  # simulated network partitions / dead nodes
        self._lock = threading.RLock()

    def register_node(self, node_id: str, partition_id: str, node_instance: Any) -> None:
        with self._lock:
            self._endpoints[node_id] = node_instance
            self._partition_map.setdefault(partition_id, set()).add(node_id)

    def unregister_node(self, node_id: str) -> None:
        with self._lock:
            self._endpoints.pop(node_id, None)
            for p_set in self._partition_map.values():
                p_set.discard(node_id)

    def isolate_node(self, node_id: str) -> None:
        """Simulate a network partition / node drop."""
        with self._lock:
            self._partitions_isolated.add(node_id)

    def reconnect_node(self, node_id: str) -> None:
        """Restore network connectivity to an isolated node."""
        with self._lock:
            self._partitions_isolated.discard(node_id)

    def send_append_entries(
        self, target_node_id: str, request: AppendEntriesRequest, sender_id: str | None = None
    ) -> AppendEntriesResponse:
        with self._lock:
            src = sender_id or request.leader_id
            if src in self._partitions_isolated or target_node_id in self._partitions_isolated:
                return AppendEntriesResponse(
                    term=request.term,
                    node_id=target_node_id,
                    success=False,
                    match_index=0,
                    error_code="NODE_UNREACHABLE",
                )
            target = self._endpoints.get(target_node_id)
            if target is None:
                return AppendEntriesResponse(
                    term=request.term,
                    node_id=target_node_id,
                    success=False,
                    match_index=0,
                    error_code="NODE_NOT_FOUND",
                )

        # Dispatch RPC to target node instance
        return cast(AppendEntriesResponse, target.handle_append_entries_rpc(request))

    def send_request_vote(
        self, target_node_id: str, request: RequestVoteRequest, sender_id: str | None = None
    ) -> RequestVoteResponse:
        with self._lock:
            src = sender_id or request.candidate_id
            if src in self._partitions_isolated or target_node_id in self._partitions_isolated:
                return RequestVoteResponse(
                    term=request.term,
                    node_id=target_node_id,
                    vote_granted=False,
                    error_code="NODE_UNREACHABLE",
                )
            target = self._endpoints.get(target_node_id)
            if target is None:
                return RequestVoteResponse(
                    term=request.term,
                    node_id=target_node_id,
                    vote_granted=False,
                    error_code="NODE_NOT_FOUND",
                )

        return cast(RequestVoteResponse, target.handle_request_vote_rpc(request))

    def send_pre_vote(
        self, target_node_id: str, request: PreVoteRequest, sender_id: str | None = None
    ) -> PreVoteResponse:
        with self._lock:
            src = sender_id or request.candidate_id
            if src in self._partitions_isolated or target_node_id in self._partitions_isolated:
                return PreVoteResponse(
                    term=request.next_term - 1,
                    node_id=target_node_id,
                    pre_vote_granted=False,
                    error_code="NODE_UNREACHABLE",
                )
            target = self._endpoints.get(target_node_id)
            if target is None:
                return PreVoteResponse(
                    term=request.next_term - 1,
                    node_id=target_node_id,
                    pre_vote_granted=False,
                    error_code="NODE_NOT_FOUND",
                )

        return cast(PreVoteResponse, target.handle_pre_vote_rpc(request))


class NetworkRaftTransport:
    """JSON-over-TCP Raft RPC. Peers are ``node_id -> (host, port)``.

    Single-node CLI scans do not need this; InMemoryRaftTransport is quorum-1.
    This class is the multi-host activation path.
    """

    def __init__(self, timeout_seconds: float = 2.0) -> None:
        self._peers: dict[str, tuple[str, int]] = {}
        self._timeout = timeout_seconds
        self._lock = threading.RLock()

    def register_peer(self, node_id: str, host: str, port: int) -> None:
        with self._lock:
            self._peers[node_id] = (host, int(port))

    def _rpc(self, target_node_id: str, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        import json
        import socket

        with self._lock:
            peer = self._peers.get(target_node_id)
        if peer is None:
            return {
                "success": False,
                "vote_granted": False,
                "error_code": "NODE_NOT_FOUND",
                "term": 0,
                "node_id": target_node_id,
                "match_index": 0,
            }
        host, port = peer
        body = json.dumps({"method": method, "payload": payload}).encode("utf-8")
        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                sock.sendall(len(body).to_bytes(4, "big") + body)
                hdr = sock.recv(4)
                if len(hdr) < 4:
                    raise OSError("short header")
                n = int.from_bytes(hdr, "big")
                data = b""
                while len(data) < n:
                    chunk = sock.recv(n - len(data))
                    if not chunk:
                        break
                    data += chunk
            decoded = json.loads(data.decode("utf-8"))
            return decoded if isinstance(decoded, dict) else {}
        except OSError as exc:
            logger.warning("Raft RPC to %s failed: %s", target_node_id, exc)
            return {
                "success": False,
                "vote_granted": False,
                "error_code": "NODE_UNREACHABLE",
                "term": 0,
                "node_id": target_node_id,
                "match_index": 0,
            }

    def send_append_entries(
        self, target_node_id: str, request: AppendEntriesRequest
    ) -> AppendEntriesResponse:
        raw = self._rpc(target_node_id, "append_entries", request.to_dict())
        return AppendEntriesResponse.from_dict(raw)

    def send_request_vote(
        self, target_node_id: str, request: RequestVoteRequest
    ) -> RequestVoteResponse:
        raw = self._rpc(target_node_id, "request_vote", request.to_dict())
        return RequestVoteResponse.from_dict(raw)
