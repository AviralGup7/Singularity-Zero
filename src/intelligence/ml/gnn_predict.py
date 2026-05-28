"""Graph Neural Network (GNN) and Reinforcement Learning (RL) prediction engine.

Provides zero-dependency, pure-NumPy Graph Convolutional Network (GCN) layers for link
prediction, and a Q-learning RL agent for optimal security probe selection.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class GNNPredictor:
    """Pure-NumPy 2-layer Graph Convolutional Network (GCN) for predicting unseen attack paths."""

    def __init__(self, hidden_dim: int = 8, seed: int = 42) -> None:
        self.hidden_dim = hidden_dim
        # Seed for deterministic and reproducible weight initialization
        rng = np.random.default_rng(seed)
        
        # W0: size 4 (input features) -> hidden_dim
        self.W0 = rng.normal(0, 0.1, (4, hidden_dim))
        # W1: size hidden_dim -> hidden_dim (embeddings)
        self.W1 = rng.normal(0, 0.1, (hidden_dim, hidden_dim))

    def _normalize_adjacency(self, A: np.ndarray) -> np.ndarray:
        """Compute the symmetric normalized adjacency matrix: D^-1/2 * (A + I) * D^-1/2."""
        N = A.shape[0]
        # Add self-loops
        A_loop = A + np.eye(N)
        
        # Calculate degrees
        degrees = np.sum(A_loop, axis=1)
        
        # D^-1/2
        with np.errstate(divide="ignore", invalid="ignore"):
            deg_inv_sqrt = 1.0 / np.sqrt(degrees)
            deg_inv_sqrt[np.isinf(deg_inv_sqrt) | np.isnan(deg_inv_sqrt)] = 0.0
            
        D_inv_sqrt = np.diag(deg_inv_sqrt)
        
        # D^-1/2 * A_loop * D^-1/2
        return D_inv_sqrt @ A_loop @ D_inv_sqrt

    def predict_links(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        threshold: float = 0.65,
    ) -> list[dict[str, Any]]:
        """Run 2-layer GCN to generate node embeddings and predict unseen pivot links."""
        if not nodes:
            return []

        N = len(nodes)
        node_ids = [n["id"] for n in nodes]
        node_to_idx = {nid: idx for idx, nid in enumerate(node_ids)}

        # 1. Build Adjacency Matrix
        A = np.zeros((N, N))
        for edge in edges:
            src = edge.get("source")
            dst = edge.get("target")
            if src in node_to_idx and dst in node_to_idx:
                A[node_to_idx[src], node_to_idx[dst]] = 1.0
                # Make it undirected for robust undirected information flow
                A[node_to_idx[dst], node_to_idx[src]] = 1.0

        # 2. Build Feature Matrix X (N x 4)
        # Features: [is_subdomain, is_endpoint, is_finding, severity_weight]
        X = np.zeros((N, 4))
        severity_weight_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}

        for idx, node in enumerate(nodes):
            ntype = node.get("type", "")
            severity = str(node.get("severity", "info")).lower()
            weight = severity_weight_map.get(severity, 0.1)

            if ntype == "subdomain":
                X[idx] = [1.0, 0.0, 0.0, 0.1]
            elif ntype == "endpoint":
                X[idx] = [0.0, 1.0, 0.0, 0.2]
            elif ntype == "finding":
                X[idx] = [0.0, 0.0, 1.0, weight]
            else:
                X[idx] = [0.0, 0.0, 0.0, 0.1]

        # 3. Compute Symmetric Normalized Adjacency
        A_tilde = self._normalize_adjacency(A)

        # 4. GCN Forward Pass
        # Layer 1: H1 = ReLU(A_tilde * X * W0)
        H1 = A_tilde @ X @ self.W0
        H1 = np.maximum(0, H1)  # ReLU

        # Layer 2: Z = A_tilde * H1 * W1
        Z = A_tilde @ H1 @ self.W1

        # 5. Cosine Similarity Link Prediction
        # Compute norms
        norms = np.linalg.norm(Z, axis=1, keepdims=True)
        norms[norms == 0.0] = 1e-9  # Avoid division by zero
        Z_normalized = Z / norms

        predicted_edges: list[dict[str, Any]] = []

        # Find unseen pivot paths (e.g. from finding to subdomain or endpoint)
        for u in range(N):
            for v in range(u + 1, N):
                # Skip if already connected
                if A[u, v] > 0.0:
                    continue

                # Cosine Similarity
                sim = float(np.dot(Z_normalized[u], Z_normalized[v]))

                if sim >= threshold:
                    node_u = nodes[u]
                    node_v = nodes[v]
                    
                    # Semantically, it's interesting to predict pivots from findings to target endpoints
                    u_type = node_u.get("type")
                    v_type = node_v.get("type")
                    if (u_type == "finding" and v_type in {"endpoint", "subdomain"}) or \
                       (v_type == "finding" and u_type in {"endpoint", "subdomain"}):
                        
                        source = node_u["id"]
                        target = node_v["id"]
                        if u_type != "finding":
                            source, target = target, source  # Finding is source

                        predicted_edges.append({
                            "source": source,
                            "target": target,
                            "label": "predicted_pivot",
                            "metadata": {
                                "relationship": "predicted_pivot",
                                "confidence": round(sim, 2),
                                "predicted": True,
                                "method": "GCN-Embeddings"
                            }
                        })

        return predicted_edges


class ProbeSelectionRLAgent:
    """Q-learning reinforcement learning agent for selecting optimal active scanner probes."""

    def __init__(self, alpha: float = 0.1, gamma: float = 0.9, epsilon: float = 0.1) -> None:
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        
        # Q-table: key is state, value is dict of action -> q_value
        self.q_table: dict[str, dict[str, float]] = {}
        self.available_probes = [
            "sqli",
            "csrf",
            "jwt",
            "xss",
            "ssrf",
            "idor",
            "hpp",
            "graphql",
            "auth_bypass",
            "json",
            "fuzzing_campaign"
        ]

    def _get_state(self, url: str) -> str:
        """Derive target state representation from target URL parameters and patterns."""
        url_lower = str(url or "").lower()
        if "api" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
            return "api_endpoint"
        if "auth" in url_lower or "login" in url_lower or "signin" in url_lower:
            return "auth_endpoint"
        if "?" in url_lower:
            return "parameterized_endpoint"
        return "generic_endpoint"

    def _initialize_state(self, state: str) -> None:
        """Warm-start the Q-values based on expert security heuristic states."""
        if state not in self.q_table:
            q_vals = {action: 0.05 for action in self.available_probes}
            
            # Prioritize probes by state features
            if state == "api_endpoint":
                q_vals["jwt"] = 0.85
                q_vals["idor"] = 0.80
                q_vals["graphql"] = 0.75
                q_vals["json"] = 0.70
                q_vals["fuzzing_campaign"] = 0.90
            elif state == "auth_endpoint":
                q_vals["auth_bypass"] = 0.90
                q_vals["jwt"] = 0.85
                q_vals["csrf"] = 0.70
            elif state == "parameterized_endpoint":
                q_vals["sqli"] = 0.85
                q_vals["xss"] = 0.80
                q_vals["hpp"] = 0.75
                q_vals["fuzzing_campaign"] = 0.85
            else:
                q_vals["ssrf"] = 0.60
                q_vals["xss"] = 0.50
                q_vals["csrf"] = 0.40

            self.q_table[state] = q_vals

    def get_optimal_probe_sequence(self, url: str) -> list[str]:
        """Rank and return the optimal security probe sequence for the target URL."""
        state = self._get_state(url)
        self._initialize_state(state)
        
        state_qs = self.q_table[state]
        # Sort probes descending based on their Q-values
        sorted_probes = sorted(self.available_probes, key=lambda a: state_qs[a], reverse=True)
        return sorted_probes

    def update(self, state: str, action: str, reward: float, next_state: str) -> None:
        """Update Q-values using standard Q-learning equation."""
        self._initialize_state(state)
        self._initialize_state(next_state)
        
        # Max Q(s', a')
        next_qs = self.q_table[next_state]
        max_next_q = max(next_qs.values()) if next_qs else 0.0
        
        # Q-learning equation
        current_q = self.q_table[state][action]
        td_target = reward + self.gamma * max_next_q
        new_q = current_q + self.alpha * (td_target - current_q)
        
        self.q_table[state][action] = round(new_q, 4)
        logger.debug("RL Agent: Updated Q(%s, %s) = %.4f", state, action, new_q)
