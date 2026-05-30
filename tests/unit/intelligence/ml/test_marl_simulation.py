"""Tests for MARL Attack-Path Simulation."""

import pytest
from src.intelligence.ml.marl_simulation import MARLSimulator

def test_marl_simulation_initialization():
    nodes = [
        {"id": "n1", "type": "subdomain", "severity": "low"},
        {"id": "n2", "type": "endpoint", "severity": "medium"},
        {"id": "n3", "type": "finding", "severity": "critical"},
    ]
    edges = [
        {"source": "n1", "target": "n2"},
    ]
    
    sim = MARLSimulator(nodes, edges, num_agents=2)
    assert len(sim.agent_positions) == 2
    assert len(sim.compromised) >= 1

def test_marl_simulation_step():
    nodes = [
        {"id": "n1", "type": "subdomain", "severity": "low"},
        {"id": "n2", "type": "endpoint", "severity": "medium"},
        {"id": "n3", "type": "finding", "severity": "critical"},
    ]
    edges = [
        {"source": "n1", "target": "n2"},
        {"source": "n2", "target": "n3"},
    ]
    
    sim = MARLSimulator(nodes, edges, num_agents=1)
    sim.agent_positions = ["n1"]
    sim.compromised = {"n1"}
    
    actions = sim.step()
    assert len(actions) == 1
    assert actions[0]["from"] == "n1"
    assert actions[0]["to"] in ["n2", "n3"] # n3 might be reached via GNN if not direct
    assert actions[0]["to"] in sim.compromised

def test_marl_rollout():
    nodes = [{"id": f"n{i}", "type": "endpoint"} for i in range(10)]
    edges = [{"source": f"n{i}", "target": f"n{i+1}"} for i in range(9)]
    
    sim = MARLSimulator(nodes, edges, num_agents=3)
    history = sim.run_rollout(steps=5)
    
    assert len(history) == 5
    for step_actions in history:
        assert len(step_actions) <= 3
