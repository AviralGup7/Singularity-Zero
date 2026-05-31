"""Tests for Autonomous Multi-Agent Red Team (Collaborative AI Swarm)."""

from src.intelligence.swarm.agent_node import AgentNode, SwarmOrchestrator


def test_agent_node_initialization():
    recon = AgentNode("Recon")
    assert recon.role == "Recon"
    assert recon.node_id.startswith("Recon-")
    assert len(recon.get_known_urls()) == 0
    assert len(recon.get_known_findings()) == 0


def test_agent_discovery():
    exploiter = AgentNode("Exploiter")
    exploiter.discover_url("http://example.com/admin")
    exploiter.discover_finding({"id": "vuln-1", "title": "SQLi in Login"})

    assert "http://example.com/admin" in exploiter.get_known_urls()
    assert any(f.get("id") == "vuln-1" for f in exploiter.get_known_findings())


def test_agent_sync_crdt():
    recon = AgentNode("Recon")
    assessor = AgentNode("Assessor")

    recon.discover_url("http://example.com/api")
    assessor.discover_url("http://example.com/docs")

    # State should be isolated initially
    assert "http://example.com/docs" not in recon.get_known_urls()
    assert "http://example.com/api" not in assessor.get_known_urls()

    # Sync via CRDT merge
    recon.sync_with(assessor)

    # Both agents should now have the exact same knowledge base
    assert "http://example.com/docs" in recon.get_known_urls()
    assert "http://example.com/api" in recon.get_known_urls()

    assert "http://example.com/docs" in assessor.get_known_urls()
    assert "http://example.com/api" in assessor.get_known_urls()


def test_swarm_global_sync():
    swarm = SwarmOrchestrator()
    recon = AgentNode("Recon")
    assessor = AgentNode("Assessor")
    exploiter = AgentNode("Exploiter")

    swarm.register_agent(recon)
    swarm.register_agent(assessor)
    swarm.register_agent(exploiter)

    recon.discover_url("http://example.com/recon")
    assessor.discover_finding({"id": "vuln-2", "title": "XSS"})
    exploiter.discover_url("http://example.com/exploit")

    swarm.global_sync()

    # Verify all agents share the same exact state after full sync
    for agent in swarm.agents:
        urls = agent.get_known_urls()
        findings = agent.get_known_findings()

        assert "http://example.com/recon" in urls
        assert "http://example.com/exploit" in urls
        assert any(f.get("id") == "vuln-2" for f in findings)
