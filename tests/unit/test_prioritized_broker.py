"""Unit tests for PrioritizedRealtimeBroker and QoS Backpressure."""

from src.realtime.prioritized_broker import (
    PrioritizedRealtimeBroker,
    QoSClass,
    TelemetryEvent,
)


def test_prioritized_broker_strict_ordering() -> None:
    broker = PrioritizedRealtimeBroker()

    # Publish in reverse order: P4, P3, P2, P1, P0
    broker.publish(TelemetryEvent(event_id="e_debug", qos=QoSClass.P4_DEBUG, topic="debug", payload={"log": "trace"}))
    broker.publish(TelemetryEvent(event_id="e_metric", qos=QoSClass.P3_TELEMETRY, topic="rps", payload={"rps": 100}))
    broker.publish(TelemetryEvent(event_id="e_finding", qos=QoSClass.P2_FINDINGS, topic="findings", payload={"id": "f1"}))
    broker.publish(TelemetryEvent(event_id="e_life", qos=QoSClass.P1_LIFECYCLE, topic="stage", payload={"stage": "recon"}))
    broker.publish(TelemetryEvent(event_id="e_ctrl", qos=QoSClass.P0_CONTROL, topic="emergency", payload={"stop": True}))

    # Drain batch: must drain P0 -> P1 -> P2 -> P3 -> P4
    batch = broker.drain_batch(max_events=10)
    assert len(batch) == 5
    assert batch[0].qos == QoSClass.P0_CONTROL
    assert batch[1].qos == QoSClass.P1_LIFECYCLE
    assert batch[2].qos == QoSClass.P2_FINDINGS
    assert batch[3].qos == QoSClass.P3_TELEMETRY
    assert batch[4].qos == QoSClass.P4_DEBUG


def test_prioritized_broker_coalescing_findings() -> None:
    broker = PrioritizedRealtimeBroker()

    # Publish duplicate updates for same finding
    broker.publish(TelemetryEvent(event_id="f_1_v1", qos=QoSClass.P2_FINDINGS, topic="findings", dedup_key="finding:sqli:users", payload={"severity": "LOW"}))
    broker.publish(TelemetryEvent(event_id="f_1_v2", qos=QoSClass.P2_FINDINGS, topic="findings", dedup_key="finding:sqli:users", payload={"severity": "HIGH"}))

    batch = broker.drain_batch(max_events=10)
    assert len(batch) == 1
    assert batch[0].payload["severity"] == "HIGH"


def test_prioritized_broker_debug_load_shedding() -> None:
    broker = PrioritizedRealtimeBroker(p4_capacity=3)

    # Publish 5 debug events to saturate buffer
    for i in range(5):
        broker.publish(TelemetryEvent(event_id=f"dbg_{i}", qos=QoSClass.P4_DEBUG, topic="debug", payload={"line": i}))

    stats = broker.get_stats()
    assert stats["dropped_counts"].get("P4_DEBUG", 0) == 2
