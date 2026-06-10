import json

from src.reporting.triage_audit import load_triage_events, triage_audit_section


def test_load_triage_events_no_file(tmp_path):
    # If the triage_audit.jsonl file does not exist, load_triage_events should return an empty list
    events = load_triage_events(tmp_path)
    assert events == []


def test_load_triage_events_filtering(tmp_path):
    triage_dir = tmp_path / "_triage"
    triage_dir.mkdir(parents=True, exist_ok=True)
    audit_file = triage_dir / "triage_audit.jsonl"

    event_run_1 = {
        "run_id": "run_1",
        "action": "override_severity",
        "analyst_name": "Alice",
        "timestamp": "2026-05-21 12:00:00",
        "finding_id": "F1",
        "hash": "abc123xyz789def0123",
        "payload": {"text": "Verified high vulnerability"},
    }

    event_run_2 = {
        "run_id": "run_2",
        "action": "false_positive_mark",
        "analyst_name": "Bob",
        "timestamp": "2026-05-21 12:05:00",
        "finding_id": "F2",
        "hash": "9876543210fedcba987",
        "payload": {"reason": "Not exploitable in staging"},
    }

    # Write events to jsonl, including empty lines to test that parser skips them
    with open(audit_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(event_run_1) + "\n")
        f.write("\n")
        f.write(json.dumps(event_run_2) + "\n")
        f.write("   \n")

    # Load all events without run_id filter
    events = load_triage_events(tmp_path)
    assert len(events) == 2
    assert events[0]["run_id"] == "run_1"
    assert events[1]["run_id"] == "run_2"

    # Load events with run_id="run_1" filter
    events_run_1 = load_triage_events(tmp_path, run_id="run_1")
    assert len(events_run_1) == 1
    assert events_run_1[0]["run_id"] == "run_1"

    # Load events with run_id="run_3" filter (non-existent)
    events_run_3 = load_triage_events(tmp_path, run_id="run_3")
    assert events_run_3 == []


def test_triage_audit_section_empty(tmp_path):
    # When no events are present, should return the empty section HTML
    html_output = triage_audit_section(tmp_path)
    assert "Collaborative Triage Audit" in html_output
    assert "No collaborative triage actions recorded for this run" in html_output


def test_triage_audit_section_with_data(tmp_path):
    triage_dir = tmp_path / "_triage"
    triage_dir.mkdir(parents=True, exist_ok=True)
    audit_file = triage_dir / "triage_audit.jsonl"

    events = [
        {
            "run_id": "run_test",
            "action": "add_analyst_note",
            "analyst_name": "Charlie",
            "timestamp": "2026-05-21 12:10:00",
            "finding_id": "F3",
            "hash": "abcdefabcdefabcdefabcdef",
            "payload": {"text": "Needs review <script>alert(1)</script>"},
        },
        {
            "run_id": "run_test",
            "action": "status_update",
            "analyst_name": "Dave",
            "timestamp": "2026-05-21 12:15:00",
            "finding_id": "F4",
            "hash": "123456781234567812345678",
            "payload": {"status": "resolved"},
        },
        {
            "run_id": "run_test",
            "action": "no_payload_text_action",
            "analyst_name": "Eve",
            "timestamp": "2026-05-21 12:20:00",
            "finding_id": "F5",
            "hash": "000000000000000000000000",
            "payload": None,  # payload is not a dict
        },
    ]

    with open(audit_file, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    # Generate section for run_test with limit=3 so all are returned
    html_output = triage_audit_section(tmp_path, run_id="run_test", limit=3)
    assert "Collaborative Triage Audit" in html_output

    # Action "status_update" should be titled "Status Update"
    assert "Status Update" in html_output
    assert "Dave" in html_output
    assert "resolved" in html_output
    assert "1234567812345678" in html_output  # first 16 characters of hash

    # Action "add_analyst_note" should be titled "Add Analyst Note"
    assert "Add Analyst Note" in html_output
    assert "Charlie" in html_output
    # HTML should be escaped
    assert "Needs review &lt;script&gt;alert(1)&lt;/script&gt;" in html_output

    # Eve's action should also be present since limit=3
    assert "No Payload Text Action" in html_output
    assert "Eve" in html_output

    # Generate section with limit=2 (Charlie should be excluded)
    html_output_limit_2 = triage_audit_section(tmp_path, run_id="run_test", limit=2)
    assert "Status Update" in html_output_limit_2
    assert "No Payload Text Action" in html_output_limit_2
    assert "Add Analyst Note" not in html_output_limit_2


def test_bulk_triage_and_team_metrics(tmp_path):
    from src.reporting.triage_audit import bulk_triage_findings, calculate_team_triage_metrics

    bulk_triage_findings(
        tmp_path,
        finding_ids=["F1", "F2"],
        status="DEFERRED",
        analyst_name="Security Lead Alice",
        role="Lead",
        reason="Low priority backlog items",
    )

    events = load_triage_events(tmp_path)
    assert len(events) == 1
    assert events[0]["action"] == "bulk_triage"
    assert events[0]["analyst_name"] == "Security Lead Alice"
    assert events[0]["analyst_role"] == "Lead"

    findings = [
        {
            "id": "F1",
            "status": "DEFERRED",
            "assignee": "Security Lead Alice",
            "discovered_at": 1000,
            "triaged_at": 1500,
        },
        {
            "id": "F2",
            "status": "DEFERRED",
            "assignee": "Security Lead Alice",
            "discovered_at": 1000,
            "triaged_at": 2500,
        },
        {"id": "F3", "status": "OPEN", "assignee": None, "discovered_at": 1000},
    ]

    metrics = calculate_team_triage_metrics(events, findings)
    assert metrics["backlog_count"] == 1
    assert metrics["triaged_count"] == 2
    assert metrics["assigned_count"] == 2
    assert metrics["avg_triage_hours"] == 0.28  # avg: (500 + 1500)/2 = 1000 seconds = ~0.28 hours


def test_triage_queue_exports(tmp_path):
    from src.reporting.triage_audit import export_triage_queue_csv, export_triage_queue_json

    findings = [
        {
            "id": "F1",
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "category": "sqli",
            "url": "http://a",
            "status": "OPEN",
            "assignee": "Bob",
            "sla_status": "COMPLIANT",
        },
    ]

    csv_path = tmp_path / "triage.csv"
    export_triage_queue_csv(findings, csv_path)
    assert csv_path.exists()
    assert "SQL Injection" in csv_path.read_text(encoding="utf-8")

    json_path = tmp_path / "triage.json"
    export_triage_queue_json(findings, json_path)
    assert json_path.exists()
    assert "CRITICAL" in json_path.read_text(encoding="utf-8")
