"""Schema definitions and table creation logic for the telemetry database."""

from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger(__name__)

_SCHEMA_DDL = """
-- Scan runs
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id              TEXT PRIMARY KEY,
    target_name         TEXT NOT NULL,
    mode                TEXT NOT NULL,
    start_time          TIMESTAMP NOT NULL,
    end_time            TIMESTAMP,
    status              TEXT NOT NULL,
    total_urls          INTEGER DEFAULT 0,
    total_endpoints     INTEGER DEFAULT 0,
    total_findings      INTEGER DEFAULT 0,
    validated_findings  INTEGER DEFAULT 0,
    false_positives     INTEGER DEFAULT 0,
    scan_duration_sec   REAL,
    config_hash         TEXT,
    feedback_applied    INTEGER DEFAULT 0,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Findings
CREATE TABLE IF NOT EXISTS findings (
    finding_id          TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL REFERENCES scan_runs(run_id),
    category            TEXT NOT NULL,
    title               TEXT NOT NULL,
    url                 TEXT NOT NULL,
    severity            TEXT NOT NULL,
    confidence          REAL NOT NULL,
    score               REAL,
    decision            TEXT,
    lifecycle_state     TEXT,
    cvss_score          REAL,
    plugin_name         TEXT,
    endpoint_base       TEXT,
    host                TEXT,
    parameter_name      TEXT,
    parameter_type      TEXT,
    evidence            TEXT,
    response_status     INTEGER,
    response_body_hash  TEXT,
    tech_stack          TEXT,
    asset_id            TEXT,
    asset_type          TEXT,
    asset_criticality   REAL,
    business_multiplier REAL,
    control_discount    REAL,
    modern_risk_score   REAL,
    remediation_priority REAL,
    triaged_at          TIMESTAMP,
    remediation_started_at TIMESTAMP,
    fixed_at            TIMESTAMP,
    verified_at         TIMESTAMP,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category, severity);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(endpoint_base, host);
CREATE INDEX IF NOT EXISTS idx_findings_decision ON findings(decision);
CREATE INDEX IF NOT EXISTS idx_findings_tech ON findings(tech_stack);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_type ON findings(asset_type);
CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(remediation_priority DESC);

-- Feedback events
CREATE TABLE IF NOT EXISTS feedback_events (
    event_id            TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL REFERENCES scan_runs(run_id),
    timestamp           TIMESTAMP NOT NULL,
    target_host         TEXT NOT NULL,
    target_endpoint     TEXT NOT NULL,
    finding_category    TEXT NOT NULL,
    finding_severity    TEXT NOT NULL,
    finding_confidence  REAL NOT NULL,
    finding_decision    TEXT NOT NULL,
    plugin_name         TEXT NOT NULL,
    parameter_name      TEXT,
    parameter_type      TEXT,
    was_validated       INTEGER NOT NULL,
    was_false_positive  INTEGER NOT NULL,
    validation_method   TEXT,
    response_delta_score INTEGER,
    endpoint_type       TEXT,
    tech_stack          TEXT,
    scan_mode           TEXT NOT NULL,
    feedback_weight     REAL NOT NULL,
    override_source     TEXT DEFAULT 'automated',
    reviewer_id         TEXT,
    override_reason     TEXT,
    asset_type          TEXT,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_feedback_run ON feedback_events(run_id);
CREATE INDEX IF NOT EXISTS idx_feedback_category ON feedback_events(finding_category, was_false_positive);
CREATE INDEX IF NOT EXISTS idx_feedback_endpoint ON feedback_events(target_endpoint, finding_category);
CREATE INDEX IF NOT EXISTS idx_feedback_plugin ON feedback_events(plugin_name, was_false_positive);
CREATE INDEX IF NOT EXISTS idx_feedback_param ON feedback_events(parameter_name, parameter_type);
CREATE INDEX IF NOT EXISTS idx_feedback_host ON feedback_events(target_host, finding_category);
CREATE INDEX IF NOT EXISTS idx_feedback_time ON feedback_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_override ON feedback_events(override_source);
CREATE INDEX IF NOT EXISTS idx_feedback_asset_type ON feedback_events(asset_type);

-- Parameter profiles
CREATE TABLE IF NOT EXISTS parameter_profiles (
    profile_id          TEXT PRIMARY KEY,
    parameter_name      TEXT NOT NULL,
    canonical_type      TEXT NOT NULL,
    sub_type            TEXT,
    entity_context      TEXT,
    endpoint_context    TEXT,
    location            TEXT,
    sensitivity_level   TEXT,
    fuzz_strategy       TEXT,
    historical_findings INTEGER DEFAULT 0,
    historical_fp_rate  REAL DEFAULT 0.0,
    classification_confidence REAL DEFAULT 0.0,
    first_seen          TIMESTAMP,
    last_seen           TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_param_profiles_name ON parameter_profiles(parameter_name);
CREATE INDEX IF NOT EXISTS idx_param_profiles_type ON parameter_profiles(canonical_type);
CREATE INDEX IF NOT EXISTS idx_param_profiles_entity ON parameter_profiles(entity_context);

-- FP patterns
CREATE TABLE IF NOT EXISTS fp_patterns (
    pattern_id            TEXT PRIMARY KEY,
    category              TEXT NOT NULL,
    status_code_pattern   TEXT,
    body_pattern          TEXT,
    header_pattern        TEXT,
    response_similarity   REAL,
    first_seen            TIMESTAMP NOT NULL,
    last_seen             TIMESTAMP NOT NULL,
    occurrence_count      INTEGER DEFAULT 0,
    confirmed_fp_count    INTEGER DEFAULT 0,
    confirmed_tp_count    INTEGER DEFAULT 0,
    fp_probability        REAL DEFAULT 0.5,
    confidence            REAL DEFAULT 0.0,
    is_active             INTEGER DEFAULT 1,
    suppression_action    TEXT DEFAULT 'downgrade',
    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_fp_patterns_category ON fp_patterns(category, is_active);
CREATE INDEX IF NOT EXISTS idx_fp_patterns_probability ON fp_patterns(fp_probability DESC);

-- Risk scores
CREATE TABLE IF NOT EXISTS risk_scores (
    score_id            TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL REFERENCES scan_runs(run_id),
    endpoint            TEXT NOT NULL,
    host                TEXT NOT NULL,
    category            TEXT NOT NULL,
    prior_risk          REAL NOT NULL,
    likelihood_ratio    REAL NOT NULL,
    recency_weight      REAL NOT NULL,
    context_modifier    REAL NOT NULL,
    exploration_bonus   REAL NOT NULL,
    correlation_amp     REAL NOT NULL,
    final_score         REAL NOT NULL,
    score_components    TEXT,
    computed_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_risk_scores_endpoint ON risk_scores(endpoint, host, category);
CREATE INDEX IF NOT EXISTS idx_risk_scores_run ON risk_scores(run_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_final ON risk_scores(final_score DESC);

-- Graph nodes
CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id             TEXT PRIMARY KEY,
    node_type           TEXT NOT NULL,
    label               TEXT NOT NULL,
    properties          TEXT,
    run_id              TEXT REFERENCES scan_runs(run_id),
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type, label);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_run ON graph_nodes(run_id);

-- Graph edges
CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id             TEXT PRIMARY KEY,
    source_node_id      TEXT NOT NULL REFERENCES graph_nodes(node_id),
    target_node_id      TEXT NOT NULL REFERENCES graph_nodes(node_id),
    edge_type           TEXT NOT NULL,
    weight              REAL DEFAULT 1.0,
    confidence          REAL DEFAULT 1.0,
    properties          TEXT,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges(edge_type);

-- Threshold history
CREATE TABLE IF NOT EXISTS threshold_history (
    history_id          TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL REFERENCES scan_runs(run_id),
    category            TEXT,
    low_threshold       REAL NOT NULL,
    medium_threshold    REAL NOT NULL,
    high_threshold      REAL NOT NULL,
    observed_fp_rate    REAL,
    target_fp_rate      REAL,
    error               REAL,
    adjustment          REAL,
    is_converged        INTEGER DEFAULT 0,
    recorded_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_threshold_history_run ON threshold_history(run_id);
CREATE INDEX IF NOT EXISTS idx_threshold_history_category ON threshold_history(category);

-- Plugin statistics
CREATE TABLE IF NOT EXISTS plugin_stats (
    stat_id             TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL REFERENCES scan_runs(run_id),
    plugin_name         TEXT NOT NULL,
    findings_produced   INTEGER DEFAULT 0,
    true_positives      INTEGER DEFAULT 0,
    false_positives     INTEGER DEFAULT 0,
    execution_time_ms   REAL,
    precision           REAL,
    recall              REAL,
    recorded_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_plugin_stats_run ON plugin_stats(run_id);
CREATE INDEX IF NOT EXISTS idx_plugin_stats_name ON plugin_stats(plugin_name);

-- Performance metrics
CREATE TABLE IF NOT EXISTS performance_metrics (
    metric_id           TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL REFERENCES scan_runs(run_id),
    metric_name         TEXT NOT NULL,
    metric_value        REAL NOT NULL,
    metric_category     TEXT,
    recorded_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_perf_metrics_run ON performance_metrics(run_id);
CREATE INDEX IF NOT EXISTS idx_perf_metrics_name ON performance_metrics(metric_name);

-- Session states
CREATE TABLE IF NOT EXISTS session_states (
    session_id          TEXT PRIMARY KEY,
    role                TEXT NOT NULL,
    target_host         TEXT NOT NULL,
    tenant_id           TEXT,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used           TIMESTAMP,
    request_count       INTEGER DEFAULT 0,
    is_active           INTEGER DEFAULT 1,
    token_expiry        TIMESTAMP
);

-- Attack chains
CREATE TABLE IF NOT EXISTS attack_chains (
    chain_id            TEXT PRIMARY KEY,
    pattern_name        TEXT NOT NULL,
    description         TEXT NOT NULL,
    finding_ids         TEXT NOT NULL,
    confidence          REAL NOT NULL,
    risk_score          REAL NOT NULL,
    validation_status   TEXT DEFAULT 'pending',
    validation_result   TEXT,
    detected_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attack_chains_pattern ON attack_chains(pattern_name);
CREATE INDEX IF NOT EXISTS idx_attack_chains_status ON attack_chains(validation_status);
CREATE INDEX IF NOT EXISTS idx_attack_chains_risk ON attack_chains(risk_score DESC);

-- Confidence models
CREATE TABLE IF NOT EXISTS confidence_models (
    model_id            TEXT PRIMARY KEY,
    category            TEXT NOT NULL,
    plugin_name         TEXT NOT NULL,
    platt_A             REAL,
    platt_B             REAL,
    sample_size         INTEGER DEFAULT 0,
    accuracy            REAL,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_confidence_models ON confidence_models(category, plugin_name);

-- Asset registry (modern risk domain)
CREATE TABLE IF NOT EXISTS assets (
    asset_id              TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    host_pattern          TEXT NOT NULL,
    path_prefix           TEXT,
    asset_type            TEXT NOT NULL DEFAULT 'unknown',
    entity_type           TEXT NOT NULL DEFAULT 'unknown',
    criticality           REAL NOT NULL DEFAULT 1.0,
    tier                  TEXT NOT NULL DEFAULT 'tier_4',
    business_value        REAL NOT NULL DEFAULT 1.0,
    compliance_requirements TEXT,
    owner                 TEXT,
    notes                 TEXT,
    metadata              TEXT,
    is_active             INTEGER NOT NULL DEFAULT 1,
    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host_pattern);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type, entity_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality DESC);

-- Risk acceptances (governance workflow)
CREATE TABLE IF NOT EXISTS risk_acceptances (
    acceptance_id          TEXT PRIMARY KEY,
    finding_id             TEXT NOT NULL,
    asset_id               TEXT,
    accepted_until         TIMESTAMP,
    accepted_by            TEXT NOT NULL,
    justification          TEXT NOT NULL,
    compensating_control_ref TEXT,
    review_date            TIMESTAMP,
    scope                  TEXT NOT NULL DEFAULT 'global',
    state                  TEXT NOT NULL DEFAULT 'active',
    created_by             TEXT,
    metadata               TEXT,
    created_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_finding ON risk_acceptances(finding_id);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_state ON risk_acceptances(state, accepted_until);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_asset ON risk_acceptances(asset_id);

-- Compensating controls
CREATE TABLE IF NOT EXISTS compensating_controls (
    control_id             TEXT PRIMARY KEY,
    finding_id             TEXT NOT NULL,
    control_type           TEXT NOT NULL,
    description            TEXT,
    discount_factor        REAL NOT NULL DEFAULT 0.85,
    evidence_url           TEXT,
    owner                  TEXT,
    expires_at             TIMESTAMP,
    is_active              INTEGER NOT NULL DEFAULT 1,
    metadata               TEXT,
    created_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_controls_finding ON compensating_controls(finding_id);
CREATE INDEX IF NOT EXISTS idx_controls_type ON compensating_controls(control_type, is_active);

-- SLA lifecycle events
CREATE TABLE IF NOT EXISTS sla_events (
    event_id               TEXT PRIMARY KEY,
    finding_id             TEXT NOT NULL,
    from_state             TEXT NOT NULL,
    to_state               TEXT NOT NULL,
    timestamp              TIMESTAMP NOT NULL,
    actor                  TEXT,
    note                   TEXT,
    metadata               TEXT,
    created_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sla_events_finding ON sla_events(finding_id);
CREATE INDEX IF NOT EXISTS idx_sla_events_state ON sla_events(to_state, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sla_events_time ON sla_events(timestamp DESC);

-- Threat intel cache
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    cache_id               TEXT PRIMARY KEY,
    indicator              TEXT NOT NULL,
    indicator_type         TEXT NOT NULL,
    source                 TEXT NOT NULL,
    score                  REAL,
    severity               TEXT,
    raw                    TEXT,
    expires_at             TIMESTAMP,
    fetched_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel_cache(indicator, source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_expiry ON threat_intel_cache(expires_at);

-- Reviewer actions (FindingReviewPanel)
CREATE TABLE IF NOT EXISTS reviewer_actions (
    action_id              TEXT PRIMARY KEY,
    finding_id             TEXT NOT NULL,
    action_type            TEXT NOT NULL,
    reviewer_id            TEXT,
    structured_note        TEXT,
    from_state             TEXT,
    to_state               TEXT,
    timestamp              TIMESTAMP NOT NULL,
    metadata               TEXT
);
CREATE INDEX IF NOT EXISTS idx_reviewer_finding ON reviewer_actions(finding_id);
CREATE INDEX IF NOT EXISTS idx_reviewer_action ON reviewer_actions(action_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_reviewer_reviewer ON reviewer_actions(reviewer_id);
"""


# ---------------------------------------------------------------------------
# In-place migrations for databases created before the modern risk domain
# tables / columns were added. ``CREATE TABLE IF NOT EXISTS`` only creates
# *missing* tables; existing tables are not retro-fitted with new columns.
# The list below is a series of idempotent ``ALTER TABLE`` statements. SQLite
# has no ``IF NOT EXISTS`` for columns, so we check the table schema first via
# ``PRAGMA table_info`` and skip columns that already exist.
# ---------------------------------------------------------------------------

# Mapping: table -> list of (column, definition) pairs to add.
_COLUMN_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "findings": [
        ("asset_id", "TEXT"),
        ("asset_type", "TEXT"),
        ("asset_criticality", "REAL"),
        ("business_multiplier", "REAL"),
        ("control_discount", "REAL"),
        ("modern_risk_score", "REAL"),
        ("remediation_priority", "REAL"),
        ("triaged_at", "TIMESTAMP"),
        ("remediation_started_at", "TIMESTAMP"),
        ("fixed_at", "TIMESTAMP"),
        ("verified_at", "TIMESTAMP"),
    ],
    "feedback_events": [
        ("override_source", "TEXT DEFAULT 'automated'"),
        ("reviewer_id", "TEXT"),
        ("override_reason", "TEXT"),
        ("asset_type", "TEXT"),
    ],
    "fp_patterns": [
        ("scope_signature", "TEXT"),
        ("is_global", "INTEGER DEFAULT 0"),
    ],
}


def _existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error:
        return set()
    return {row[1] for row in rows}


def _existing_tables(conn: sqlite3.Connection) -> set[str]:
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    except sqlite3.Error:
        return set()
    return {row[0] for row in rows}


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Apply column-level migrations to ``conn`` in-place.

    Returns the number of statements executed. Safe to call on a
    brand-new database: the ``CREATE TABLE IF NOT EXISTS`` script
    has already produced the modern schema, so this function will
    detect every column as present and become a no-op.
    """
    executed = 0
    tables = _existing_tables(conn)
    for table, columns in _COLUMN_MIGRATIONS.items():
        if table not in tables:
            # ``CREATE TABLE IF NOT EXISTS`` will create the modern
            # version on the next ``initialize()`` call.
            continue
        existing = _existing_columns(conn, table)
        for name, definition in columns:
            if name in existing:
                continue
            try:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                )
                executed += 1
            except sqlite3.Error as exc:  # noqa: BLE001
                logger.warning(
                    "Schema migration: failed to add %s.%s: %s", table, name, exc
                )
    conn.commit()
    return executed


__all__ = ["_SCHEMA_DDL", "apply_migrations"]
