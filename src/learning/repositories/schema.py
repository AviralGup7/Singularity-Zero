"""Schema definitions and table creation logic for the telemetry database."""

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
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category, severity);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(endpoint_base, host);
CREATE INDEX IF NOT EXISTS idx_findings_decision ON findings(decision);

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
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_feedback_run ON feedback_events(run_id);
CREATE INDEX IF NOT EXISTS idx_feedback_category ON feedback_events(finding_category, was_false_positive);
CREATE INDEX IF NOT EXISTS idx_feedback_endpoint ON feedback_events(target_endpoint, finding_category);
CREATE INDEX IF NOT EXISTS idx_feedback_plugin ON feedback_events(plugin_name, was_false_positive);
CREATE INDEX IF NOT EXISTS idx_feedback_param ON feedback_events(parameter_name, parameter_type);
CREATE INDEX IF NOT EXISTS idx_feedback_host ON feedback_events(target_host, finding_category);
CREATE INDEX IF NOT EXISTS idx_feedback_time ON feedback_events(timestamp DESC);

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
"""

__all__ = ["_SCHEMA_DDL"]
