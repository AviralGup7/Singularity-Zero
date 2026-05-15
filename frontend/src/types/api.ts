// ============================================================
// TypeScript types for the Cyber Pipeline API
// ============================================================

export interface MeshNode {
  id: string;
  host: string;
  port: number;
  status: 'alive' | 'suspect' | 'dead';
  cpu_usage: number;
  ram_available_mb: number;
  active_jobs: number;
  last_seen: number;
}

export interface MeshEdge {
  source: string;
  target: string;
  throughput: number;
  latency_ms: number;
  drop_rate: number;
  status: 'alive' | 'suspect' | 'dead';
}

export interface MeshHealth {
  peer_count: number;
  leader_id: string;
  avg_latency_ms: number;
  drop_rate: number;
  active_heartbeats: boolean;
  nodes: MeshNode[];
  edges: MeshEdge[];
  retry?: {
    base_ms: number;
    max_ms: number;
    max_attempts: number;
  };
  heartbeat?: {
    interval_sec: number;
    fail_threshold: number;
  };
  peer_stats?: Record<string, Record<string, unknown>>;
}

export interface BloomNodeHealth {
  node_id: string;
  memory_mb: number;
  element_count: number;
  false_positive_probability: number;
  fill_ratio: number;
  last_sync_time: number;
  capacity: number;
  hash_count: number;
  clock: Record<string, number>;
  stale: boolean;
}

export interface BloomSaturationPoint {
  time: number;
  fill_ratio: number;
  false_positive_probability: number;
}

export interface BloomHealthResponse {
  nodes: BloomNodeHealth[];
  saturation_history: BloomSaturationPoint[];
  sync_interval_seconds: number;
  redis_enabled: boolean;
  channel: string;
}

export interface BloomReconcileResponse {
  status: string;
  node_id?: string;
  redis_enabled: boolean;
  channel?: string;
  remote_nodes?: number;
  last_sync_time?: number;
}

export interface AttackStep {
  asset_id: string;
  finding_id: string;
  severity: string;
}

export interface AttackChain {
  id: string;
  steps: AttackStep[];
  confidence: number;
  description: string;
}

export interface Target {
  name: string;
  href: string;
  latest_run: string;
  latest_generated_at: string;
  latest_report_href: string;
  priority_url_count: number;
  finding_count: number;
  validated_leads: number;
  url_count: number;
  parameter_count: number;
  new_findings: number;
  attack_chain_count: number;
  max_attack_chain_confidence: number;
  validation_plan_count: number;
  top_finding_title: string;
  top_finding_severity: string;
  top_finding_url: string;
  severity_counts: Record<string, number>;
  run_count: number;
  last_scan?: string;
}

export interface Job {
  id: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  base_url: string;
  hostname: string;
  target_name: string;
  mode: string;
  stage?: string;
  stage_label: string;
  failed_stage?: string;
  failure_reason_code?: string;
  failure_step?: string;
  failure_reason?: string;
  progress_percent: number;
  has_eta: boolean;
  eta_label: string;
  stalled: boolean;
  started_at: string;
  started_at_ist?: string;
  finished_at_label?: string;
  completed_at?: string;
  latest_logs: string[];
  error: string | null;
  warnings: string[];
  warning_count?: number;
  fatal_signal_count?: number;
  timeout_events?: string[];
  degraded_providers?: string[];
  effective_timeout_seconds?: number | null;
  enabled_modules: string[];
  scope_entries: string[];
  status_message: string;
  execution_options: Record<string, boolean>;
  runtime_overrides?: Record<string, string>;
  elapsed_seconds?: number;
  elapsed_label?: string;
  stage_percent?: number;
  stage_processed?: number;
  stage_total?: number;
  iteration_current?: number;
  iteration_total?: number;
  plugin_progress?: PluginProgressEntry[];
  findings_count?: number;
  stage_progress_label?: string;
  stage_progress?: StageProgressEntry[];
  progress_telemetry?: ProgressTelemetry;
  concurrent_stage_count?: number;
  can_stop?: boolean;
  returncode?: number | null;
  duration_forecast?: DurationForecast;
  stalled_context?: StalledContext;
  per_module_stats?: Record<string, { duration_sec?: number; findings_count?: number }>;
  config_href?: string;
  scope_href?: string;
  stdout_href?: string;
  stderr_href?: string;
  target_href?: string;
}

export interface PluginProgressEntry {
  group: string;
  label: string;
  processed: number;
  total: number;
  percent: number;
  current_plugin?: string;
  status: 'pending' | 'running' | 'completed' | 'error';
  error_message?: string;
}

export interface StageProgressEntry {
  stage: string;
  stage_label: string;
  status: 'pending' | 'running' | 'completed' | 'error' | 'skipped';
  processed: number;
  total: number | null;
  percent: number;
  reason?: string;
  error?: string;
  retry_count?: number;
  last_event?: string;
  started_at?: number;
  updated_at?: number;
}

export interface StageTransitionEntry {
  stage: string;
  status: string;
  timestamp: number;
  message?: string;
}

export interface SkippedStageEntry {
  stage: string;
  reason?: string;
}

export interface ProgressTelemetry {
  [key: string]: unknown;
  active_task_count?: number;
  requests_per_second?: number;
  throughput_per_second?: number;
  eta_seconds?: number;
  high_value_target_count?: number;
  vulnerability_likelihood_score?: number;
  signal_noise_ratio?: number;
  confidence_score?: number;
  drop_off?: { input: number; kept: number; dropped: number };
  deduplication?: { removed: number; remaining: number };
  targets?: { queued: number; scanning: number; done: number };
  retry_count?: number;
  failure_count?: number;
  stage_transitions?: StageTransitionEntry[];
  event_triggers?: string[];
  skipped_stages?: SkippedStageEntry[];
  top_active_targets?: string[];
  bottleneck_stage?: string;
  bottleneck_seconds?: number;
  next_best_action?: string;
  learning_feedback?: Record<string, unknown> | string;
  last_update_epoch?: number;
}

export interface DurationForecast {
  per_stage: Record<string, { mean: number; p50: number; p90: number; count: number }>;
  total_mean_seconds: number;
}

export interface StalledContext {
  stage: string;
  stage_label: string;
  seconds_since_update: number;
  elapsed_label: string;
  expected_duration_seconds: number;
  probable_cause: string;
  suggested_actions: string[];
}

export interface JobLogs {
  job_id: string;
  logs: string[];
  total_logs: number;
  status: string;
}

export interface TraceLink {
  job_id: string;
  trace_id: string;
  trace_url: string;
  mode: 'trace' | 'search';
}

export interface RemediationSuggestion {
  id: string;
  title: string;
  command: string;
  rationale?: string;
  safety_note?: string;
}

export interface RemediationResponse {
  job_id?: string;
  finding_id?: string;
  suggestions: RemediationSuggestion[];
}

export interface EvidenceItem {
  id: string;
  timestamp: string;
  source: string;
  description: string;
  raw_data: string;
  data_type?: string;
  sensitive?: boolean;
  redacted?: boolean;
}

export interface RequestResponsePair {
  id: string;
  timestamp: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: string;
    body_encoding?: 'plain' | 'base64' | 'url' | 'hex';
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body: string;
    body_encoding?: 'plain' | 'base64' | 'url' | 'hex';
  };
  sensitive_fields?: string[];
}

export interface Finding {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  timestamp: number | string;
  url?: string;
  host?: string;
  port?: number;
  protocol?: string;
  evidence?: {
    request?: string;
    response?: string;
    match?: string;
    proof?: string;
  };
  lifecycle_state: 'detected' | 'validated' | 'exploitable' | 'reportable';
  metadata?: Record<string, unknown>;
  csi_score?: number;
  logic_diff?: string;

  // UI / Analysis extensions (optional)
  cve?: string;
  cwe?: string;
  target?: string;
  status?: 'open' | 'closed' | 'accepted';
  cvss_score?: number;
  cvss_vector?: string;
  cvss_explanation?: string;
  cvss_v4_score?: number;
  cvss_v4_vector?: string;
  request_response?: RequestResponsePair[];

  // Project-specific UI state
  assignedTo?: string;
  duplicates?: string[];
  falsePositive?: boolean;
  fpStatus?: 'none' | 'pending' | 'approved' | 'rejected';
  fpJustification?: string;
  kanbanStatus?: 'new' | 'in-progress' | 'resolved';
}

export interface TargetSummary {
  name: string;
  finding_count: number;
  severity_counts: Record<string, number>;
}

export interface FindingsSummary {
  total_findings: number;
  severity_totals: Record<string, number>;
  by_module: Record<string, number>;
  targets: TargetSummary[];
  targets_with_findings: number;
  total_targets: number;
}

export interface DashboardStats {
  active_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  completed_targets: number;
  total_findings: number;
  total_targets: number;
  avg_progress: number;
  stage_counts: Record<string, number>;
  pipeline_health_score: number;
  pipeline_health_label: string;
  trend_data: number[];
  findings_summary: FindingsSummary;
  mesh_health?: Record<string, unknown>;
  mesh?: MeshNode[];
}
export interface ApiDefaults {
  default_mode: string;
  form_defaults: Record<string, string>;
}

export interface ModuleOption {
  name: string;
  label: string;
  description: string;
  kind: string;
  group: string;
  dependency_hint?: string;
  requires?: string[];
}

export interface ModuleGroup {
  name: string;
  label: string;
  description: string;
  icon: string;
}

export interface AnalysisCheckOption {
  name: string;
  label: string;
  description: string;
  group: string;
}

export interface ModePreset {
  name: string;
  label: string;
  description: string;
  modules: string[];
}

export interface AnalysisControlGroup {
  name: string;
  label: string;
  description: string;
  icon?: string;
}

export interface AnalysisFocusPreset {
  name: string;
  label: string;
  description: string;
  checks?: string[];
}

export interface RegistryResponse {
  modules: {
    options: ModuleOption[];
    groups: ModuleGroup[];
  };
  analysis: {
    check_options: AnalysisCheckOption[];
    control_groups: AnalysisControlGroup[];
    focus_presets: AnalysisFocusPreset[];
  };
  modes: {
    presets: ModePreset[];
    stage_labels: Record<string, string>;
  };
}

export interface HealthResponse {
  status: string;
  timestamp: string;
  uptime_seconds?: number;
  version?: string;
  dependencies: Record<string, unknown>;
  mesh: MeshNode[];
}

export interface ReplayResponse {
  replay_id: string;
  auth_mode: string;
  applied_header_names: string[];
  requested_url: string;
  final_url: string;
  redirect_chain: string[];
  status_code: number | null;
  body_similarity: number | null;
  status_changed: boolean;
  redirect_changed: boolean;
  content_changed: boolean;
}

// Type aliases for API client compatibility
export type Defaults = ApiDefaults;
export type ReplayResult = ReplayResponse;
export type RegistryData = RegistryResponse;
export type HealthStatus = HealthResponse;

export interface StartJobRequest {
  base_url: string;
  scope_text?: string;
  selected_modules?: string[];
  mode?: string;
  runtime_overrides?: Record<string, string>;
  execution_options?: Record<string, boolean>;
}

export type StartJobResponse = Job;

export type JobActionResponse = Job;

export interface GapAnalysisResult {
  module: string;
  category: string;
  total_checks: number;
  covered_checks: number;
  missing_checks: number;
  coverage_percent: number;
  status: 'complete' | 'partial' | 'missing';
}

export interface DetectionGapResponse {
  target: string | null;
  results: GapAnalysisResult[];
  overall_coverage: number;
  total_modules: number;
  modules_with_gaps: number;
}

export interface ExportOptions {
  format: 'csv' | 'json';
  filters?: {
    severity?: string[];
    status?: string[];
    targets?: string[];
  };
}
