"""Pydantic request/response schemas for the FastAPI dashboard."""

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    items: list[T]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool


class MeshNodeSchema(BaseModel):
    """Schema for distributed mesh node telemetry."""

    id: str
    host: str
    port: int
    status: str
    cpu_usage: float
    ram_available_mb: float
    active_jobs: int
    last_seen: float


class AttackStepSchema(BaseModel):
    """Single hop in a multi-stage attack chain."""

    asset_id: str
    finding_id: str
    severity: str


class AttackChainSchema(BaseModel):
    """Complete lateral movement path."""

    id: str
    steps: list[AttackStepSchema]
    confidence: float
    description: str


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    detail: str | None = None
    code: str | None = None


class StrictRequestModel(BaseModel):
    """Base class for JSON request bodies that reject unknown fields."""

    model_config = ConfigDict(extra="forbid")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    timestamp: str
    version: str = "2.0.0"
    uptime_seconds: float | None = None
    dependencies: dict[str, Any] = Field(default_factory=dict)
    mesh: list[MeshNodeSchema] = Field(default_factory=list)


class ReadinessResponse(BaseModel):
    """Readiness check response."""

    ready: bool
    checks: dict[str, bool] = Field(default_factory=dict)


class JobCreateRequest(StrictRequestModel):
    """Request body for starting a new scan job."""

    base_url: str = Field(..., min_length=1, description="Target base URL")
    target_name: str = Field(default="", description="Target name for output directory")
    scope_text: str = Field(default="", description="Additional scope entries")
    mode: str = Field(default="idor", description="Pipeline mode")
    modules: list[str] | None = Field(default=None, description="Selected module names")
    runtime_overrides: dict[str, str] = Field(default_factory=dict)
    execution_options: dict[str, bool] = Field(default_factory=dict)


class StageProgressEntry(BaseModel):
    """Per-stage progress status entry."""

    stage: str
    stage_label: str
    status: str
    processed: int = 0
    total: int | None = None
    percent: int = 0
    reason: str = ""
    error: str = ""
    retry_count: int = 0
    last_event: str = ""
    started_at: float | None = None
    updated_at: float | None = None


class StageTransitionEntry(BaseModel):
    """Stage transition audit trail entry."""

    stage: str
    status: str
    timestamp: float
    message: str = ""


class SkippedStageEntry(BaseModel):
    """Skipped stage reason entry."""

    stage: str
    reason: str = ""


class DropOffStats(BaseModel):
    """Drop-off tracking stats between stages."""

    input: int = 0
    kept: int = 0
    dropped: int = 0


class DeduplicationStats(BaseModel):
    """Duplicate removal statistics."""

    removed: int = 0
    remaining: int = 0


class TargetProgressStats(BaseModel):
    """Per-target queue/scanning/done progress counters."""

    queued: int = 0
    scanning: int = 0
    done: int = 0


class ProgressTelemetry(BaseModel):
    """Rich progress telemetry surfaced to dashboard clients."""

    active_task_count: int = 0
    requests_per_second: float | None = None
    throughput_per_second: float | None = None
    eta_seconds: float | None = None
    high_value_target_count: int = 0
    vulnerability_likelihood_score: float | None = None
    signal_noise_ratio: float | None = None
    confidence_score: float | None = None
    drop_off: DropOffStats | None = None
    deduplication: DeduplicationStats | None = None
    targets: TargetProgressStats = Field(default_factory=TargetProgressStats)
    retry_count: int = 0
    failure_count: int = 0
    stage_transitions: list[StageTransitionEntry] = Field(default_factory=list)
    event_triggers: list[str] = Field(default_factory=list)
    skipped_stages: list[SkippedStageEntry] = Field(default_factory=list)
    top_active_targets: list[str] = Field(default_factory=list)
    bottleneck_stage: str = ""
    bottleneck_seconds: float | None = None
    next_best_action: str = ""
    learning_feedback: dict[str, Any] | str | None = None
    last_update_epoch: float | None = None


class JobResponse(BaseModel):
    """Single job response."""

    id: str
    base_url: str
    hostname: str
    scope_entries: list[str]
    enabled_modules: list[str]
    mode: str
    target_name: str
    status: str
    stage: str
    stage_label: str
    status_message: str
    failed_stage: str = ""
    failure_reason_code: str = ""
    failure_step: str = ""
    failure_reason: str = ""
    progress_percent: int
    started_at: str
    started_at_label: str | None = None
    updated_at_label: str | None = None
    finished_at_label: str | None = None
    returncode: int | None = None
    error: str = ""
    warnings: list[str]
    execution_options: dict[str, bool]
    can_stop: bool
    latest_logs: list[str]
    config_href: str
    scope_href: str
    stdout_href: str
    stderr_href: str
    target_href: str
    elapsed_seconds: float | None = None
    elapsed_label: str | None = None
    eta_label: str | None = None
    has_eta: bool = False
    last_update_label: str | None = None
    stalled: bool = False
    stage_progress_label: str | None = None
    stage_progress: list[StageProgressEntry] = Field(default_factory=list)
    progress_telemetry: ProgressTelemetry = Field(default_factory=ProgressTelemetry)
    concurrent_stage_count: int = 0


class JobListResponse(BaseModel):
    """List of jobs response."""

    jobs: list[JobResponse]
    total: int = 0


class JobLogsResponse(BaseModel):
    """Job logs response."""

    job_id: str
    logs: list[str]
    total_logs: int = 0
    status: str | None = None


class TargetInfo(BaseModel):
    """Target summary information."""

    name: str
    href: str = ""
    latest_run: str | None = None
    latest_generated_at: str = ""
    latest_report_href: str = ""
    priority_url_count: int = 0
    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    validated_leads: int = 0
    url_count: int = 0
    parameter_count: int = 0
    new_findings: int = 0
    attack_chain_count: int = 0
    max_attack_chain_confidence: float = 0.0
    validation_plan_count: int = 0
    top_finding_title: str = ""
    top_finding_severity: str = ""
    top_finding_url: str = ""
    run_count: int = 0
    last_scan: str | None = None


class TargetListResponse(BaseModel):
    """List of targets response."""

    targets: list[TargetInfo]
    total: int = 0


class FindingResponse(BaseModel):
    """Single finding response."""

    id: str = ""
    url: str
    severity: str
    score: float
    title: str
    description: str
    module: str
    timestamp: str | None = None
    lifecycle_state: str = "detected"
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskScoreResponse(BaseModel):
    """Risk score response."""

    target: str
    aggregate_score: float
    severity: str
    total_findings: int
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    timestamp: str = ""


class HistoricalScoreEntry(BaseModel):
    """Single historical score entry."""

    score: float
    severity: str
    timestamp: str
    findings: list[dict[str, Any]] = Field(default_factory=list)


class HistoricalScoreResponse(BaseModel):
    """Historical scores response."""

    target: str
    endpoints: dict[str, dict[str, Any]] = Field(default_factory=dict)
    runs_analyzed: int = 0


class NoteCreateRequest(StrictRequestModel):
    """Request body for creating a note."""

    finding_id: str = Field(..., min_length=1)
    note: str = Field(..., min_length=1, max_length=10000)
    tags: list[str] = Field(default_factory=list)
    author: str = Field(default="")
    graph_node_id: str | None = Field(default=None)
    graph_edge_id: str | None = Field(default=None)
    exchange_id: str | None = Field(default=None)


class NoteUpdateRequest(StrictRequestModel):
    """Request body for updating a note."""

    finding_id: str = Field(..., min_length=1)
    note: str | None = None
    tags: list[str] | None = None
    graph_node_id: str | None = Field(default=None)
    graph_edge_id: str | None = Field(default=None)
    exchange_id: str | None = Field(default=None)


class NoteResponse(BaseModel):
    """Single note response."""

    note_id: str
    finding_id: str
    note: str
    tags: list[str]
    author: str
    created_at: str
    updated_at: str
    graph_node_id: str | None = None
    graph_edge_id: str | None = None
    exchange_id: str | None = None


class NoteListResponse(BaseModel):
    """List of notes response."""

    notes: list[NoteResponse]
    target: str = ""
    count: int = 0


class CacheStatsResponse(BaseModel):
    """Cache statistics response."""

    total_entries: int
    active_entries: int
    expired_entries: int
    total_size_bytes: int
    namespaces: dict[str, int] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    backend_type: str = ""
    l1_entries: int = 0
    l2_entries: int = 0
    l3_entries: int = 0


class RedisCacheOverview(BaseModel):
    """Redis cache status and runtime counters."""

    connected: bool = False
    keys_count: int = 0
    used_memory_human: str = "0 B"
    used_memory_bytes: int = 0
    max_memory_bytes: int | None = None
    hit_rate: float | None = None
    miss_rate: float | None = None
    connected_clients: int = 0
    error: str | None = None


class SQLiteCacheOverview(BaseModel):
    """SQLite cache file and query status."""

    connected: bool = False
    db_path: str = ""
    file_size_mb: float = 0.0
    query_count: int = 0
    entry_count: int = 0
    cache_hit_ratio: float | None = None
    error: str | None = None


class CacheStatusResponse(BaseModel):
    """Combined cache introspection response."""

    redis: RedisCacheOverview
    sqlite: SQLiteCacheOverview


class CacheKeyInfo(BaseModel):
    """Redis key metadata for key explorer views."""

    key: str
    ttl: int | None = None
    size: int | None = None
    type: str | None = None


class CacheKeysResponse(BaseModel):
    """Redis key listing response."""

    pattern: str
    limit: int
    count: int = 0
    truncated: bool = False
    connected: bool = False
    keys: list[CacheKeyInfo] = Field(default_factory=list)
    error: str | None = None


class CacheKeyDeleteRequest(StrictRequestModel):
    """Request body for deleting Redis keys by pattern."""

    pattern: str = Field(..., min_length=1, max_length=512)


class CacheKeyDeleteResponse(BaseModel):
    """Redis key deletion response."""

    pattern: str
    matched: int = 0
    deleted: int = 0
    connected: bool = False
    error: str | None = None


class CachePerformancePoint(BaseModel):
    """Single sampled cache performance point."""

    timestamp: str
    epoch: float
    hit_rate: float | None = None
    miss_rate: float | None = None
    redis_hit_rate: float | None = None
    redis_miss_rate: float | None = None
    local_hit_rate: float | None = None
    local_miss_rate: float | None = None


class CachePerformanceHistoryResponse(BaseModel):
    """Rolling one-hour cache performance history."""

    points: list[CachePerformancePoint] = Field(default_factory=list)


class CacheCleanupResponse(BaseModel):
    """Cache cleanup response."""

    cleaned: int
    duration_seconds: float


class TimelineEntry(BaseModel):
    """Single timeline entry."""

    timestamp: str
    severity: str
    url: str
    title: str
    module: str = ""


class TimelineResponse(BaseModel):
    """Timeline response."""

    target: str = ""
    timeline: list[TimelineEntry]
    count: int = 0


class ReplayResponse(BaseModel):
    """Replay result response."""

    replay_id: str
    auth_mode: str
    applied_header_names: list[str]
    requested_url: str
    final_url: str
    redirect_chain: list[str] = Field(default_factory=list)
    status_code: int | None = None
    body_similarity: float | None = None
    status_changed: bool | None = None
    redirect_changed: bool | None = None
    content_changed: bool | None = None


class RegistryModuleOptions(BaseModel):
    """Module options registry."""

    options: list[dict[str, Any]] = Field(default_factory=list)
    groups: list[dict[str, Any]] = Field(default_factory=list)


class RegistryAnalysisOptions(BaseModel):
    """Analysis check options registry."""

    check_options: list[dict[str, Any]] = Field(default_factory=list)
    control_groups: list[dict[str, Any]] = Field(default_factory=list)
    focus_presets: list[dict[str, Any]] = Field(default_factory=list)


class RegistryModePresets(BaseModel):
    """Mode presets registry."""

    presets: list[dict[str, Any]] = Field(default_factory=list)
    stage_labels: dict[str, str] = Field(default_factory=dict)


class RegistryResponse(BaseModel):
    """Combined registry response."""

    modules: RegistryModuleOptions
    analysis: RegistryAnalysisOptions
    modes: RegistryModePresets


class DashboardStatsResponse(BaseModel):
    """Dashboard statistics response."""

    active_jobs: int
    completed_jobs: int
    failed_jobs: int
    completed_targets: int
    total_findings: int
    total_targets: int
    avg_progress: int
    stage_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    pipeline_health_score: int
    pipeline_health_label: str
    trend_data: list[int] = Field(default_factory=list)
    findings_summary: dict[str, Any] = Field(default_factory=dict)
    mesh_health: dict[str, Any] = Field(default_factory=dict)


class DefaultsResponse(BaseModel):
    """API defaults response."""

    form_defaults: dict[str, str] = Field(default_factory=dict)
    default_mode: str = ""
    config_template: dict[str, Any] = Field(default_factory=dict)


class FindingsSummaryResponse(BaseModel):
    """Findings summary response."""

    total_findings: int
    severity_totals: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_module: dict[str, int] = Field(default_factory=dict)
    targets: list[dict[str, Any]] = Field(default_factory=list)
    targets_with_findings: int = 0
    total_targets: int = 0


class GapAnalysisEntry(BaseModel):
    """Entry for detection gap analysis."""

    module: str
    category: str
    total_checks: int
    covered_checks: int
    missing_checks: int
    coverage_percent: int
    status: str


class DetectionGapResponse(BaseModel):
    """Detection gap response."""

    target: str | None = None
    results: list[GapAnalysisEntry] = Field(default_factory=list)
    overall_coverage: int = 0
    total_modules: int = 0
    modules_with_gaps: int = 0


class CacheNamespaceResponse(BaseModel):
    """Cache namespace invalidation response."""

    cleared: int = 0
    namespace: str = ""


class NoteDeleteResponse(BaseModel):
    """Note deletion response."""

    deleted: bool = False
    note_id: str = ""


class TokenRequest(StrictRequestModel):
    """Request body for dashboard token exchange."""

    api_key: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """Short-lived dashboard token response."""

    access_token: str
    token_type: str = "bearer"  # nosec: S105
    expires_in: int
    role: str


class APIKeyCreateRequest(StrictRequestModel):
    """Request body for generating an API key."""

    role: str = Field(..., pattern="^(read_only|worker|admin)$")


class APIKeyResponse(BaseModel):
    """Masked API key inventory item."""

    id: str
    masked_key: str
    role: str
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None
    active: bool = True


class APIKeyCreateResponse(APIKeyResponse):
    """Generated API key response. The raw key is returned once."""

    api_key: str


class SecurityEventResponse(BaseModel):
    """Security event log entry."""

    id: int
    timestamp: str
    event_type: str
    status_code: int | None = None
    method: str | None = None
    path: str | None = None
    client_ip: str | None = None
    api_key_id: str | None = None
    detail: str = ""


class RateLimitBucketResponse(BaseModel):
    """Current request-rate telemetry for an endpoint."""

    endpoint: str
    requests_per_second: float
    recent_count: int
    limit_per_second: int | None = None


class RateLimitStatusResponse(BaseModel):
    """Rate-limit telemetry response."""

    enabled: bool
    buckets: list[RateLimitBucketResponse] = Field(default_factory=list)


class CSPReportResponse(BaseModel):
    """Persisted CSP report."""

    id: int
    timestamp: str
    client_ip: str | None = None
    user_agent: str = ""
    report: dict[str, Any] = Field(default_factory=dict)
