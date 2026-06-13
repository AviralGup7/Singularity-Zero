# API Reference (Machine-Readable)

This document provides the OpenAPI 3.1.0 specification for the Cyber Security Test Pipeline, enriched with AI metadata for autonomous agent orchestration.

---

## 🔒 Global Security & Governance Headers

All endpoints in the dashboard API support dynamic tenant-isolation and state-altering anti-CSRF checks:

### 1. Multi-Tenant Isolation (`X-Tenant-ID` Header)
- **Header**: `X-Tenant-ID: <tenant_identifier>` (Optional, defaults to `default`)
- **Usage**: Scopes Redis and SQLite operations to separate namespace boundaries. Users are restricted to retrieving targets, findings, and logs associated with their active tenant boundaries.

### 2. Double-Submit Cookie Anti-CSRF (`X-CSRF-Token` Header & `csrf_token` Cookie)
- **Applicability**: Required on all mutating requests (`POST`, `PUT`, `DELETE`, `PATCH`).
- **Mechanism**: Enforces the stateless double-submit cookie verification. The client must read the random token from the `csrf_token` cookie (set on safe `GET` requests) and transmit it via the `X-CSRF-Token` request header.
- **Exemptions**: Integrations using bearer authorization (`Authorization: Bearer <jwt>`) or absolute API keys (`X-API-Key`) are exempt from browser session CSRF checks.

---

```yaml
components:
  schemas:
    APIKeyCreateRequest:
      additionalProperties: false
      description: Request body for generating an API key.
      properties:
        role:
          pattern: ^(viewer|operator|admin)$
          title: Role
          type: string
      required:
      - role
      title: APIKeyCreateRequest
      type: object
    APIKeyCreateResponse:
      description: Generated API key response. The raw key is returned once.
      properties:
        active:
          default: true
          title: Active
          type: boolean
        api_key:
          title: Api Key
          type: string
        created_at:
          title: Created At
          type: string
        id:
          title: Id
          type: string
        last_used_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Used At
        masked_key:
          title: Masked Key
          type: string
        revoked_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Revoked At
        role:
          title: Role
          type: string
      required:
      - id
      - masked_key
      - role
      - created_at
      - api_key
      title: APIKeyCreateResponse
      type: object
    APIKeyResponse:
      description: Masked API key inventory item.
      properties:
        active:
          default: true
          title: Active
          type: boolean
        created_at:
          title: Created At
          type: string
        id:
          title: Id
          type: string
        last_used_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Used At
        masked_key:
          title: Masked Key
          type: string
        revoked_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Revoked At
        role:
          title: Role
          type: string
      required:
      - id
      - masked_key
      - role
      - created_at
      title: APIKeyResponse
      type: object
    AccessLogCreateRequest:
      description: Body for creating a new access-log entry.
      properties:
        action:
          title: Action
          type: string
        details:
          additionalProperties: true
          title: Details
          type: object
        outcome:
          default: success
          title: Outcome
          type: string
        reason:
          default: ''
          title: Reason
          type: string
        resource:
          title: Resource
          type: string
        user:
          default: anonymous
          title: User
          type: string
      required:
      - action
      - resource
      title: AccessLogCreateRequest
      type: object
    ApiDefaults:
      properties:
        default_mode:
          title: Default Mode
          type: string
        form_defaults:
          additionalProperties:
            type: string
          title: Form Defaults
          type: object
      required:
      - default_mode
      - form_defaults
      title: ApiDefaults
      type: object
    Body_import_semgrep_api_imports_semgrep_post:
      properties:
        file:
          anyOf:
          - contentMediaType: application/octet-stream
            type: string
          - type: 'null'
          description: Semgrep JSON file (multipart/form-data)
          title: File
      title: Body_import_semgrep_api_imports_semgrep_post
      type: object
    CSPReportResponse:
      description: Persisted CSP report.
      properties:
        client_ip:
          anyOf:
          - type: string
          - type: 'null'
          title: Client Ip
        id:
          title: Id
          type: integer
        report:
          additionalProperties: true
          title: Report
          type: object
        timestamp:
          title: Timestamp
          type: string
        user_agent:
          default: ''
          title: User Agent
          type: string
      required:
      - id
      - timestamp
      title: CSPReportResponse
      type: object
    CacheCleanupResponse:
      description: Cache cleanup response.
      properties:
        cleaned:
          title: Cleaned
          type: integer
        duration_seconds:
          title: Duration Seconds
          type: number
      required:
      - cleaned
      - duration_seconds
      title: CacheCleanupResponse
      type: object
    CacheKeyDeleteRequest:
      additionalProperties: false
      description: Request body for deleting Redis keys by pattern.
      properties:
        pattern:
          maxLength: 512
          minLength: 1
          title: Pattern
          type: string
      required:
      - pattern
      title: CacheKeyDeleteRequest
      type: object
    CacheKeyDeleteResponse:
      description: Redis key deletion response.
      properties:
        connected:
          default: false
          title: Connected
          type: boolean
        deleted:
          default: 0
          title: Deleted
          type: integer
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
        matched:
          default: 0
          title: Matched
          type: integer
        pattern:
          title: Pattern
          type: string
      required:
      - pattern
      title: CacheKeyDeleteResponse
      type: object
    CacheKeyInfo:
      description: Redis key metadata for key explorer views.
      properties:
        key:
          title: Key
          type: string
        size:
          anyOf:
          - type: integer
          - type: 'null'
          title: Size
        ttl:
          anyOf:
          - type: integer
          - type: 'null'
          title: Ttl
        type:
          anyOf:
          - type: string
          - type: 'null'
          title: Type
      required:
      - key
      title: CacheKeyInfo
      type: object
    CacheKeysResponse:
      description: Redis key listing response.
      properties:
        connected:
          default: false
          title: Connected
          type: boolean
        count:
          default: 0
          title: Count
          type: integer
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
        keys:
          items:
            $ref: '#/components/schemas/CacheKeyInfo'
          title: Keys
          type: array
        limit:
          title: Limit
          type: integer
        pattern:
          title: Pattern
          type: string
        truncated:
          default: false
          title: Truncated
          type: boolean
      required:
      - pattern
      - limit
      title: CacheKeysResponse
      type: object
    CacheNamespaceResponse:
      description: Cache namespace invalidation response.
      properties:
        cleared:
          default: 0
          title: Cleared
          type: integer
        namespace:
          default: ''
          title: Namespace
          type: string
      title: CacheNamespaceResponse
      type: object
    CachePerformanceHistoryResponse:
      description: Rolling one-hour cache performance history.
      properties:
        points:
          items:
            $ref: '#/components/schemas/CachePerformancePoint'
          title: Points
          type: array
      title: CachePerformanceHistoryResponse
      type: object
    CachePerformancePoint:
      description: Single sampled cache performance point.
      properties:
        epoch:
          title: Epoch
          type: number
        hit_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Hit Rate
        local_hit_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Local Hit Rate
        local_miss_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Local Miss Rate
        miss_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Miss Rate
        redis_hit_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Redis Hit Rate
        redis_miss_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Redis Miss Rate
        timestamp:
          title: Timestamp
          type: string
      required:
      - timestamp
      - epoch
      title: CachePerformancePoint
      type: object
    CacheStatsResponse:
      description: Cache statistics response.
      properties:
        active_entries:
          title: Active Entries
          type: integer
        backend_type:
          default: ''
          title: Backend Type
          type: string
        expired_entries:
          title: Expired Entries
          type: integer
        l1_entries:
          default: 0
          title: L1 Entries
          type: integer
        l2_entries:
          default: 0
          title: L2 Entries
          type: integer
        l3_entries:
          default: 0
          title: L3 Entries
          type: integer
        metrics:
          additionalProperties: true
          title: Metrics
          type: object
        namespaces:
          additionalProperties:
            type: integer
          title: Namespaces
          type: object
        total_entries:
          title: Total Entries
          type: integer
        total_size_bytes:
          title: Total Size Bytes
          type: integer
      required:
      - total_entries
      - active_entries
      - expired_entries
      - total_size_bytes
      title: CacheStatsResponse
      type: object
    CacheStatusResponse:
      description: Combined cache introspection response.
      properties:
        redis:
          $ref: '#/components/schemas/RedisCacheOverview'
        sqlite:
          $ref: '#/components/schemas/SQLiteCacheOverview'
      required:
      - redis
      - sqlite
      title: CacheStatusResponse
      type: object
    DashboardStatsResponse:
      description: Dashboard statistics response.
      properties:
        active_jobs:
          title: Active Jobs
          type: integer
        avg_progress:
          title: Avg Progress
          type: integer
        completed_jobs:
          title: Completed Jobs
          type: integer
        completed_targets:
          title: Completed Targets
          type: integer
        failed_jobs:
          title: Failed Jobs
          type: integer
        pipeline_health_label:
          title: Pipeline Health Label
          type: string
        pipeline_health_score:
          title: Pipeline Health Score
          type: integer
        severity_counts:
          additionalProperties:
            type: integer
          title: Severity Counts
          type: object
        stage_counts:
          additionalProperties:
            type: integer
          title: Stage Counts
          type: object
        total_findings:
          title: Total Findings
          type: integer
        total_targets:
          title: Total Targets
          type: integer
      required:
      - active_jobs
      - completed_jobs
      - failed_jobs
      - completed_targets
      - total_findings
      - total_targets
      - avg_progress
      - pipeline_health_score
      - pipeline_health_label
      title: DashboardStatsResponse
      type: object
    DeduplicationStats:
      description: Duplicate removal statistics.
      properties:
        remaining:
          default: 0
          title: Remaining
          type: integer
        removed:
          default: 0
          title: Removed
          type: integer
      title: DeduplicationStats
      type: object
    DeleteResponse:
      properties:
        deleted:
          title: Deleted
          type: integer
        success:
          title: Success
          type: boolean
      required:
      - success
      - deleted
      title: DeleteResponse
      type: object
    DetectionGapResponse:
      description: Detection gap response.
      properties:
        modules_with_gaps:
          default: 0
          title: Modules With Gaps
          type: integer
        overall_coverage:
          default: 0
          title: Overall Coverage
          type: integer
        results:
          items:
            $ref: '#/components/schemas/GapAnalysisEntry'
          title: Results
          type: array
        target:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
        total_modules:
          default: 0
          title: Total Modules
          type: integer
      title: DetectionGapResponse
      type: object
    DropOffStats:
      description: Drop-off tracking stats between stages.
      properties:
        dropped:
          default: 0
          title: Dropped
          type: integer
        input:
          default: 0
          title: Input
          type: integer
        kept:
          default: 0
          title: Kept
          type: integer
      title: DropOffStats
      type: object
    ErrorResponse:
      description: Standard error response.
      properties:
        code:
          anyOf:
          - type: string
          - type: 'null'
          title: Code
        detail:
          anyOf:
          - type: string
          - type: 'null'
          title: Detail
        error:
          title: Error
          type: string
      required:
      - error
      title: ErrorResponse
      type: object
    EvidenceAccessRequest:
      description: Body for logging evidence access.
      properties:
        details:
          default: Evidence accessed for review
          title: Details
          type: string
        user:
          default: anonymous
          title: User
          type: string
      title: EvidenceAccessRequest
      type: object
    EvidenceCreateRequest:
      description: Body for creating an evidence record.
      properties:
        data:
          title: Data
          type: string
        finding_id:
          title: Finding Id
          type: string
        user:
          default: anonymous
          title: User
          type: string
      required:
      - finding_id
      - data
      title: EvidenceCreateRequest
      type: object
    EvidenceModifyRequest:
      description: Body for modifying evidence data.
      properties:
        details:
          default: Evidence modified
          title: Details
          type: string
        new_data:
          title: New Data
          type: string
        user:
          default: anonymous
          title: User
          type: string
      required:
      - new_data
      title: EvidenceModifyRequest
      type: object
    FeedbackEventEntry:
      description: FastAPI response schema for feedback events.
      properties:
        endpoint_type:
          anyOf:
          - type: string
          - type: 'null'
          title: Endpoint Type
        event_id:
          title: Event Id
          type: string
        feedback_weight:
          anyOf:
          - type: number
          - type: 'null'
          title: Feedback Weight
        finding_category:
          title: Finding Category
          type: string
        finding_confidence:
          anyOf:
          - type: number
          - type: 'null'
          title: Finding Confidence
        finding_decision:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Decision
        finding_severity:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Severity
        parameter_name:
          anyOf:
          - type: string
          - type: 'null'
          title: Parameter Name
        parameter_type:
          anyOf:
          - type: string
          - type: 'null'
          title: Parameter Type
        plugin_name:
          anyOf:
          - type: string
          - type: 'null'
          title: Plugin Name
        response_delta_score:
          anyOf:
          - type: number
          - type: 'null'
          title: Response Delta Score
        run_id:
          title: Run Id
          type: string
        scan_mode:
          anyOf:
          - type: string
          - type: 'null'
          title: Scan Mode
        target_endpoint:
          title: Target Endpoint
          type: string
        target_host:
          title: Target Host
          type: string
        tech_stack:
          anyOf:
          - type: string
          - type: 'null'
          title: Tech Stack
        timestamp:
          title: Timestamp
          type: string
        validation_method:
          anyOf:
          - type: string
          - type: 'null'
          title: Validation Method
        was_false_positive:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Was False Positive
        was_validated:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Was Validated
      required:
      - event_id
      - run_id
      - timestamp
      - target_host
      - target_endpoint
      - finding_category
      title: FeedbackEventEntry
      type: object
    FindingsSummaryResponse:
      description: Findings summary response.
      properties:
        by_module:
          additionalProperties:
            type: integer
          title: By Module
          type: object
        by_severity:
          additionalProperties:
            type: integer
          title: By Severity
          type: object
        findings:
          items:
            additionalProperties: true
            type: object
          title: Findings
          type: array
        severity_totals:
          additionalProperties:
            type: integer
          title: Severity Totals
          type: object
        targets:
          items:
            additionalProperties: true
            type: object
          title: Targets
          type: array
        targets_with_findings:
          default: 0
          title: Targets With Findings
          type: integer
        total_findings:
          title: Total Findings
          type: integer
        total_targets:
          default: 0
          title: Total Targets
          type: integer
      required:
      - total_findings
      title: FindingsSummaryResponse
      type: object
    ForceOpenRequest:
      description: Body for the force-open tool circuit breaker endpoint.
      properties:
        duration_seconds:
          anyOf:
          - minimum: 0.0
            type: number
          - type: 'null'
          description: Optional fixed cool-down window. Defaults to the breaker's
            configured recovery_timeout when omitted. 0 = indefinite (stays OPEN until
            reset).
          title: Duration Seconds
        reason:
          default: dashboard-operator
          maxLength: 512
          title: Reason
          type: string
      title: ForceOpenRequest
      type: object
    FpPatternEntry:
      description: Learned false positive pattern entry.
      properties:
        body_pattern:
          anyOf:
          - type: string
          - type: 'null'
          title: Body Pattern
        category:
          title: Category
          type: string
        confidence:
          anyOf:
          - type: number
          - type: 'null'
          title: Confidence
        confirmed_fp_count:
          anyOf:
          - type: integer
          - type: 'null'
          title: Confirmed Fp Count
        confirmed_tp_count:
          anyOf:
          - type: integer
          - type: 'null'
          title: Confirmed Tp Count
        created_at:
          title: Created At
          type: string
        first_seen:
          title: First Seen
          type: string
        fp_probability:
          anyOf:
          - type: number
          - type: 'null'
          title: Fp Probability
        header_pattern:
          anyOf:
          - type: string
          - type: 'null'
          title: Header Pattern
        is_active:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Is Active
        last_seen:
          title: Last Seen
          type: string
        occurrence_count:
          anyOf:
          - type: integer
          - type: 'null'
          title: Occurrence Count
        pattern_id:
          title: Pattern Id
          type: string
        response_similarity:
          anyOf:
          - type: number
          - type: 'null'
          title: Response Similarity
        status_code_pattern:
          anyOf:
          - type: string
          - type: 'null'
          title: Status Code Pattern
        suppression_action:
          anyOf:
          - type: string
          - type: 'null'
          title: Suppression Action
        updated_at:
          title: Updated At
          type: string
      required:
      - pattern_id
      - category
      - first_seen
      - last_seen
      - created_at
      - updated_at
      title: FpPatternEntry
      type: object
    FrontendTelemetryEvent:
      properties:
        event_type:
          title: Event Type
          type: string
        payload:
          anyOf:
          - additionalProperties: true
            type: object
          - type: 'null'
          title: Payload
      required:
      - event_type
      title: FrontendTelemetryEvent
      type: object
    GapAnalysisEntry:
      description: Entry for detection gap analysis.
      properties:
        category:
          title: Category
          type: string
        coverage_percent:
          title: Coverage Percent
          type: integer
        covered_checks:
          title: Covered Checks
          type: integer
        missing_check_details:
          items:
            type: string
          title: Missing Check Details
          type: array
        missing_checks:
          title: Missing Checks
          type: integer
        module:
          title: Module
          type: string
        status:
          title: Status
          type: string
        total_checks:
          title: Total Checks
          type: integer
      required:
      - module
      - category
      - total_checks
      - covered_checks
      - missing_checks
      - coverage_percent
      - status
      title: GapAnalysisEntry
      type: object
    HTTPValidationError:
      properties:
        detail:
          items:
            $ref: '#/components/schemas/ValidationError'
          title: Detail
          type: array
      title: HTTPValidationError
      type: object
    HealthResponse:
      description: Health check response.
      properties:
        dependencies:
          additionalProperties: true
          title: Dependencies
          type: object
        mesh:
          items:
            $ref: '#/components/schemas/MeshNodeSchema'
          title: Mesh
          type: array
        status:
          title: Status
          type: string
        timestamp:
          title: Timestamp
          type: string
        uptime_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Uptime Seconds
        version:
          default: 2.0.0
          title: Version
          type: string
      required:
      - status
      - timestamp
      title: HealthResponse
      type: object
    HistoricalScoreResponse:
      description: Historical scores response.
      properties:
        endpoints:
          additionalProperties:
            additionalProperties: true
            type: object
          title: Endpoints
          type: object
        runs_analyzed:
          default: 0
          title: Runs Analyzed
          type: integer
        target:
          title: Target
          type: string
      required:
      - target
      title: HistoricalScoreResponse
      type: object
    HuntModeRequest:
      description: Body for the hunt-mode toggle endpoint.
      properties:
        actor:
          anyOf:
          - maxLength: 128
            type: string
          - type: 'null'
          title: Actor
        enabled:
          title: Enabled
          type: boolean
        reason:
          anyOf:
          - maxLength: 512
            type: string
          - type: 'null'
          title: Reason
      required:
      - enabled
      title: HuntModeRequest
      type: object
    JobCreateRequest:
      additionalProperties: false
      description: Request body for starting a new scan job.
      properties:
        base_url:
          description: Target base URL
          minLength: 1
          title: Base Url
          type: string
        execution_options:
          additionalProperties:
            type: boolean
          title: Execution Options
          type: object
        mode:
          default: idor
          description: Pipeline mode
          title: Mode
          type: string
        modules:
          anyOf:
          - items:
              type: string
            type: array
          - type: 'null'
          description: Selected module names
          title: Modules
        runtime_overrides:
          additionalProperties:
            type: string
          title: Runtime Overrides
          type: object
        scope_text:
          default: ''
          description: Additional scope entries
          title: Scope Text
          type: string
        target_name:
          default: ''
          description: Target name for output directory
          title: Target Name
          type: string
      required:
      - base_url
      title: JobCreateRequest
      type: object
    JobListResponse:
      description: List of jobs response.
      properties:
        jobs:
          items:
            $ref: '#/components/schemas/JobResponse'
          title: Jobs
          type: array
        total:
          default: 0
          title: Total
          type: integer
      required:
      - jobs
      title: JobListResponse
      type: object
    JobLogsResponse:
      description: Job logs response.
      properties:
        job_id:
          title: Job Id
          type: string
        logs:
          items:
            type: string
          title: Logs
          type: array
        status:
          anyOf:
          - type: string
          - type: 'null'
          title: Status
        total_logs:
          default: 0
          title: Total Logs
          type: integer
      required:
      - job_id
      - logs
      title: JobLogsResponse
      type: object
    JobResponse:
      description: Single job response.
      properties:
        base_url:
          title: Base Url
          type: string
        can_stop:
          title: Can Stop
          type: boolean
        concurrent_stage_count:
          default: 0
          title: Concurrent Stage Count
          type: integer
        config_href:
          title: Config Href
          type: string
        elapsed_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Elapsed Label
        elapsed_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Elapsed Seconds
        enabled_modules:
          items:
            type: string
          title: Enabled Modules
          type: array
        error:
          default: ''
          title: Error
          type: string
        eta_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Eta Label
        execution_options:
          additionalProperties:
            type: boolean
          title: Execution Options
          type: object
        failed_stage:
          default: ''
          title: Failed Stage
          type: string
        failure_reason:
          default: ''
          title: Failure Reason
          type: string
        failure_reason_code:
          default: ''
          title: Failure Reason Code
          type: string
        failure_step:
          default: ''
          title: Failure Step
          type: string
        finished_at_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Finished At Label
        has_eta:
          default: false
          title: Has Eta
          type: boolean
        hostname:
          title: Hostname
          type: string
        id:
          title: Id
          type: string
        last_update_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Update Label
        latest_logs:
          items:
            type: string
          title: Latest Logs
          type: array
        mode:
          title: Mode
          type: string
        progress_percent:
          title: Progress Percent
          type: integer
        progress_telemetry:
          $ref: '#/components/schemas/ProgressTelemetry'
        returncode:
          anyOf:
          - type: integer
          - type: 'null'
          title: Returncode
        scope_entries:
          items:
            type: string
          title: Scope Entries
          type: array
        scope_href:
          title: Scope Href
          type: string
        stage:
          title: Stage
          type: string
        stage_label:
          title: Stage Label
          type: string
        stage_progress:
          items:
            $ref: '#/components/schemas/StageProgressEntry'
          title: Stage Progress
          type: array
        stage_progress_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Stage Progress Label
        stalled:
          default: false
          title: Stalled
          type: boolean
        started_at:
          title: Started At
          type: string
        started_at_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Started At Label
        status:
          title: Status
          type: string
        status_message:
          title: Status Message
          type: string
        stderr_href:
          title: Stderr Href
          type: string
        stdout_href:
          title: Stdout Href
          type: string
        target_href:
          title: Target Href
          type: string
        target_name:
          title: Target Name
          type: string
        telemetry_events:
          items:
            $ref: '#/components/schemas/PipelineTelemetryEvent'
          title: Telemetry Events
          type: array
        updated_at_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Updated At Label
        warnings:
          items:
            type: string
          title: Warnings
          type: array
      required:
      - id
      - base_url
      - hostname
      - mode
      - target_name
      - status
      - stage
      - stage_label
      - status_message
      - progress_percent
      - started_at
      - can_stop
      - config_href
      - scope_href
      - stdout_href
      - stderr_href
      - target_href
      title: JobResponse
      type: object
    MarkReadResponse:
      properties:
        success:
          title: Success
          type: boolean
        unread_count:
          title: Unread Count
          type: integer
      required:
      - success
      - unread_count
      title: MarkReadResponse
      type: object
    MeshNodeSchema:
      description: Schema for distributed mesh node telemetry.
      properties:
        active_jobs:
          title: Active Jobs
          type: integer
        cpu_usage:
          title: Cpu Usage
          type: number
        host:
          title: Host
          type: string
        id:
          title: Id
          type: string
        last_seen:
          title: Last Seen
          type: number
        port:
          title: Port
          type: integer
        ram_available_mb:
          title: Ram Available Mb
          type: number
        status:
          title: Status
          type: string
      required:
      - id
      - host
      - port
      - status
      - cpu_usage
      - ram_available_mb
      - active_jobs
      - last_seen
      title: MeshNodeSchema
      type: object
    NoteCreateRequest:
      additionalProperties: false
      description: Request body for creating a note.
      properties:
        author:
          default: ''
          title: Author
          type: string
        exchange_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Exchange Id
        finding_id:
          minLength: 1
          title: Finding Id
          type: string
        graph_edge_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Edge Id
        graph_node_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Node Id
        note:
          maxLength: 10000
          minLength: 1
          title: Note
          type: string
        tags:
          items:
            type: string
          title: Tags
          type: array
      required:
      - finding_id
      - note
      title: NoteCreateRequest
      type: object
    NoteDeleteResponse:
      description: Note deletion response.
      properties:
        deleted:
          default: false
          title: Deleted
          type: boolean
        note_id:
          default: ''
          title: Note Id
          type: string
      title: NoteDeleteResponse
      type: object
    NoteListResponse:
      description: List of notes response.
      properties:
        count:
          default: 0
          title: Count
          type: integer
        notes:
          items:
            $ref: '#/components/schemas/NoteResponse'
          title: Notes
          type: array
        target:
          default: ''
          title: Target
          type: string
      required:
      - notes
      title: NoteListResponse
      type: object
    NoteResponse:
      description: Single note response.
      properties:
        author:
          title: Author
          type: string
        created_at:
          title: Created At
          type: string
        exchange_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Exchange Id
        finding_id:
          title: Finding Id
          type: string
        graph_edge_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Edge Id
        graph_node_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Node Id
        note:
          title: Note
          type: string
        note_id:
          title: Note Id
          type: string
        tags:
          items:
            type: string
          title: Tags
          type: array
        updated_at:
          title: Updated At
          type: string
      required:
      - note_id
      - finding_id
      - note
      - tags
      - author
      - created_at
      - updated_at
      title: NoteResponse
      type: object
    NoteUpdateRequest:
      additionalProperties: false
      description: Request body for updating a note.
      properties:
        exchange_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Exchange Id
        finding_id:
          minLength: 1
          title: Finding Id
          type: string
        graph_edge_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Edge Id
        graph_node_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Node Id
        note:
          anyOf:
          - type: string
          - type: 'null'
          title: Note
        tags:
          anyOf:
          - items:
              type: string
            type: array
          - type: 'null'
          title: Tags
      required:
      - finding_id
      title: NoteUpdateRequest
      type: object
    NotificationListResponse:
      properties:
        limit:
          title: Limit
          type: integer
        notifications:
          items:
            additionalProperties: true
            type: object
          title: Notifications
          type: array
        offset:
          title: Offset
          type: integer
        total:
          title: Total
          type: integer
        unread_count:
          title: Unread Count
          type: integer
      required:
      - notifications
      - total
      - unread_count
      - limit
      - offset
      title: NotificationListResponse
      type: object
    PipelineTelemetryEvent:
      description: Replayable structured event emitted by the pipeline.
      properties:
        artifact_id:
          default: ''
          title: Artifact Id
          type: string
        artifact_type:
          default: ''
          title: Artifact Type
          type: string
        check_id:
          default: ''
          title: Check Id
          type: string
        epoch:
          title: Epoch
          type: number
        event_id:
          title: Event Id
          type: string
        event_type:
          title: Event Type
          type: string
        finding_id:
          default: ''
          title: Finding Id
          type: string
        message:
          default: ''
          title: Message
          type: string
        metrics:
          additionalProperties: true
          title: Metrics
          type: object
        parent_id:
          default: ''
          title: Parent Id
          type: string
        payload:
          additionalProperties: true
          title: Payload
          type: object
        run_id:
          default: ''
          title: Run Id
          type: string
        schema_version:
          default: telemetry.v2
          title: Schema Version
          type: string
        sequence:
          default: 0
          title: Sequence
          type: integer
        severity:
          default: ''
          title: Severity
          type: string
        source:
          default: ''
          title: Source
          type: string
        stage:
          title: Stage
          type: string
        status:
          title: Status
          type: string
        target:
          default: ''
          title: Target
          type: string
        timestamp:
          title: Timestamp
          type: string
        trace_id:
          default: ''
          title: Trace Id
          type: string
      required:
      - event_id
      - event_type
      - timestamp
      - epoch
      - stage
      - status
      title: PipelineTelemetryEvent
      type: object
    ProgressTelemetry:
      description: Rich progress telemetry surfaced to dashboard clients.
      properties:
        active_task_count:
          default: 0
          title: Active Task Count
          type: integer
        artifact_counts:
          additionalProperties:
            type: integer
          title: Artifact Counts
          type: object
        bottleneck_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Bottleneck Seconds
        bottleneck_stage:
          default: ''
          title: Bottleneck Stage
          type: string
        confidence_score:
          anyOf:
          - type: number
          - type: 'null'
          title: Confidence Score
        deduplication:
          anyOf:
          - $ref: '#/components/schemas/DeduplicationStats'
          - type: 'null'
        drop_off:
          anyOf:
          - $ref: '#/components/schemas/DropOffStats'
          - type: 'null'
        eta_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Eta Seconds
        event_counts:
          additionalProperties:
            type: integer
          title: Event Counts
          type: object
        event_triggers:
          items:
            type: string
          title: Event Triggers
          type: array
        failure_count:
          default: 0
          title: Failure Count
          type: integer
        high_value_target_count:
          default: 0
          title: High Value Target Count
          type: integer
        last_update_epoch:
          anyOf:
          - type: number
          - type: 'null'
          title: Last Update Epoch
        learning_feedback:
          anyOf:
          - additionalProperties: true
            type: object
          - type: string
          - type: 'null'
          title: Learning Feedback
        next_best_action:
          default: ''
          title: Next Best Action
          type: string
        requests_per_second:
          anyOf:
          - type: number
          - type: 'null'
          title: Requests Per Second
        retry_count:
          default: 0
          title: Retry Count
          type: integer
        signal_noise_ratio:
          anyOf:
          - type: number
          - type: 'null'
          title: Signal Noise Ratio
        skipped_stages:
          items:
            $ref: '#/components/schemas/SkippedStageEntry'
          title: Skipped Stages
          type: array
        stage_transitions:
          items:
            $ref: '#/components/schemas/StageTransitionEntry'
          title: Stage Transitions
          type: array
        targets:
          $ref: '#/components/schemas/TargetProgressStats'
        throughput_per_second:
          anyOf:
          - type: number
          - type: 'null'
          title: Throughput Per Second
        top_active_targets:
          items:
            type: string
          title: Top Active Targets
          type: array
        vulnerability_likelihood_score:
          anyOf:
          - type: number
          - type: 'null'
          title: Vulnerability Likelihood Score
      title: ProgressTelemetry
      type: object
    RateLimitBucketResponse:
      description: Current request-rate telemetry for an endpoint.
      properties:
        endpoint:
          title: Endpoint
          type: string
        limit_per_second:
          anyOf:
          - type: integer
          - type: 'null'
          title: Limit Per Second
        recent_count:
          title: Recent Count
          type: integer
        requests_per_second:
          title: Requests Per Second
          type: number
      required:
      - endpoint
      - requests_per_second
      - recent_count
      title: RateLimitBucketResponse
      type: object
    RateLimitStatusResponse:
      description: Rate-limit telemetry response.
      properties:
        buckets:
          items:
            $ref: '#/components/schemas/RateLimitBucketResponse'
          title: Buckets
          type: array
        enabled:
          title: Enabled
          type: boolean
      required:
      - enabled
      title: RateLimitStatusResponse
      type: object
    RedisCacheOverview:
      description: Redis cache status and runtime counters.
      properties:
        connected:
          default: false
          title: Connected
          type: boolean
        connected_clients:
          default: 0
          title: Connected Clients
          type: integer
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
        hit_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Hit Rate
        keys_count:
          default: 0
          title: Keys Count
          type: integer
        max_memory_bytes:
          anyOf:
          - type: integer
          - type: 'null'
          title: Max Memory Bytes
        miss_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Miss Rate
        used_memory_bytes:
          default: 0
          title: Used Memory Bytes
          type: integer
        used_memory_human:
          default: 0 B
          title: Used Memory Human
          type: string
      title: RedisCacheOverview
      type: object
    RegistryAnalysisOptions:
      description: Analysis check options registry.
      properties:
        check_options:
          items:
            additionalProperties: true
            type: object
          title: Check Options
          type: array
        control_groups:
          items:
            additionalProperties: true
            type: object
          title: Control Groups
          type: array
        dynamic_plugins:
          items:
            additionalProperties: true
            type: object
          title: Dynamic Plugins
          type: array
        focus_presets:
          items:
            additionalProperties: true
            type: object
          title: Focus Presets
          type: array
        invalid_dynamic_plugins:
          items:
            additionalProperties: true
            type: object
          title: Invalid Dynamic Plugins
          type: array
      title: RegistryAnalysisOptions
      type: object
    RegistryModePresets:
      description: Mode presets registry.
      properties:
        presets:
          items:
            additionalProperties: true
            type: object
          title: Presets
          type: array
        stage_labels:
          additionalProperties:
            type: string
          title: Stage Labels
          type: object
      title: RegistryModePresets
      type: object
    RegistryModuleOptions:
      description: Module options registry.
      properties:
        groups:
          items:
            additionalProperties: true
            type: object
          title: Groups
          type: array
        options:
          items:
            additionalProperties: true
            type: object
          title: Options
          type: array
      title: RegistryModuleOptions
      type: object
    RegistryResponse:
      description: Combined registry response.
      properties:
        analysis:
          $ref: '#/components/schemas/RegistryAnalysisOptions'
        capabilities:
          additionalProperties: true
          title: Capabilities
          type: object
        modes:
          $ref: '#/components/schemas/RegistryModePresets'
        modules:
          $ref: '#/components/schemas/RegistryModuleOptions'
      required:
      - modules
      - analysis
      - modes
      title: RegistryResponse
      type: object
    ReplayResponse:
      description: Replay result response.
      properties:
        applied_header_names:
          items:
            type: string
          title: Applied Header Names
          type: array
        auth_mode:
          title: Auth Mode
          type: string
        body_similarity:
          anyOf:
          - type: number
          - type: 'null'
          title: Body Similarity
        content_changed:
          anyOf:
          - type: boolean
          - type: 'null'
          title: Content Changed
        final_url:
          title: Final Url
          type: string
        redirect_chain:
          items:
            type: string
          title: Redirect Chain
          type: array
        redirect_changed:
          anyOf:
          - type: boolean
          - type: 'null'
          title: Redirect Changed
        replay_id:
          title: Replay Id
          type: string
        requested_url:
          title: Requested Url
          type: string
        status_changed:
          anyOf:
          - type: boolean
          - type: 'null'
          title: Status Changed
        status_code:
          anyOf:
          - type: integer
          - type: 'null'
          title: Status Code
      required:
      - replay_id
      - auth_mode
      - applied_header_names
      - requested_url
      - final_url
      title: ReplayResponse
      type: object
    RiskScoreResponse:
      description: Risk score response.
      properties:
        aggregate_score:
          title: Aggregate Score
          type: number
        severity:
          title: Severity
          type: string
        severity_breakdown:
          additionalProperties:
            type: integer
          title: Severity Breakdown
          type: object
        target:
          title: Target
          type: string
        timestamp:
          default: ''
          title: Timestamp
          type: string
        total_findings:
          title: Total Findings
          type: integer
      required:
      - target
      - aggregate_score
      - severity
      - total_findings
      title: RiskScoreResponse
      type: object
    SQLiteCacheOverview:
      description: SQLite cache file and query status.
      properties:
        cache_hit_ratio:
          anyOf:
          - type: number
          - type: 'null'
          title: Cache Hit Ratio
        connected:
          default: false
          title: Connected
          type: boolean
        db_path:
          default: ''
          title: Db Path
          type: string
        entry_count:
          default: 0
          title: Entry Count
          type: integer
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
        file_size_mb:
          default: 0.0
          title: File Size Mb
          type: number
        query_count:
          default: 0
          title: Query Count
          type: integer
      title: SQLiteCacheOverview
      type: object
    SandboxLaunchRequest:
      properties:
        image:
          default: ubuntu:latest
          title: Image
          type: string
        target_node:
          title: Target Node
          type: string
      required:
      - target_node
      title: SandboxLaunchRequest
      type: object
    SecurityEventResponse:
      description: Security event log entry.
      properties:
        api_key_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Api Key Id
        client_ip:
          anyOf:
          - type: string
          - type: 'null'
          title: Client Ip
        detail:
          default: ''
          title: Detail
          type: string
        event_type:
          title: Event Type
          type: string
        id:
          title: Id
          type: integer
        method:
          anyOf:
          - type: string
          - type: 'null'
          title: Method
        path:
          anyOf:
          - type: string
          - type: 'null'
          title: Path
        status_code:
          anyOf:
          - type: integer
          - type: 'null'
          title: Status Code
        timestamp:
          title: Timestamp
          type: string
      required:
      - id
      - timestamp
      - event_type
      title: SecurityEventResponse
      type: object
    SkippedStageEntry:
      description: Skipped stage reason entry.
      properties:
        reason:
          default: ''
          title: Reason
          type: string
        stage:
          title: Stage
          type: string
      required:
      - stage
      title: SkippedStageEntry
      type: object
    SlackTestRequest:
      properties:
        channel:
          default: '#security-alerts'
          description: The Slack channel to post to
          title: Channel
          type: string
        url:
          description: The Slack Incoming Webhook URL
          title: Url
          type: string
      required:
      - url
      title: SlackTestRequest
      type: object
    StageProgressEntry:
      description: Per-stage progress status entry.
      properties:
        error:
          default: ''
          title: Error
          type: string
        last_event:
          default: ''
          title: Last Event
          type: string
        percent:
          default: 0
          title: Percent
          type: integer
        processed:
          default: 0
          title: Processed
          type: integer
        reason:
          default: ''
          title: Reason
          type: string
        retry_count:
          default: 0
          title: Retry Count
          type: integer
        stage:
          title: Stage
          type: string
        stage_label:
          title: Stage Label
          type: string
        started_at:
          anyOf:
          - type: number
          - type: 'null'
          title: Started At
        status:
          title: Status
          type: string
        total:
          anyOf:
          - type: integer
          - type: 'null'
          title: Total
        updated_at:
          anyOf:
          - type: number
          - type: 'null'
          title: Updated At
      required:
      - stage
      - stage_label
      - status
      title: StageProgressEntry
      type: object
    StageTransitionEntry:
      description: Stage transition audit trail entry.
      properties:
        message:
          default: ''
          title: Message
          type: string
        stage:
          title: Stage
          type: string
        status:
          title: Status
          type: string
        timestamp:
          title: Timestamp
          type: number
      required:
      - stage
      - status
      - timestamp
      title: StageTransitionEntry
      type: object
    SubmitFindingPayload:
      properties:
        additional_notes:
          default: ''
          title: Additional Notes
          type: string
        draft:
          default: true
          title: Draft
          type: boolean
        platform:
          pattern: ^(hackerone|bugcrowd|intigriti|synack|yeswehack|openbugbounty|googlevrp|meta|apple|aws|msrc|mozilla|govdefense)$
          title: Platform
          type: string
      required:
      - platform
      title: SubmitFindingPayload
      type: object
    TargetComparisonDetail:
      description: Single side of a target comparison response.
      properties:
        attack_chain_count:
          default: 0
          title: Attack Chain Count
          type: integer
        finding_count:
          default: 0
          title: Finding Count
          type: integer
        latest_run:
          default: ''
          title: Latest Run
          type: string
        name:
          default: ''
          title: Name
          type: string
        parameter_count:
          default: 0
          title: Parameter Count
          type: integer
        risk_score:
          default: 0.0
          title: Risk Score
          type: number
        run_count:
          default: 0
          title: Run Count
          type: integer
        severity_counts:
          additionalProperties:
            type: integer
          title: Severity Counts
          type: object
        url_count:
          default: 0
          title: Url Count
          type: integer
      title: TargetComparisonDetail
      type: object
    TargetComparisonResponse:
      description: Side-by-side target comparison response.
      properties:
        target_a:
          $ref: '#/components/schemas/TargetComparisonDetail'
        target_b:
          $ref: '#/components/schemas/TargetComparisonDetail'
      required:
      - target_a
      - target_b
      title: TargetComparisonResponse
      type: object
    TargetFindingsResponse:
      description: Findings for a specific target.
      properties:
        findings:
          items:
            additionalProperties: true
            type: object
          title: Findings
          type: array
        target:
          default: ''
          title: Target
          type: string
        total:
          default: 0
          title: Total
          type: integer
      title: TargetFindingsResponse
      type: object
    TargetInfo:
      description: Target summary information.
      properties:
        attack_chain_count:
          default: 0
          title: Attack Chain Count
          type: integer
        finding_count:
          default: 0
          title: Finding Count
          type: integer
        href:
          default: ''
          title: Href
          type: string
        last_scan:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Scan
        latest_generated_at:
          default: ''
          title: Latest Generated At
          type: string
        latest_report_href:
          default: ''
          title: Latest Report Href
          type: string
        latest_run:
          anyOf:
          - type: string
          - type: 'null'
          title: Latest Run
        max_attack_chain_confidence:
          default: 0.0
          title: Max Attack Chain Confidence
          type: number
        name:
          title: Name
          type: string
        new_findings:
          default: 0
          title: New Findings
          type: integer
        parameter_count:
          default: 0
          title: Parameter Count
          type: integer
        priority_url_count:
          default: 0
          title: Priority Url Count
          type: integer
        run_count:
          default: 0
          title: Run Count
          type: integer
        severity_counts:
          additionalProperties:
            type: integer
          title: Severity Counts
          type: object
        top_finding_severity:
          default: ''
          title: Top Finding Severity
          type: string
        top_finding_title:
          default: ''
          title: Top Finding Title
          type: string
        top_finding_url:
          default: ''
          title: Top Finding Url
          type: string
        url_count:
          default: 0
          title: Url Count
          type: integer
        validated_leads:
          default: 0
          title: Validated Leads
          type: integer
        validation_plan_count:
          default: 0
          title: Validation Plan Count
          type: integer
      required:
      - name
      title: TargetInfo
      type: object
    TargetListResponse:
      description: List of targets response.
      properties:
        targets:
          items:
            $ref: '#/components/schemas/TargetInfo'
          title: Targets
          type: array
        total:
          default: 0
          title: Total
          type: integer
      required:
      - targets
      title: TargetListResponse
      type: object
    TargetProgressStats:
      description: Per-target queue/scanning/done progress counters.
      properties:
        done:
          default: 0
          title: Done
          type: integer
        queued:
          default: 0
          title: Queued
          type: integer
        scanning:
          default: 0
          title: Scanning
          type: integer
      title: TargetProgressStats
      type: object
    TelemetryKpis:
      description: FastAPI response schema for learning subsystem KPIs.
      properties:
        active_exploits_per_run:
          default: 0
          title: Active Exploits Per Run
          type: integer
        active_suppression_rules:
          default: 0
          title: Active Suppression Rules
          type: integer
        attack_chain_coverage:
          default: 0.0
          title: Attack Chain Coverage
          type: number
        auto_validated_ratio:
          default: 0.0
          title: Auto Validated Ratio
          type: number
        category_coverage:
          default: 0.0
          title: Category Coverage
          type: number
        detection_rate:
          default: 0.0
          title: Detection Rate
          type: number
        endpoint_coverage:
          default: 0.0
          title: Endpoint Coverage
          type: number
        f1_score:
          default: 0.0
          title: F1 Score
          type: number
        findings_per_scan_hour:
          default: 0.0
          title: Findings Per Scan Hour
          type: number
        fn_rate:
          default: 0.0
          title: Fn Rate
          type: number
        fp_pattern_count:
          default: 0
          title: Fp Pattern Count
          type: integer
        fp_rate:
          default: 0.0
          title: Fp Rate
          type: number
        learning_velocity_precision:
          default: 0.0
          title: Learning Velocity Precision
          type: number
        learning_velocity_recall:
          default: 0.0
          title: Learning Velocity Recall
          type: number
        mean_time_to_detect_minutes:
          default: 0.0
          title: Mean Time To Detect Minutes
          type: number
        mean_time_to_validate_minutes:
          default: 0.0
          title: Mean Time To Validate Minutes
          type: number
        parameter_coverage:
          default: 0.0
          title: Parameter Coverage
          type: number
        pipeline_uptime:
          default: 1.0
          title: Pipeline Uptime
          type: number
        precision:
          default: 0.0
          title: Precision
          type: number
        recall:
          default: 0.0
          title: Recall
          type: number
        regression_count:
          default: 0
          title: Regression Count
          type: integer
        safety_violations:
          default: 0
          title: Safety Violations
          type: integer
        scan_duration_minutes:
          default: 0.0
          title: Scan Duration Minutes
          type: number
        threshold_convergence:
          default: false
          title: Threshold Convergence
          type: boolean
        urls_per_minute:
          default: 0.0
          title: Urls Per Minute
          type: number
        validated_findings_ratio:
          default: 0.0
          title: Validated Findings Ratio
          type: number
        validation_success_rate:
          default: 0.0
          title: Validation Success Rate
          type: number
      title: TelemetryKpis
      type: object
    TerminalCommandRequest:
      properties:
        command:
          title: Command
          type: string
      required:
      - command
      title: TerminalCommandRequest
      type: object
    ThresholdHistoryEntry:
      description: Threshold history entry.
      properties:
        adjustment:
          anyOf:
          - type: number
          - type: 'null'
          title: Adjustment
        category:
          title: Category
          type: string
        error:
          anyOf:
          - type: number
          - type: 'null'
          title: Error
        high_threshold:
          anyOf:
          - type: number
          - type: 'null'
          title: High Threshold
        history_id:
          title: History Id
          type: string
        is_converged:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Is Converged
        low_threshold:
          anyOf:
          - type: number
          - type: 'null'
          title: Low Threshold
        medium_threshold:
          anyOf:
          - type: number
          - type: 'null'
          title: Medium Threshold
        observed_fp_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Observed Fp Rate
        recorded_at:
          title: Recorded At
          type: string
        run_id:
          title: Run Id
          type: string
        target_fp_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Target Fp Rate
      required:
      - history_id
      - run_id
      - category
      - recorded_at
      title: ThresholdHistoryEntry
      type: object
    TimelineEntry:
      description: Single timeline entry.
      properties:
        module:
          default: ''
          title: Module
          type: string
        severity:
          title: Severity
          type: string
        timestamp:
          title: Timestamp
          type: string
        title:
          title: Title
          type: string
        url:
          title: Url
          type: string
      required:
      - timestamp
      - severity
      - url
      - title
      title: TimelineEntry
      type: object
    TimelineResponse:
      description: Timeline response.
      properties:
        count:
          default: 0
          title: Count
          type: integer
        target:
          default: ''
          title: Target
          type: string
        timeline:
          items:
            $ref: '#/components/schemas/TimelineEntry'
          title: Timeline
          type: array
      required:
      - timeline
      title: TimelineResponse
      type: object
    TokenRequest:
      additionalProperties: false
      description: Request body for dashboard token exchange.
      properties:
        api_key:
          anyOf:
          - type: string
          - type: 'null'
          title: Api Key
        mode:
          anyOf:
          - type: string
          - type: 'null'
          title: Mode
      title: TokenRequest
      type: object
    TokenResponse:
      description: Short-lived dashboard token response.
      properties:
        access_token:
          title: Access Token
          type: string
        expires_in:
          title: Expires In
          type: integer
        role:
          title: Role
          type: string
        token_type:
          default: bearer
          title: Token Type
          type: string
      required:
      - access_token
      - expires_in
      - role
      title: TokenResponse
      type: object
    ToolAvailabilityRequest:
      description: Body for the tool availability check endpoint.
      properties:
        tools:
          description: List of tool names to check availability for
          items:
            type: string
          title: Tools
          type: array
      required:
      - tools
      title: ToolAvailabilityRequest
      type: object
    UnreadCountResponse:
      properties:
        unread_count:
          title: Unread Count
          type: integer
      required:
      - unread_count
      title: UnreadCountResponse
      type: object
    ValidationError:
      properties:
        ctx:
          title: Context
          type: object
        input:
          title: Input
        loc:
          items:
            anyOf:
            - type: string
            - type: integer
          title: Location
          type: array
        msg:
          title: Message
          type: string
        type:
          title: Error Type
          type: string
      required:
      - loc
      - msg
      - type
      title: ValidationError
      type: object
    WebhookTestRequest:
      properties:
        secret:
          anyOf:
          - type: string
          - type: 'null'
          description: Optional HMAC signing secret
          title: Secret
        url:
          description: The webhook URL to test
          title: Url
          type: string
      required:
      - url
      title: WebhookTestRequest
      type: object
  securitySchemes:
    APIKeyHeader:
      in: header
      name: X-API-Key
      type: apiKey
info:
  description: Unified security orchestration and vulnerability analysis dashboard.
  title: Cyber Security Test Pipeline Dashboard
  version: 2.0.0
  x-ai-metadata:
    agent_roles:
    - orchestrator
    - worker
    - dashboard
    - auditor
    mesh_aware: true
    stateful_endpoints:
    - /api/jobs/{id}
    - /api/jobs/{id}/progress/stream
openapi: 3.1.0
paths:
  /api/access-logs:
    delete:
      description: Clear all access-log entries.
      operationId: clear_access_logs_api_access_logs_delete
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  type: string
                title: Response Clear Access Logs Api Access Logs Delete
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Clear all access-log entries
      tags:
      - Access Logs
      - Access Logs
    get:
      description: Return access-log entries, optionally filtered by user or action.
      operationId: list_access_logs_api_access_logs_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 1000
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: offset
        required: false
        schema:
          default: 0
          minimum: 0
          title: Offset
          type: integer
      - in: query
        name: user
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: User
      - in: query
        name: action
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Action
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response List Access Logs Api Access Logs Get
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List access-log entries
      tags:
      - Access Logs
      - Access Logs
    post:
      description: Record a new access-log entry.
      operationId: create_access_log_api_access_logs_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AccessLogCreateRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Create Access Log Api Access Logs Post
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Create an access-log entry
      tags:
      - Access Logs
      - Access Logs
  /api/access-logs/export:
    get:
      description: Export all access-log entries.
      operationId: export_access_logs_api_access_logs_export_get
      parameters:
      - in: query
        name: format
        required: false
        schema:
          default: json
          pattern: ^(json|csv)$
          title: Format
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Export Access Logs Api Access Logs Export Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Export access logs as JSON
      tags:
      - Access Logs
      - Access Logs
  /api/audit/entries:
    get:
      description: Return audit log entries with filtering and pagination.
      operationId: get_audit_entries_api_audit_entries_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 100
          maximum: 1000
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: offset
        required: false
        schema:
          default: 0
          minimum: 0
          title: Offset
          type: integer
      - in: query
        name: event
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Event
      - in: query
        name: user_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: User Id
      - in: query
        name: severity
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Severity
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response Get Audit Entries Api Audit Entries Get
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get audit log entries
      tags:
      - Audit
      - Audit
  /api/audit/verify:
    get:
      description: Check the hash chain of the audit log to detect tampering.
      operationId: verify_audit_integrity_api_audit_verify_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Verify Audit Integrity Api Audit Verify Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
      security:
      - APIKeyHeader: []
      summary: Verify audit log integrity
      tags:
      - Audit
      - Audit
  /api/auth/token:
    post:
      operationId: create_dashboard_token_api_auth_token_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TokenRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TokenResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unprocessable Entity
      summary: Exchange an API key for a short-lived dashboard token
      tags:
      - Security
      - Security
  /api/bloom/health:
    get:
      description: Return Bloom filter mesh health for dashboard tiles.
      operationId: bloom_health_api_bloom_health_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Bloom Health Api Bloom Health Get
                type: object
          description: Successful Response
      summary: Bloom Health
      tags:
      - Bloom
      - Bloom
      x-ai-action: get_bloom_health
      x-ai-idempotency: true
  /api/bloom/reconcile:
    post:
      description: Force an immediate Bloom snapshot publish across online nodes.
      operationId: reconcile_bloom_mesh_api_bloom_reconcile_post
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Reconcile Bloom Mesh Api Bloom Reconcile Post
                type: object
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Reconcile Bloom Mesh
      tags:
      - Bloom
      - Bloom
      x-ai-action: reconcile_bloom_mesh
      x-ai-idempotency: true
      x-ai-impact: medium
  /api/cache/cleanup:
    post:
      description: Run cache cleanup to remove expired entries.
      operationId: trigger_cache_cleanup_api_cache_cleanup_post
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheCleanupResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
      security:
      - APIKeyHeader: []
      summary: Trigger cache cleanup
      tags:
      - Cache
      - Cache
  /api/cache/clear:
    post:
      description: Clear all entries from the configured cache manager.
      operationId: clear_all_cache_api_cache_clear_post
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheNamespaceResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
      security:
      - APIKeyHeader: []
      summary: Clear all cache entries
      tags:
      - Cache
      - Cache
  /api/cache/keys:
    delete:
      description: Delete Redis keys matching a pattern using SCAN and batched DEL.
      operationId: delete_cache_keys_api_cache_keys_delete
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CacheKeyDeleteRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheKeyDeleteResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Delete Redis keys by pattern
      tags:
      - Cache
      - Cache
    get:
      description: List Redis keys matching a glob pattern with TTL and size metadata.
      operationId: list_cache_keys_api_cache_keys_get
      parameters:
      - in: query
        name: pattern
        required: false
        schema:
          default: '*'
          maxLength: 512
          minLength: 1
          title: Pattern
          type: string
      - in: query
        name: limit
        required: false
        schema:
          default: 100
          maximum: 1000
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheKeysResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List Redis keys
      tags:
      - Cache
      - Cache
  /api/cache/performance-history:
    get:
      description: Return the last hour of one-minute cache hit/miss samples.
      operationId: get_cache_performance_history_api_cache_performance_history_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CachePerformanceHistoryResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
      security:
      - APIKeyHeader: []
      summary: Get cache performance history
      tags:
      - Cache
      - Cache
  /api/cache/stats:
    get:
      description: Return cache statistics including hit/miss rates and entry counts.
      operationId: get_cache_stats_api_cache_stats_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheStatsResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get cache statistics
      tags:
      - Cache
      - Cache
  /api/cache/status:
    get:
      description: Return Redis and SQLite cache status without mutating cache contents.
      operationId: get_cache_status_api_cache_status_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheStatusResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
      security:
      - APIKeyHeader: []
      summary: Get cache backend status
      tags:
      - Cache
      - Cache
  /api/cache/{namespace}:
    delete:
      description: Clear all entries in the specified cache namespace.
      operationId: invalidate_cache_namespace_api_cache__namespace__delete
      parameters:
      - in: path
        name: namespace
        required: true
        schema:
          title: Namespace
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheNamespaceResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Invalidate cache namespace
      tags:
      - Cache
      - Cache
  /api/cockpit/events:
    get:
      description: Return a timeline of cockpit-relevant events.
      operationId: get_cockpit_events_api_cockpit_events_get
      parameters:
      - in: query
        name: target
        required: true
        schema:
          minLength: 1
          title: Target
          type: string
      - in: query
        name: run
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run
      - in: query
        name: job_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Job Id
      - in: query
        name: cursor
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Cursor
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Cockpit Events Api Cockpit Events Get
                type: object
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get cockpit event timeline
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/forensics:
    get:
      description: List forensic exchanges stored for a target.
      operationId: list_forensic_exchanges_api_cockpit_forensics_get
      parameters:
      - in: query
        name: target
        required: true
        schema:
          minLength: 1
          title: Target
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response List Forensic Exchanges Api Cockpit Forensics Get
                type: object
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List forensic exchanges for a target
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/forensics/{exchange_id}:
    get:
      description: Retrieve a forensic exchange artifact from disk.
      operationId: get_forensic_exchange_api_cockpit_forensics__exchange_id__get
      parameters:
      - in: path
        name: exchange_id
        required: true
        schema:
          title: Exchange Id
          type: string
      - in: query
        name: target
        required: true
        schema:
          minLength: 1
          title: Target
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Forensic Exchange Api Cockpit Forensics  Exchange
                  Id  Get
                type: object
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get forensic exchange details
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/graph:
    get:
      description: Build and return 3D threat graph data for the cockpit.
      operationId: get_cockpit_graph_api_cockpit_graph_get
      parameters:
      - in: query
        name: target
        required: true
        schema:
          minLength: 1
          title: Target
          type: string
      - in: query
        name: run
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run
      - in: query
        name: job_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Job Id
      - in: query
        name: max_nodes
        required: false
        schema:
          default: 2000
          maximum: 10000
          minimum: 1
          title: Max Nodes
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Cockpit Graph Api Cockpit Graph Get
                type: object
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get 3D threat graph data
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/graph/stream:
    get:
      description: Stream graph snapshots so the 3D cockpit can ingest pipeline additions
        live.
      operationId: stream_cockpit_graph_api_cockpit_graph_stream_get
      parameters:
      - in: query
        name: target
        required: true
        schema:
          title: Target
          type: string
      - in: query
        name: run
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run
      - in: query
        name: job_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Job Id
      - in: query
        name: interval_seconds
        required: false
        schema:
          default: 2.0
          maximum: 15.0
          minimum: 0.5
          title: Interval Seconds
          type: number
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Stream cockpit graph snapshots
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/probes:
    post:
      description: Trigger a manual probe with scope validation and forensic capture.
      operationId: trigger_cockpit_probe_api_cockpit_probes_post
      parameters:
      - in: query
        name: target
        required: true
        schema:
          minLength: 1
          title: Target
          type: string
      - in: query
        name: url
        required: true
        schema:
          minLength: 1
          title: Url
          type: string
      - in: query
        name: method
        required: false
        schema:
          default: GET
          title: Method
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Trigger Cockpit Probe Api Cockpit Probes Post
                type: object
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Trigger a manual forensic probe
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/sandbox/launch:
    post:
      operationId: launch_sandbox_api_cockpit_sandbox_launch_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SandboxLaunchRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Launch Sandbox Api Cockpit Sandbox Launch Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Launch a safe dockerized sandbox for a node
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/sandbox/{sandbox_id}/state:
    get:
      operationId: get_sandbox_state_api_cockpit_sandbox__sandbox_id__state_get
      parameters:
      - in: path
        name: sandbox_id
        required: true
        schema:
          title: Sandbox Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Sandbox State Api Cockpit Sandbox  Sandbox Id  State
                  Get
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: View chronological state of the sandbox for Time-Travel Replay
      tags:
      - Cockpit
      - Cockpit
  /api/cockpit/sandbox/{sandbox_id}/terminal:
    post:
      operationId: execute_terminal_api_cockpit_sandbox__sandbox_id__terminal_post
      parameters:
      - in: path
        name: sandbox_id
        required: true
        schema:
          title: Sandbox Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TerminalCommandRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Execute Terminal Api Cockpit Sandbox  Sandbox Id  Terminal
                  Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Execute manual command in the sandbox terminal
      tags:
      - Cockpit
      - Cockpit
  /api/compliance/access-logs:
    get:
      operationId: list_access_logs_api_compliance_access_logs_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 2000
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: user
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: User
      - in: query
        name: action
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Action
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response List Access Logs Api Compliance Access Logs Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List compliance access log entries
      tags:
      - Compliance
      - Compliance
    post:
      operationId: create_access_log_api_compliance_access_logs_post
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Create Access Log Api Compliance Access Logs Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Record a compliance access log entry
      tags:
      - Compliance
      - Compliance
  /api/compliance/evidence:
    get:
      operationId: list_evidence_api_compliance_evidence_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 2000
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: finding_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Id
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response List Evidence Api Compliance Evidence Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List evidence custody records
      tags:
      - Compliance
      - Compliance
    post:
      operationId: create_evidence_api_compliance_evidence_post
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Create Evidence Api Compliance Evidence Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Create an evidence custody record
      tags:
      - Compliance
      - Compliance
  /api/compliance/evidence/{evidence_id}/access:
    post:
      operationId: log_evidence_access_api_compliance_evidence__evidence_id__access_post
      parameters:
      - in: path
        name: evidence_id
        required: true
        schema:
          title: Evidence Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Log Evidence Access Api Compliance Evidence  Evidence
                  Id  Access Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Log an access event on an evidence record
      tags:
      - Compliance
      - Compliance
  /api/compliance/evidence/{evidence_id}/verify:
    post:
      operationId: verify_evidence_api_compliance_evidence__evidence_id__verify_post
      parameters:
      - in: path
        name: evidence_id
        required: true
        schema:
          title: Evidence Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Verify Evidence Api Compliance Evidence  Evidence
                  Id  Verify Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Verify the cryptographic integrity of an evidence record
      tags:
      - Compliance
      - Compliance
  /api/csp-report:
    post:
      operationId: csp_report_api_csp_report_post
      responses:
        '204':
          description: Successful Response
      summary: Accept a CSP violation report
      tags:
      - Security
      - Security
  /api/csrf-token:
    get:
      description: 'Issue a fresh CSRF token, set it as an HttpOnly cookie, and return
        it.


        The endpoint now requires authentication. The cookie is ``HttpOnly``,

        ``Secure`` (in production) and ``SameSite=Strict`` so it cannot be

        exfiltrated by client-side scripts. The response body returns the

        token so SPAs can copy it into the ``X-CSRF-Token`` header.'
      operationId: get_csrf_token_api_csrf_token_get
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Retrieve the current active CSRF token for the session
      tags:
      - Security
      - Security
  /api/dashboard:
    get:
      operationId: get_dashboard_stats_api_dashboard_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DashboardStatsResponse'
          description: Successful Response
      summary: Get Dashboard Stats
      tags:
      - Analytics
  /api/defaults:
    get:
      description: Return default settings for forms and UI components.
      operationId: get_defaults_api_defaults_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ApiDefaults'
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Get form and system defaults
      tags:
      - Defaults
      - Defaults
  /api/evasion/hunt-mode:
    post:
      description: 'Enable or disable hunt mode.


        Hunt mode prioritises high-value categories, skips low-yield stages,

        and enforces a budget to maximise payout per hour.'
      operationId: set_hunt_mode_api_evasion_hunt_mode_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/HuntModeRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Set Hunt Mode Api Evasion Hunt Mode Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Toggle bug-bounty hunt mode on or off
      tags:
      - Evasion Telemetry
      - Evasion Telemetry
  /api/evasion/metrics:
    get:
      description: 'Returns aggregated and per-target/per-session WAF evasion benchmarks.

        Calculates evasion success rates per target/session.'
      operationId: get_evasion_metrics_api_evasion_metrics_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Evasion Metrics Api Evasion Metrics Get
                type: object
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Get WAF evasion effectiveness metrics
      tags:
      - Evasion Telemetry
      - Evasion Telemetry
  /api/evasion/reset:
    post:
      description: Resets the WAF evasion metrics repository.
      operationId: reset_evasion_metrics_api_evasion_reset_post
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Reset Evasion Metrics Api Evasion Reset Post
                type: object
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Reset Chameleon Evasion Telemetry metrics
      tags:
      - Evasion Telemetry
      - Evasion Telemetry
  /api/evidence-custody:
    get:
      description: Return evidence records, optionally filtered by finding_id.
      operationId: list_evidence_api_evidence_custody_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 1000
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: offset
        required: false
        schema:
          default: 0
          minimum: 0
          title: Offset
          type: integer
      - in: query
        name: finding_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Id
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response List Evidence Api Evidence Custody Get
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List all evidence records
      tags:
      - Evidence Custody
      - Evidence Custody
    post:
      description: Create a new evidence record with an initial custody entry.
      operationId: create_evidence_api_evidence_custody_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/EvidenceCreateRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Create Evidence Api Evidence Custody Post
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Create an evidence record
      tags:
      - Evidence Custody
      - Evidence Custody
  /api/evidence-custody/{evidence_id}:
    delete:
      description: Remove an evidence record.
      operationId: delete_evidence_api_evidence_custody__evidence_id__delete
      parameters:
      - in: path
        name: evidence_id
        required: true
        schema:
          title: Evidence Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  type: string
                title: Response Delete Evidence Api Evidence Custody  Evidence Id  Delete
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Delete an evidence record
      tags:
      - Evidence Custody
      - Evidence Custody
    get:
      description: Return a single evidence record by ID.
      operationId: get_evidence_api_evidence_custody__evidence_id__get
      parameters:
      - in: path
        name: evidence_id
        required: true
        schema:
          title: Evidence Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Evidence Api Evidence Custody  Evidence Id  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get a single evidence record
      tags:
      - Evidence Custody
      - Evidence Custody
  /api/evidence-custody/{evidence_id}/access:
    post:
      description: Append an 'accessed' entry to the custody chain.
      operationId: log_evidence_access_api_evidence_custody__evidence_id__access_post
      parameters:
      - in: path
        name: evidence_id
        required: true
        schema:
          title: Evidence Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/EvidenceAccessRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Log Evidence Access Api Evidence Custody  Evidence
                  Id  Access Post
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Log evidence access
      tags:
      - Evidence Custody
      - Evidence Custody
  /api/evidence-custody/{evidence_id}/modify:
    post:
      description: Update evidence data and append a 'modified' custody entry.
      operationId: modify_evidence_api_evidence_custody__evidence_id__modify_post
      parameters:
      - in: path
        name: evidence_id
        required: true
        schema:
          title: Evidence Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/EvidenceModifyRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Modify Evidence Api Evidence Custody  Evidence Id  Modify
                  Post
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Modify evidence data
      tags:
      - Evidence Custody
      - Evidence Custody
  /api/evidence-custody/{evidence_id}/verify:
    get:
      description: Verify that the stored hash matches the current data.
      operationId: verify_evidence_api_evidence_custody__evidence_id__verify_get
      parameters:
      - in: path
        name: evidence_id
        required: true
        schema:
          title: Evidence Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Verify Evidence Api Evidence Custody  Evidence Id  Verify
                  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Verify evidence integrity
      tags:
      - Evidence Custody
      - Evidence Custody
  /api/export/compliance/{target_name}/attestation:
    get:
      description: Export a high-fidelity HTML compliance attestation (Phase 6.3).
      operationId: export_compliance_attestation_api_export_compliance__target_name__attestation_get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      - description: 'Export format: html or pdf'
        in: query
        name: format
        required: false
        schema:
          default: pdf
          description: 'Export format: html or pdf'
          pattern: ^(html|pdf)$
          title: Format
          type: string
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Export compliance attestation (SOC 2 / PCI DSS)
      tags:
      - Export
      - Export
  /api/export/findings/all:
    get:
      description: Export findings from all targets in CSV or JSON format.
      operationId: export_all_findings_api_export_findings_all_get
      parameters:
      - description: 'Export format: csv or json'
        in: query
        name: format
        required: false
        schema:
          default: json
          description: 'Export format: csv or json'
          pattern: ^(csv|json)$
          title: Format
          type: string
      - description: Maximum number of targets to export
        in: query
        name: max_targets
        required: false
        schema:
          default: 50
          description: Maximum number of targets to export
          maximum: 200
          minimum: 1
          title: Max Targets
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Export findings from all targets
      tags:
      - Export
      - Export
  /api/export/findings/{target_name}:
    get:
      description: Export all findings for a target in CSV or JSON format.
      operationId: export_findings_api_export_findings__target_name__get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      - description: 'Export format: csv or json'
        in: query
        name: format
        required: false
        schema:
          default: json
          description: 'Export format: csv or json'
          pattern: ^(csv|json)$
          title: Format
          type: string
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Export findings for a target
      tags:
      - Export
      - Export
  /api/export/findings/{target_name}/latest:
    get:
      description: Export findings from the latest run for a target.
      operationId: export_latest_findings_api_export_findings__target_name__latest_get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      - description: 'Export format: csv or json'
        in: query
        name: format
        required: false
        schema:
          default: json
          description: 'Export format: csv or json'
          pattern: ^(csv|json)$
          title: Format
          type: string
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Export latest findings for a target
      tags:
      - Export
      - Export
  /api/findings:
    get:
      description: Return a global summary of findings across all targets.
      operationId: get_findings_summary_api_findings_get
      parameters:
      - in: query
        name: target
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/FindingsSummaryResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get summary of all findings
      tags:
      - Findings
      - Findings
  /api/findings/bulk:
    put:
      description: Apply updates to multiple findings.
      operationId: bulk_update_findings_api_findings_bulk_put
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response Bulk Update Findings Api Findings Bulk Put
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Bulk update findings
      tags:
      - Findings
      - Findings
  /api/findings/timeline:
    get:
      operationId: get_findings_timeline_api_findings_timeline_get
      parameters:
      - description: Filter by job or run identifier
        in: query
        name: job_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by job or run identifier
          title: Job Id
      - in: query
        name: severity
        required: false
        schema:
          anyOf:
          - pattern: ^(critical|high|medium|low|info)$
            type: string
          - type: 'null'
          title: Severity
      - description: Filter by target name
        in: query
        name: target
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by target name
          title: Target
      - description: Inclusive ISO start date
        in: query
        name: start_date
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Inclusive ISO start date
          title: Start Date
      - description: Inclusive ISO end date
        in: query
        name: end_date
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Inclusive ISO end date
          title: End Date
      - in: query
        name: limit
        required: false
        schema:
          default: 50
          maximum: 200
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: offset
        required: false
        schema:
          default: 0
          minimum: 0
          title: Offset
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response Get Findings Timeline Api Findings Timeline Get
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get finding discovery events across jobs
      tags:
      - Findings
      - Findings
  /api/findings/{finding_id}:
    delete:
      description: Remove a finding from disk.
      operationId: delete_finding_api_findings__finding_id__delete
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  type: boolean
                title: Response Delete Finding Api Findings  Finding Id  Delete
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Delete a finding
      tags:
      - Findings
      - Findings
      x-ai-action: delete_finding
      x-ai-idempotency: false
      x-ai-impact: high
    get:
      description: Retrieve full details for a specific finding by ID.
      operationId: get_finding_detail_api_findings__finding_id__get
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Finding Detail Api Findings  Finding Id  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get individual finding details
      tags:
      - Findings
      - Findings
    put:
      description: Update finding metadata (status, severity, etc.) on disk.
      operationId: update_finding_api_findings__finding_id__put
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Update Data
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Update Finding Api Findings  Finding Id  Put
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Update a finding
      tags:
      - Findings
      - Findings
      x-ai-action: update_finding
      x-ai-idempotency: false
  /api/findings/{finding_id}/ai-explain:
    get:
      operationId: explain_finding_ai_api_findings__finding_id__ai_explain_get
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Explain Finding Ai Api Findings  Finding Id  Ai Explain
                  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get AI persona-tailored (Developer/Auditor) explanations for a finding
      tags:
      - Findings
      - Findings
  /api/findings/{finding_id}/explain:
    get:
      operationId: explain_finding_severity_api_findings__finding_id__explain_get
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Explain Finding Severity Api Findings  Finding Id  Explain
                  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get ML explainability analysis (SHAP) for a finding
      tags:
      - Findings
      - Findings
  /api/findings/{finding_id}/remediation:
    get:
      operationId: get_finding_remediation_api_findings__finding_id__remediation_get
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Finding Remediation Api Findings  Finding Id  Remediation
                  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get fix-command suggestions for a finding
      tags:
      - Findings
      - Findings
  /api/forensics/trace/{run_id}:
    get:
      operationId: list_run_traces_api_forensics_trace__run_id__get
      parameters:
      - description: Pipeline run ID
        in: path
        name: run_id
        required: true
        schema:
          description: Pipeline run ID
          minLength: 1
          title: Run Id
          type: string
      - description: Override trace directory
        in: query
        name: trace_dir
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Override trace directory
          title: Trace Dir
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response List Run Traces Api Forensics Trace  Run Id  Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '404':
          description: Run not found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List all StageTraces for a run
      tags:
      - Forensics Trace
      - Forensics Trace
  /api/forensics/trace/{run_id}/{stage_name}:
    get:
      operationId: get_stage_trace_api_forensics_trace__run_id___stage_name__get
      parameters:
      - description: Pipeline run ID
        in: path
        name: run_id
        required: true
        schema:
          description: Pipeline run ID
          minLength: 1
          title: Run Id
          type: string
      - description: Stage name
        in: path
        name: stage_name
        required: true
        schema:
          description: Stage name
          minLength: 1
          title: Stage Name
          type: string
      - description: Override trace directory
        in: query
        name: trace_dir
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Override trace directory
          title: Trace Dir
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Stage Trace Api Forensics Trace  Run Id   Stage
                  Name  Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '404':
          description: Trace not found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get the full StageTrace for a run+stage combination
      tags:
      - Forensics Trace
      - Forensics Trace
  /api/forensics/trace/{run_id}/{stage_name}/causal-chain/{finding_id}:
    get:
      operationId: get_finding_causal_chain_api_forensics_trace__run_id___stage_name__causal_chain__finding_id__get
      parameters:
      - description: Pipeline run ID
        in: path
        name: run_id
        required: true
        schema:
          description: Pipeline run ID
          minLength: 1
          title: Run Id
          type: string
      - description: Stage name
        in: path
        name: stage_name
        required: true
        schema:
          description: Stage name
          minLength: 1
          title: Stage Name
          type: string
      - description: Finding identifier
        in: path
        name: finding_id
        required: true
        schema:
          description: Finding identifier
          minLength: 1
          title: Finding Id
          type: string
      - description: Override trace directory
        in: query
        name: trace_dir
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Override trace directory
          title: Trace Dir
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Finding Causal Chain Api Forensics Trace  Run
                  Id   Stage Name  Causal Chain  Finding Id  Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '404':
          description: Finding or trace not found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get all stages that contributed to a specific finding
      tags:
      - Forensics Trace
      - Forensics Trace
  /api/gap-analysis:
    get:
      description: Analyze coverage gaps across vulnerability categories using real
        telemetry.
      operationId: get_gap_analysis_api_gap_analysis_get
      parameters:
      - in: query
        name: target
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DetectionGapResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get detection gap analysis
      tags:
      - Gap Analysis
      - Gap Analysis
  /api/gap-analysis/refresh:
    post:
      description: Trigger a fresh analysis of findings vs coverage registry.
      operationId: refresh_gap_analysis_api_gap_analysis_refresh_post
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  type: string
                title: Response Refresh Gap Analysis Api Gap Analysis Refresh Post
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Trigger fresh gap analysis
      tags:
      - Gap Analysis
      - Gap Analysis
  /api/health:
    get:
      description: Comprehensive health check endpoint with distributed mesh telemetry.
      operationId: health_check_api_health_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'
          description: Successful Response
      summary: Health check
      tags:
      - Health
      - Health
  /api/health/live:
    get:
      operationId: health_check_live_api_health_live_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Health Check Live Api Health Live Get
                type: object
          description: Successful Response
      summary: Health Check Live
      tags:
      - System
  /api/health/mesh:
    get:
      description: Return detailed local view of mesh membership and transport health.
      operationId: mesh_health_api_health_mesh_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Mesh Health Api Health Mesh Get
                type: object
          description: Successful Response
      summary: Mesh health
      tags:
      - Health
      - Health
      x-ai-action: get_mesh_health
      x-ai-idempotency: true
  /api/health/ready:
    get:
      operationId: health_check_ready_api_health_ready_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Health Check Ready Api Health Ready Get
                type: object
          description: Successful Response
      summary: Health Check Ready
      tags:
      - System
      x-ai-action: check_readiness
      x-ai-idempotency: true
  /api/health/self-healing:
    get:
      description: Return the latest autonomous recovery snapshot.
      operationId: self_healing_snapshot_api_health_self_healing_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Self Healing Snapshot Api Health Self Healing Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Self Healing Snapshot
      tags:
      - Self-Healing
      - Self-Healing
  /api/health/self-healing/circuit-breakers:
    get:
      description: 'Return a serializable snapshot of every per-tool circuit breaker.


        The response is sourced from the bound

        :class:`~src.pipeline.services.tool_execution.ToolExecutionService` (or

        the module-level default if the controller has none wired).'
      operationId: list_circuit_breakers_api_health_self_healing_circuit_breakers_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response List Circuit Breakers Api Health Self Healing Circuit
                  Breakers Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: List Circuit Breakers
      tags:
      - Self-Healing
      - Self-Healing
  /api/health/self-healing/circuit-breakers/{tool_name}/force-open:
    post:
      description: 'Trip a tool''s circuit breaker.


        The ``TRIP_TOOL_CIRCUIT_BREAKER`` corrective action calls the same

        backend.  Operators can invoke this endpoint to manually cool down a

        tool that is hammering a rate-limited upstream.'
      operationId: force_open_tool_breaker_api_health_self_healing_circuit_breakers__tool_name__force_open_post
      parameters:
      - in: path
        name: tool_name
        required: true
        schema:
          title: Tool Name
          type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ForceOpenRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Force Open Tool Breaker Api Health Self Healing Circuit
                  Breakers  Tool Name  Force Open Post
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Force Open Tool Breaker
      tags:
      - Self-Healing
      - Self-Healing
  /api/health/self-healing/circuit-breakers/{tool_name}/reset:
    post:
      description: Manually reset a tool's breaker back to CLOSED.
      operationId: reset_tool_breaker_api_health_self_healing_circuit_breakers__tool_name__reset_post
      parameters:
      - in: path
        name: tool_name
        required: true
        schema:
          title: Tool Name
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Reset Tool Breaker Api Health Self Healing Circuit
                  Breakers  Tool Name  Reset Post
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Reset Tool Breaker
      tags:
      - Self-Healing
      - Self-Healing
  /api/health/self-healing/evaluate:
    post:
      description: Run one immediate controller pass.
      operationId: evaluate_self_healing_api_health_self_healing_evaluate_post
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Evaluate Self Healing Api Health Self Healing Evaluate
                  Post
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Evaluate Self Healing
      tags:
      - Self-Healing
      - Self-Healing
  /api/health/self-healing/tile:
    get:
      description: Compact health tile payload for dashboard clients.
      operationId: self_healing_tile_api_health_self_healing_tile_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Self Healing Tile Api Health Self Healing Tile Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Self Healing Tile
      tags:
      - Self-Healing
      - Self-Healing
  /api/health/self-healing/tools/check:
    post:
      description: 'Check if required tool binaries are available on the system.


        Returns a map of tool name to availability status, including whether

        the tool is installed, its resolved path, and circuit breaker state.'
      operationId: check_tool_availability_api_health_self_healing_tools_check_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ToolAvailabilityRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Check Tool Availability Api Health Self Healing Tools
                  Check Post
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Check Tool Availability
      tags:
      - Self-Healing
      - Self-Healing
  /api/imports/semgrep:
    post:
      operationId: import_semgrep_api_imports_semgrep_post
      parameters:
      - description: Target name for the imported results
        in: query
        name: target_name
        required: true
        schema:
          description: Target name for the imported results
          title: Target Name
          type: string
      - description: Optional run name (will be created if omitted)
        in: query
        name: run
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Optional run name (will be created if omitted)
          title: Run
      - description: Overwrite existing semgrep.json if present
        in: query
        name: overwrite
        required: false
        schema:
          default: false
          description: Overwrite existing semgrep.json if present
          title: Overwrite
          type: boolean
      requestBody:
        content:
          multipart/form-data:
            schema:
              $ref: '#/components/schemas/Body_import_semgrep_api_imports_semgrep_post'
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  type: string
                title: Response Import Semgrep Api Imports Semgrep Post
                type: object
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '409':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Conflict
        '413':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Request Entity Too Large
        '415':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unsupported Media Type
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Import Semgrep JSON for a target
      tags:
      - Imports
      - Imports
  /api/jobs:
    get:
      description: List all scan jobs with sorting, filtering and pagination.
      operationId: list_jobs_api_jobs_get
      parameters:
      - description: Page number
        in: query
        name: page
        required: false
        schema:
          default: 1
          description: Page number
          minimum: 1
          title: Page
          type: integer
      - description: Items per page
        in: query
        name: page_size
        required: false
        schema:
          default: 20
          description: Items per page
          maximum: 100
          minimum: 1
          title: Page Size
          type: integer
      - description: Filter by status
        in: query
        name: status
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by status
          title: Status
      - description: Sort field
        in: query
        name: sort_by
        required: false
        schema:
          default: started_at
          description: Sort field
          title: Sort By
          type: string
      - description: Sort order
        in: query
        name: sort_order
        required: false
        schema:
          default: desc
          description: Sort order
          pattern: ^(asc|desc)$
          title: Sort Order
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobListResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List all jobs
      tags:
      - Jobs
      x-ai-action: list_jobs
      x-ai-idempotency: true
    post:
      description: 'Start a new pipeline scan job.


        Creates a job record, writes config/scope files, and launches

        the pipeline subprocess in a background thread.'
      operationId: start_job_api_jobs_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/JobCreateRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
        '429':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Too Many Requests
      security:
      - APIKeyHeader: []
      summary: Start a new scan job
      tags:
      - Jobs
      x-ai-action: start_scan
      x-ai-idempotency: false
      x-ai-impact: high
      x-ai-requires:
      - base_url
  /api/jobs/historical-durations:
    get:
      description: Return historical duration statistics for each pipeline stage based
        on past job runs. Requires ENABLE_DURATION_FORECAST=true.
      operationId: get_historical_durations_api_jobs_historical_durations_get
      responses:
        '200':
          content:
            application/json:
              schema:
                title: Response Get Historical Durations Api Jobs Historical Durations
                  Get
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '501':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Implemented
      security:
      - APIKeyHeader: []
      summary: Get historical stage durations
      tags:
      - Jobs
  /api/jobs/start:
    post:
      description: 'Start a new pipeline scan job.


        Creates a job record, writes config/scope files, and launches

        the pipeline subprocess in a background thread.'
      operationId: start_job_api_jobs_start_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/JobCreateRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
        '429':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Too Many Requests
      security:
      - APIKeyHeader: []
      summary: Start a new scan job
      tags:
      - Jobs
  /api/jobs/{job_id}:
    get:
      operationId: get_job_api_jobs__job_id__get
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get job details
      tags:
      - Jobs
  /api/jobs/{job_id}/logs:
    get:
      operationId: get_job_logs_api_jobs__job_id__logs_get
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobLogsResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get job logs
      tags:
      - Jobs
  /api/jobs/{job_id}/logs/stream:
    get:
      description: Stream process logs in real-time, optionally enriched with progress
        metadata.
      operationId: stream_job_logs_api_jobs__job_id__logs_stream_get
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Stream job logs (SSE)
      tags:
      - Jobs
      - Jobs
  /api/jobs/{job_id}/progress/stream:
    get:
      description: Stream real-time job execution stage transitions, metrics, and
        topology.
      operationId: stream_job_progress_api_jobs__job_id__progress_stream_get
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema: {}
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
        '501':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Implemented
      security:
      - APIKeyHeader: []
      summary: Stream job progress events (SSE)
      tags:
      - Jobs
      - Jobs
  /api/jobs/{job_id}/remediation:
    get:
      operationId: get_job_remediation_api_jobs__job_id__remediation_get
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Job Remediation Api Jobs  Job Id  Remediation
                  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get fix-command suggestions for a failed job
      tags:
      - Jobs
  /api/jobs/{job_id}/restart-safe:
    post:
      operationId: restart_job_safe_api_jobs__job_id__restart_safe_post
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Restart a job with safe defaults
      tags:
      - Jobs
  /api/jobs/{job_id}/stop:
    post:
      operationId: stop_job_api_jobs__job_id__stop_post
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Stop a running job
      tags:
      - Jobs
  /api/jobs/{job_id}/timeline:
    get:
      description: Return execution timeline for a job showing stage transitions.
      operationId: get_job_timeline_api_jobs__job_id__timeline_get
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Job Timeline Api Jobs  Job Id  Timeline Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get job execution timeline
      tags:
      - Jobs
  /api/jobs/{job_id}/trace:
    get:
      operationId: get_job_trace_link_api_jobs__job_id__trace_get
      parameters:
      - in: path
        name: job_id
        required: true
        schema:
          title: Job Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  type: string
                title: Response Get Job Trace Link Api Jobs  Job Id  Trace Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get the Jaeger deep link for a job trace
      tags:
      - Jobs
  /api/learning/db-stats:
    get:
      description: Get statistics about the telemetry database (Phase 5.3).
      operationId: get_learning_db_stats_api_learning_db_stats_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  type: integer
                title: Response Get Learning Db Stats Api Learning Db Stats Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get telemetry database statistics (authenticated)
      tags:
      - Learning
      - learning
  /api/learning/feedback:
    get:
      description: Get feedback events for analysis and inspection (Phase 5.3).
      operationId: get_feedback_events_api_learning_feedback_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 100
          maximum: 10000
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: run_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run Id
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  $ref: '#/components/schemas/FeedbackEventEntry'
                title: Response Get Feedback Events Api Learning Feedback Get
                type: array
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get feedback events (authenticated)
      tags:
      - Learning
      - learning
  /api/learning/fp-patterns:
    get:
      description: Get the current repository of learned false positive patterns (Phase
        5.3).
      operationId: get_fp_patterns_api_learning_fp_patterns_get
      parameters:
      - in: query
        name: category
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Category
      - in: query
        name: active_only
        required: false
        schema:
          default: true
          title: Active Only
          type: boolean
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  $ref: '#/components/schemas/FpPatternEntry'
                title: Response Get Fp Patterns Api Learning Fp Patterns Get
                type: array
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get learned FP patterns (authenticated)
      tags:
      - Learning
      - learning
  /api/learning/kpis:
    get:
      description: Get high-level learning performance indicators (Phase 5.3).
      operationId: get_learning_kpis_api_learning_kpis_get
      parameters:
      - in: query
        name: target
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TelemetryKpis'
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get learning KPIs (authenticated)
      tags:
      - Learning
      - learning
  /api/learning/thresholds:
    get:
      description: Get the history of automated threshold calibrations (Phase 5.3).
      operationId: get_threshold_history_api_learning_thresholds_get
      parameters:
      - in: query
        name: run_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run Id
      - in: query
        name: category
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Category
      - in: query
        name: limit
        required: false
        schema:
          default: 50
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  $ref: '#/components/schemas/ThresholdHistoryEntry'
                title: Response Get Threshold History Api Learning Thresholds Get
                type: array
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get threshold history (authenticated)
      tags:
      - Learning
      - learning
  /api/mesh/elect-leader:
    post:
      description: 'Manually trigger deterministic local leader election.


        SECURITY: requires admin authentication. The previous unauthenticated

        version allowed any caller to disrupt the mesh by forcing a leader

        election under a forged identity.'
      operationId: elect_leader_api_mesh_elect_leader_post
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Elect Leader Api Mesh Elect Leader Post
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '503':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Service Unavailable
      security:
      - APIKeyHeader: []
      summary: Manually trigger deterministic local leader election (admin only)
      tags:
      - Mesh
      - Mesh
  /api/notes/{target_name}:
    get:
      description: Return all notes for a target.
      operationId: get_notes_api_notes__target_name__get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteListResponse'
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get notes for a target
      tags:
      - Notes
      - Notes
    post:
      description: Create a new analyst note for a target.
      operationId: create_note_api_notes__target_name__post
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NoteCreateRequest'
        required: true
      responses:
        '201':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteResponse'
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Create a new note
      tags:
      - Notes
      - Notes
  /api/notes/{target_name}/{note_id}:
    delete:
      description: Delete a note.
      operationId: delete_note_api_notes__target_name___note_id__delete
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      - in: path
        name: note_id
        required: true
        schema:
          title: Note Id
          type: string
      - in: query
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteDeleteResponse'
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Delete a note
      tags:
      - Notes
      - Notes
    put:
      description: Update an existing note.
      operationId: update_note_api_notes__target_name___note_id__put
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      - in: path
        name: note_id
        required: true
        schema:
          title: Note Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NoteUpdateRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteResponse'
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Update a note
      tags:
      - Notes
      - Notes
  /api/notifications:
    delete:
      description: Delete all notifications.
      operationId: delete_all_notifications_api_notifications_delete
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DeleteResponse'
          description: Successful Response
      summary: Delete All Notifications
      tags:
      - Notifications
      - Notifications
    get:
      description: Return paginated notifications, newest first.
      operationId: list_notifications_api_notifications_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 100
          maximum: 500
          minimum: 1
          title: Limit
          type: integer
      - in: query
        name: offset
        required: false
        schema:
          default: 0
          minimum: 0
          title: Offset
          type: integer
      - in: query
        name: unread_only
        required: false
        schema:
          default: false
          title: Unread Only
          type: boolean
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NotificationListResponse'
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      summary: List Notifications
      tags:
      - Notifications
      - Notifications
  /api/notifications/read-all:
    patch:
      description: Mark all notifications as read.
      operationId: mark_all_read_api_notifications_read_all_patch
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/MarkReadResponse'
          description: Successful Response
      summary: Mark All Read
      tags:
      - Notifications
      - Notifications
  /api/notifications/stream:
    get:
      description: SSE endpoint for real-time notification streaming.
      operationId: notification_stream_api_notifications_stream_get
      responses:
        '200':
          content:
            application/json:
              schema:
                title: Response Notification Stream Api Notifications Stream Get
          description: Successful Response
      summary: Notification Stream
      tags:
      - Notifications
      - Notifications
  /api/notifications/unread-count:
    get:
      description: Return the count of unread notifications.
      operationId: unread_count_api_notifications_unread_count_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UnreadCountResponse'
          description: Successful Response
      summary: Unread Count
      tags:
      - Notifications
      - Notifications
  /api/notifications/{notification_id}:
    delete:
      description: Delete a single notification.
      operationId: delete_notification_api_notifications__notification_id__delete
      parameters:
      - in: path
        name: notification_id
        required: true
        schema:
          title: Notification Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DeleteResponse'
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      summary: Delete Notification
      tags:
      - Notifications
      - Notifications
  /api/notifications/{notification_id}/read:
    patch:
      description: Mark a single notification as read.
      operationId: mark_notification_read_api_notifications__notification_id__read_patch
      parameters:
      - in: path
        name: notification_id
        required: true
        schema:
          title: Notification Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/MarkReadResponse'
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      summary: Mark Notification Read
      tags:
      - Notifications
      - Notifications
  /api/registry:
    get:
      description: Return all registry data (modules, analysis, modes) in a single
        response.
      operationId: get_registry_api_registry_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get combined registry data
      tags:
      - Registry
      - Registry
  /api/registry/analysis:
    get:
      description: Return analysis check options, control groups, and focus presets.
      operationId: get_analysis_options_api_registry_analysis_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryAnalysisOptions'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get analysis check options
      tags:
      - Registry
      - Registry
  /api/registry/capabilities:
    get:
      description: Return the generated capability manifest for built-in and dynamic
        plugins.
      operationId: get_capabilities_api_registry_capabilities_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Capabilities Api Registry Capabilities Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get generated capability manifest
      tags:
      - Registry
      - Registry
  /api/registry/modes:
    get:
      description: Return mode presets and stage labels.
      operationId: get_mode_presets_api_registry_modes_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryModePresets'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get mode presets
      tags:
      - Registry
      - Registry
  /api/registry/modules:
    get:
      description: Return available module options and groups.
      operationId: get_module_options_api_registry_modules_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryModuleOptions'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get module options
      tags:
      - Registry
      - Registry
  /api/registry/plugins:
    get:
      description: Return hot-loaded third-party plugin manifests and validation errors.
      operationId: get_dynamic_plugins_api_registry_plugins_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Dynamic Plugins Api Registry Plugins Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get dynamic plugin catalog
      tags:
      - Registry
      - Registry
  /api/remediated/{finding_id}/verify:
    post:
      description: Verify whether a finding has been remediated by re-running the
        AEVE PoC bundle.
      operationId: verify_finding_remediation_api_remediated__finding_id__verify_post
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Verify Finding Remediation Api Remediated  Finding
                  Id  Verify Post
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
          detail: Unauthorized
        '403':
          description: Forbidden
          detail: Access denied
        '404':
          description: Not Found
          detail: Finding not found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
        '429':
          description: Too Many Requests
          detail: Rate limit exceeded
      security:
      - APIKeyHeader: []
      summary: Verify whether a vulnerability finding has been remediated
      tags:
      - Remediation Verification
      - Remediation Verification
      x-ai-action: verify_remediation
      x-ai-idempotency: false
      x-ai-impact: medium
      x-ai-requires:
      - finding_id
  /api/remediation/planner:
    get:
      description: Generate a tactical remediation plan by grouping findings across
        all targets.
      operationId: get_remediation_plan_api_remediation_planner_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Remediation Plan Api Remediation Planner Get
                type: object
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Get Remediation Plan
      tags:
      - Remediation
      - Remediation
  /api/replay:
    get:
      description: Replay a previously captured request and compare responses.
      operationId: replay_request_api_replay_get
      parameters:
      - description: Target name
        in: query
        name: target
        required: true
        schema:
          description: Target name
          title: Target
          type: string
      - description: Run name
        in: query
        name: run
        required: true
        schema:
          description: Run name
          title: Run
          type: string
      - description: Replay ID
        in: query
        name: replay_id
        required: true
        schema:
          description: Replay ID
          title: Replay Id
          type: string
      - description: Authentication mode
        in: query
        name: auth_mode
        required: false
        schema:
          default: inherit
          description: Authentication mode
          title: Auth Mode
          type: string
      - description: Bearer token for bearer mode
        in: query
        name: authorization
        required: false
        schema:
          default: ''
          description: Bearer token for bearer mode
          title: Authorization
          type: string
      - description: Cookie value to forward to the replay target
        in: query
        name: cookie
        required: false
        schema:
          default: ''
          description: Cookie value to forward to the replay target
          title: Cookie
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReplayResponse'
          description: Successful Response
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Replay a captured request
      tags:
      - Replay
      - Replay
  /api/reports/ai-summary:
    get:
      operationId: get_ai_executive_summary_api_reports_ai_summary_get
      parameters:
      - in: query
        name: target
        required: true
        schema:
          title: Target
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Ai Executive Summary Api Reports Ai Summary Get
                type: object
          description: Successful Response
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
        '500':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Internal Server Error
      security:
      - APIKeyHeader: []
      summary: Get AI executive security posture summary for a target
      tags:
      - Reports
  /api/reports/compliance/pdf:
    get:
      description: Return the compliance attestation PDF for the latest run of *target*.
      operationId: get_compliance_pdf_api_reports_compliance_pdf_get
      parameters:
      - in: query
        name: target
        required: true
        schema:
          title: Target
          type: string
      responses:
        '200':
          description: Successful Response
        '404':
          description: No run artifacts found for the given target
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
        '503':
          description: reportlab is not installed
      security:
      - APIKeyHeader: []
      summary: Download SOC 2 / PCI-DSS compliance attestation PDF
      tags:
      - Reports
  /api/reports/library:
    get:
      operationId: list_report_library_api_reports_library_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response List Report Library Api Reports Library Get
                type: object
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: List signed report artefacts across pipeline runs
      tags:
      - Reports
  /api/reports/platforms:
    get:
      description: Return a per-platform readiness summary.
      operationId: list_platforms_api_reports_platforms_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response List Platforms Api Reports Platforms Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: List configured bug-bounty platform clients
      tags:
      - Reports
  /api/reports/runs/{run_id}/findings/{finding_id}/submit:
    post:
      description: Push a finding to one of the supported platforms.
      operationId: submit_finding_to_platform_api_reports_runs__run_id__findings__finding_id__submit_post
      parameters:
      - in: path
        name: run_id
        required: true
        schema:
          title: Run Id
          type: string
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SubmitFindingPayload'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Submit Finding To Platform Api Reports Runs  Run Id  Findings  Finding
                  Id  Submit Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Submit a finding to a bug-bounty platform
      tags:
      - Reports
  /api/reports/sla/trending:
    get:
      description: Retrieve MTTR and active SLA breach trends for all tenant-scoped
        targets.
      operationId: get_sla_trending_api_reports_sla_trending_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Sla Trending Api Reports Sla Trending Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Get GRC SLA trending telemetry and active breaches
      tags:
      - Reports
  /api/risk-domain/acceptances:
    get:
      operationId: list_acceptances_api_risk_domain_acceptances_get
      parameters:
      - in: query
        name: state
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: State
      - in: query
        name: finding_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Id
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 2000
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response List Acceptances Api Risk Domain Acceptances Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List risk acceptances
      tags:
      - Risk Domain
      - Risk Domain
    post:
      operationId: create_acceptance_api_risk_domain_acceptances_post
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Create Acceptance Api Risk Domain Acceptances Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Create a risk acceptance
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/acceptances/{acceptance_id}/revoke:
    post:
      operationId: revoke_acceptance_api_risk_domain_acceptances__acceptance_id__revoke_post
      parameters:
      - in: path
        name: acceptance_id
        required: true
        schema:
          title: Acceptance Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Revoke Acceptance Api Risk Domain Acceptances  Acceptance
                  Id  Revoke Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Revoke a previously accepted risk
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/assets:
    get:
      operationId: list_assets_api_risk_domain_assets_get
      parameters:
      - in: query
        name: asset_type
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Asset Type
      - in: query
        name: active_only
        required: false
        schema:
          default: true
          title: Active Only
          type: boolean
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 2000
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response List Assets Api Risk Domain Assets Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List registered assets
      tags:
      - Risk Domain
      - Risk Domain
    post:
      operationId: create_asset_api_risk_domain_assets_post
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Create Asset Api Risk Domain Assets Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Create a new asset
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/assets/{asset_id}:
    delete:
      operationId: delete_asset_api_risk_domain_assets__asset_id__delete
      parameters:
      - in: path
        name: asset_id
        required: true
        schema:
          title: Asset Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Delete Asset Api Risk Domain Assets  Asset Id  Delete
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Delete an asset
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/controls:
    get:
      operationId: list_controls_api_risk_domain_controls_get
      parameters:
      - in: query
        name: finding_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Id
      - in: query
        name: control_type
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Control Type
      - in: query
        name: active_only
        required: false
        schema:
          default: true
          title: Active Only
          type: boolean
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 2000
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response List Controls Api Risk Domain Controls Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List compensating controls
      tags:
      - Risk Domain
      - Risk Domain
    post:
      operationId: create_control_api_risk_domain_controls_post
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Create Control Api Risk Domain Controls Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Add a compensating control
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/findings/{finding_id}/lifecycle:
    get:
      operationId: get_finding_lifecycle_api_risk_domain_findings__finding_id__lifecycle_get
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response Get Finding Lifecycle Api Risk Domain Findings  Finding
                  Id  Lifecycle Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get the lifecycle timeline for a single finding
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/findings/{finding_id}/review:
    post:
      operationId: record_reviewer_action_api_risk_domain_findings__finding_id__review_post
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Record Reviewer Action Api Risk Domain Findings  Finding
                  Id  Review Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Record a structured reviewer action (FindingReviewPanel)
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/findings/{finding_id}/review-history:
    get:
      operationId: get_review_history_api_risk_domain_findings__finding_id__review_history_get
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response Get Review History Api Risk Domain Findings  Finding
                  Id  Review History Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get the structured-review history for a finding
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/findings/{finding_id}/transition:
    post:
      operationId: transition_finding_api_risk_domain_findings__finding_id__transition_post
      parameters:
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Transition Finding Api Risk Domain Findings  Finding
                  Id  Transition Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Record a lifecycle state transition for a finding
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk-domain/sla/summary:
    get:
      description: 'Return aggregate per-stage SLA metrics.


        The summary is derived from the ``sla_events`` table, not from

        the live state of individual findings, so it can answer historical

        questions (e.g. "how long did triage take in the past N days?")

        without re-walking the entire ``findings`` table.'
      operationId: get_sla_summary_api_risk_domain_sla_summary_get
      parameters:
      - in: query
        name: days
        required: false
        schema:
          default: 30
          maximum: 365
          minimum: 1
          title: Days
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Sla Summary Api Risk Domain Sla Summary Get
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get lifecycle SLA summary (avg/worst per-stage lag, breaches)
      tags:
      - Risk Domain
      - Risk Domain
  /api/risk/factors:
    get:
      operationId: get_risk_factors_api_risk_factors_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Risk Factors Api Risk Factors Get
                type: object
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Get CSI factor documentation and weights
      tags:
      - Risk
      - Risk
  /api/risk/history:
    get:
      operationId: get_risk_history_api_risk_history_get
      parameters:
      - description: Target name to filter
        in: query
        name: target_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Target name to filter
          title: Target Id
      - in: query
        name: days
        required: false
        schema:
          default: 30
          maximum: 120
          minimum: 1
          title: Days
          type: integer
      - in: query
        name: group_by
        required: false
        schema:
          anyOf:
          - pattern: ^(target)$
            type: string
          - type: 'null'
          title: Group By
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                title: Response Get Risk History Api Risk History Get
                type: array
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get historical composite security index values
      tags:
      - Risk
      - Risk
  /api/security/api-keys:
    get:
      operationId: list_api_keys_api_security_api_keys_get
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  $ref: '#/components/schemas/APIKeyResponse'
                title: Response List Api Keys Api Security Api Keys Get
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
      security:
      - APIKeyHeader: []
      summary: List API keys
      tags:
      - Security
      - Security
    post:
      operationId: generate_api_key_api_security_api_keys_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/APIKeyCreateRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/APIKeyCreateResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Generate an API key
      tags:
      - Security
      - Security
  /api/security/api-keys/{key_id}:
    delete:
      operationId: revoke_api_key_api_security_api_keys__key_id__delete
      parameters:
      - in: path
        name: key_id
        required: true
        schema:
          title: Key Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties:
                  anyOf:
                  - type: boolean
                  - type: string
                title: Response Revoke Api Key Api Security Api Keys  Key Id  Delete
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Revoke an API key
      tags:
      - Security
      - Security
  /api/security/csp-reports:
    get:
      operationId: list_csp_reports_api_security_csp_reports_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 50
          maximum: 200
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  $ref: '#/components/schemas/CSPReportResponse'
                title: Response List Csp Reports Api Security Csp Reports Get
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List CSP violation reports
      tags:
      - Security
      - Security
  /api/security/events:
    get:
      operationId: list_security_events_api_security_events_get
      parameters:
      - in: query
        name: limit
        required: false
        schema:
          default: 100
          maximum: 500
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                items:
                  $ref: '#/components/schemas/SecurityEventResponse'
                title: Response List Security Events Api Security Events Get
                type: array
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List recent security events
      tags:
      - Security
      - Security
  /api/security/rate-limit-status:
    get:
      operationId: rate_limit_status_api_security_rate_limit_status_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RateLimitStatusResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '403':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Forbidden
      security:
      - APIKeyHeader: []
      summary: Get current rate limiting telemetry
      tags:
      - Security
      - Security
  /api/targets:
    get:
      operationId: list_targets_api_targets_get
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TargetListResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: List all targets
      tags:
      - Targets
      - Targets CRUD
  /api/targets/compare:
    get:
      description: Compare targets with traversal protection. (SEC-FIX)
      operationId: compare_targets_api_targets_compare_get
      parameters:
      - description: First target name
        in: query
        name: target_a
        required: true
        schema:
          description: First target name
          title: Target A
          type: string
      - description: Second target name
        in: query
        name: target_b
        required: true
        schema:
          description: Second target name
          title: Target B
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TargetComparisonResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Compare two targets side by side
      tags:
      - Targets
      - Targets Scoring
  /api/targets/findings/list:
    get:
      description: List all findings with traversal protection on target filter. (SEC-FIX)
      operationId: list_all_findings_api_targets_findings_list_get
      parameters:
      - description: Page number
        in: query
        name: page
        required: false
        schema:
          default: 1
          description: Page number
          minimum: 1
          title: Page
          type: integer
      - description: Items per page
        in: query
        name: page_size
        required: false
        schema:
          default: 50
          description: Items per page
          maximum: 1000
          minimum: 1
          title: Page Size
          type: integer
      - description: Filter by severity
        in: query
        name: severity
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by severity
          title: Severity
      - description: Filter by target name
        in: query
        name: target
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by target name
          title: Target
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response List All Findings Api Targets Findings List Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List all findings with pagination
      tags:
      - Targets
      - Targets CRUD
  /api/targets/{target_name}:
    delete:
      description: Delete a target output directory. (SEC-FIX)
      operationId: delete_target_api_targets__target_name__delete
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Delete Target Api Targets  Target Name  Delete
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Delete a target
      tags:
      - Targets
      - Targets CRUD
  /api/targets/{target_name}/compliance:
    get:
      description: Get the latest compliance report with traversal protection. (SEC-FIX)
      operationId: get_target_compliance_api_targets__target_name__compliance_get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Target Compliance Api Targets  Target Name  Compliance
                  Get
                type: object
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get compliance report for a target
      tags:
      - Targets
      - Targets CRUD
  /api/targets/{target_name}/findings:
    get:
      description: Retrieve findings for a specific target with traversal protection.
        (SEC-FIX)
      operationId: get_target_findings_api_targets__target_name__findings_get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      - description: Specific run name
        in: query
        name: run
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Specific run name
          title: Run
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TargetFindingsResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get findings for a target
      tags:
      - Targets
      - Targets CRUD
  /api/targets/{target_name}/historical-scores:
    get:
      description: Get historical scores with traversal protection. (SEC-FIX)
      operationId: get_historical_scores_api_targets__target_name__historical_scores_get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HistoricalScoreResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get historical scores for a target
      tags:
      - Targets
      - Targets Scoring
  /api/targets/{target_name}/risk-score:
    get:
      description: Get risk score with traversal protection. (SEC-FIX)
      operationId: get_risk_score_api_targets__target_name__risk_score_get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RiskScoreResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get risk score for a target
      tags:
      - Targets
      - Targets Scoring
  /api/targets/{target_name}/timeline:
    get:
      description: Retrieve timeline with traversal protection. (SEC-FIX)
      operationId: get_timeline_api_targets__target_name__timeline_get
      parameters:
      - in: path
        name: target_name
        required: true
        schema:
          title: Target Name
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TimelineResponse'
          description: Successful Response
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get timeline data for a target
      tags:
      - Targets
      - Targets CRUD
  /api/telemetry:
    post:
      operationId: report_frontend_telemetry_api_telemetry_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/FrontendTelemetryEvent'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Report Frontend Telemetry Api Telemetry Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      summary: Report Frontend Telemetry
      tags:
      - Analytics
  /api/traces:
    get:
      description: List recent traces from the local SQLite span store.
      operationId: list_traces_api_traces_get
      parameters:
      - in: query
        name: service_name
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Service Name
      - in: query
        name: start_ms
        required: false
        schema:
          anyOf:
          - type: integer
          - type: 'null'
          title: Start Ms
      - in: query
        name: end_ms
        required: false
        schema:
          anyOf:
          - type: integer
          - type: 'null'
          title: End Ms
      - in: query
        name: limit
        required: false
        schema:
          default: 100
          maximum: 500
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response List Traces Api Traces Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: List recent traces (authenticated)
      tags:
      - Tracing
      - Tracing
  /api/traces/{trace_id}:
    get:
      description: Return all spans for a trace in waterfall order.
      operationId: get_trace_api_traces__trace_id__get
      parameters:
      - in: path
        name: trace_id
        required: true
        schema:
          title: Trace Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Trace Api Traces  Trace Id  Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
        '404':
          description: Not found
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Return all spans for a trace (authenticated)
      tags:
      - Tracing
      - Tracing
  /api/tracing/config:
    get:
      description: 'Return OTLP exporter configuration and reachability.


        SECURITY: requires authentication. The configuration includes the

        OTLP endpoint URL and the service name, both of which leak

        internal architecture if exposed unauthenticated.'
      operationId: tracing_config_api_tracing_config_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Tracing Config Api Tracing Config Get
                type: object
          description: Successful Response
        '401':
          description: Unauthorized
      security:
      - APIKeyHeader: []
      summary: Return OTLP exporter configuration (authenticated)
      tags:
      - Tracing
      - Tracing
  /api/triage/audit/verify:
    get:
      operationId: verify_triage_audit_api_triage_audit_verify_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Verify Triage Audit Api Triage Audit Verify Get
                type: object
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Verify Triage Audit
      tags:
      - Triage Collaboration
      - Triage Collaboration
  /api/triage/runs/{run_id}/audit:
    get:
      operationId: get_triage_audit_api_triage_runs__run_id__audit_get
      parameters:
      - in: path
        name: run_id
        required: true
        schema:
          title: Run Id
          type: string
      - in: query
        name: finding_id
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Id
      - in: query
        name: limit
        required: false
        schema:
          default: 200
          maximum: 1000
          minimum: 1
          title: Limit
          type: integer
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Triage Audit Api Triage Runs  Run Id  Audit Get
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get Triage Audit
      tags:
      - Triage Collaboration
      - Triage Collaboration
  /api/triage/runs/{run_id}/findings/{finding_id}:
    get:
      operationId: get_finding_triage_state_api_triage_runs__run_id__findings__finding_id__get
      parameters:
      - in: path
        name: run_id
        required: true
        schema:
          title: Run Id
          type: string
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Finding Triage State Api Triage Runs  Run Id  Findings  Finding
                  Id  Get
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Get Finding Triage State
      tags:
      - Triage Collaboration
      - Triage Collaboration
  /api/triage/runs/{run_id}/findings/{finding_id}/actions:
    post:
      operationId: record_triage_action_api_triage_runs__run_id__findings__finding_id__actions_post
      parameters:
      - in: path
        name: run_id
        required: true
        schema:
          title: Run Id
          type: string
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              title: Payload
              type: object
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Record Triage Action Api Triage Runs  Run Id  Findings  Finding
                  Id  Actions Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Record Triage Action
      tags:
      - Triage Collaboration
      - Triage Collaboration
  /api/triage/runs/{run_id}/findings/{finding_id}/ai-review:
    post:
      operationId: ai_triage_finding_api_triage_runs__run_id__findings__finding_id__ai_review_post
      parameters:
      - in: path
        name: run_id
        required: true
        schema:
          title: Run Id
          type: string
      - in: path
        name: finding_id
        required: true
        schema:
          title: Finding Id
          type: string
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Ai Triage Finding Api Triage Runs  Run Id  Findings  Finding
                  Id  Ai Review Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Ai Triage Finding
      tags:
      - Triage Collaboration
      - Triage Collaboration
  /api/version:
    get:
      operationId: get_version_api_version_get
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Get Version Api Version Get
                type: object
          description: Successful Response
      summary: Get Version
      tags:
      - System
  /api/webhooks/test:
    post:
      description: Test a custom HTTP webhook integration.
      operationId: test_webhook_api_webhooks_test_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/WebhookTestRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Test Webhook Api Webhooks Test Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Test Webhook
      tags:
      - Webhooks
      - Webhooks
  /api/webhooks/test-slack:
    post:
      description: Test a Slack Incoming Webhook integration.
      operationId: test_slack_api_webhooks_test_slack_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SlackTestRequest'
        required: true
      responses:
        '200':
          content:
            application/json:
              schema:
                additionalProperties: true
                title: Response Test Slack Api Webhooks Test Slack Post
                type: object
          description: Successful Response
        '422':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
          description: Validation Error
      security:
      - APIKeyHeader: []
      summary: Test Slack
      tags:
      - Webhooks
      - Webhooks
  /metrics:
    get:
      operationId: get_metrics_metrics_get
      responses:
        '200':
          content:
            application/json:
              schema:
                title: Response Get Metrics Metrics Get
          description: Successful Response
      security:
      - APIKeyHeader: []
      summary: Get Metrics
      tags:
      - System
```

---

## 📡 WebSocket Logs
- `WS /ws/logs/{job_id}`: Stream live logs.
- `x-ai-role`: Used by `auditor` agents to monitor execution in real-time.
- **Message Format**: JSON object corresponding to the `LogMessage` protocol schema:
  - `id`: string (monotonically unique message UUID)
  - `type`: string (value is `"log"`)
  - `sequence`: integer (monotonically increasing counter for client-side ordering checks)
  - `timestamp`: number (epoch float when the message was emitted)
  - `job_id`: string
  - `line`: string (raw content of the log line)
  - `source`: string (value is `"stdout"` or `"stderr"`)
  - `level`: string (value is `"info"`, `"warning"`, or `"error"`)
- **Auth**: Attempts authentication in the following order:
  1. JWT token via subprotocol `Sec-WebSocket-Protocol: bearer.<jwt>`
  2. API key from `x-api-key` header
  3. API key from `?api_key=<key>` query parameter
  *(Note: The legacy `token` query parameter or `X-API-Key` query parameters are not evaluated.)*
