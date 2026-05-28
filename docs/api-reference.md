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
openapi: 3.1.0
info:
  title: Cyber Security Test Pipeline Dashboard
  description: Unified security orchestration and vulnerability analysis dashboard.
  version: 2.0.0
  x-ai-metadata:
    agent_roles:
    - orchestrator
    - worker
    - dashboard
    - auditor
    stateful_endpoints:
    - /api/jobs/{id}
    - /api/jobs/{id}/progress/stream
    mesh_aware: true
paths:
  /api/health:
    get:
      tags:
      - Health
      - Health
      summary: Health check
      description: Comprehensive health check endpoint with distributed mesh telemetry.
      operationId: health_check_api_health_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'
  /api/health/mesh:
    get:
      tags:
      - Health
      - Health
      summary: Mesh health
      description: Return detailed local view of mesh membership and transport health.
      operationId: mesh_health_api_health_mesh_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Mesh Health Api Health Mesh Get
      x-ai-action: get_mesh_health
      x-ai-idempotency: true
  /api/health/ready:
    get:
      tags:
      - System
      summary: Health Check Ready
      description: Readiness probe with subsystem checks.
      operationId: health_check_ready_api_health_ready_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Health Check Ready Api Health Ready Get
      x-ai-action: check_readiness
      x-ai-idempotency: true
  /api/health/live:
    get:
      tags:
      - System
      summary: Health Check Live
      operationId: health_check_live_api_health_live_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Health Check Live Api Health Live Get
  /api/remediated/{finding_id}/verify:
    post:
      tags:
      - Remediation Verification
      - Remediation Verification
      summary: Verify whether a vulnerability finding has been remediated
      description: Verify whether a finding has been remediated by re-running the
        AEVE PoC bundle.
      operationId: verify_finding_remediation_api_remediated__finding_id__verify_post
      security:
      - APIKeyHeader: []
      parameters:
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Verify Finding Remediation Api Remediated  Finding
                  Id  Verify Post
        '404':
          detail: Finding not found
          description: Not Found
        '401':
          detail: Unauthorized
          description: Unauthorized
        '403':
          detail: Access denied
          description: Forbidden
        '429':
          detail: Rate limit exceeded
          description: Too Many Requests
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      x-ai-action: verify_remediation
      x-ai-idempotency: false
      x-ai-impact: medium
      x-ai-requires:
      - finding_id
  /api/health/self-healing:
    get:
      tags:
      - Self-Healing
      - Self-Healing
      summary: Self Healing Snapshot
      description: Return the latest autonomous recovery snapshot.
      operationId: self_healing_snapshot_api_health_self_healing_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Self Healing Snapshot Api Health Self Healing Get
  /api/health/self-healing/evaluate:
    post:
      tags:
      - Self-Healing
      - Self-Healing
      summary: Evaluate Self Healing
      description: Run one immediate controller pass.
      operationId: evaluate_self_healing_api_health_self_healing_evaluate_post
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Evaluate Self Healing Api Health Self Healing Evaluate
                  Post
  /api/health/self-healing/tile:
    get:
      tags:
      - Self-Healing
      - Self-Healing
      summary: Self Healing Tile
      description: Compact health tile payload for dashboard clients.
      operationId: self_healing_tile_api_health_self_healing_tile_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Self Healing Tile Api Health Self Healing Tile Get
  /api/audit/entries:
    get:
      tags:
      - Audit
      - Audit
      summary: Get audit log entries
      description: Return audit log entries with filtering and pagination.
      operationId: get_audit_entries_api_audit_entries_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 1000
          minimum: 1
          default: 100
          title: Limit
      - name: offset
        in: query
        required: false
        schema:
          type: integer
          minimum: 0
          default: 0
          title: Offset
      - name: event
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Event
      - name: user_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: User Id
      - name: severity
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Severity
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  additionalProperties: true
                title: Response Get Audit Entries Api Audit Entries Get
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/audit/verify:
    get:
      tags:
      - Audit
      - Audit
      summary: Verify audit log integrity
      description: Check the hash chain of the audit log to detect tampering.
      operationId: verify_audit_integrity_api_audit_verify_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Verify Audit Integrity Api Audit Verify Get
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/bloom/health:
    get:
      tags:
      - Bloom
      - Bloom
      summary: Bloom Health
      description: Return Bloom filter mesh health for dashboard tiles.
      operationId: bloom_health_api_bloom_health_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Bloom Health Api Bloom Health Get
      x-ai-action: get_bloom_health
      x-ai-idempotency: true
  /api/bloom/reconcile:
    post:
      tags:
      - Bloom
      - Bloom
      summary: Reconcile Bloom Mesh
      description: Force an immediate Bloom snapshot publish across online nodes.
      operationId: reconcile_bloom_mesh_api_bloom_reconcile_post
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Reconcile Bloom Mesh Api Bloom Reconcile Post
      security:
      - APIKeyHeader: []
      x-ai-action: reconcile_bloom_mesh
      x-ai-idempotency: true
      x-ai-impact: medium
  /api/cockpit/attack-chains:
    get:
      tags:
      - Cockpit
      - Cockpit
      summary: Get lateral movement attack chains
      description: Return identified attack chains linking multiple vulnerabilities
        and assets.
      operationId: get_attack_chains_api_cockpit_attack_chains_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          minLength: 1
          title: Target
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/AttackChainSchema'
                title: Response Get Attack Chains Api Cockpit Attack Chains Get
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/cockpit/graph:
    get:
      tags:
      - Cockpit
      - Cockpit
      summary: Get 3D threat graph data
      description: Build and return 3D threat graph data for the cockpit.
      operationId: get_cockpit_graph_api_cockpit_graph_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          minLength: 1
          title: Target
      - name: run
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run
      - name: job_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Job Id
      - name: max_nodes
        in: query
        required: false
        schema:
          type: integer
          maximum: 10000
          minimum: 1
          default: 2000
          title: Max Nodes
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Cockpit Graph Api Cockpit Graph Get
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/cockpit/events:
    get:
      tags:
      - Cockpit
      - Cockpit
      summary: Get cockpit event timeline
      description: Return a timeline of cockpit-relevant events.
      operationId: get_cockpit_events_api_cockpit_events_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          minLength: 1
          title: Target
      - name: run
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run
      - name: job_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Job Id
      - name: cursor
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Cursor
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Cockpit Events Api Cockpit Events Get
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/cockpit/graph/stream:
    get:
      tags:
      - Cockpit
      - Cockpit
      summary: Stream cockpit graph snapshots
      description: Stream graph snapshots so the 3D cockpit can ingest pipeline additions
        live.
      operationId: stream_cockpit_graph_api_cockpit_graph_stream_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          title: Target
      - name: run
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run
      - name: job_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Job Id
      - name: interval_seconds
        in: query
        required: false
        schema:
          type: number
          maximum: 15.0
          minimum: 0.5
          default: 2.0
          title: Interval Seconds
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema: {}
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/cockpit/forensics:
    get:
      tags:
      - Cockpit
      - Cockpit
      summary: List forensic exchanges for a target
      description: List forensic exchanges stored for a target.
      operationId: list_forensic_exchanges_api_cockpit_forensics_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          minLength: 1
          title: Target
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response List Forensic Exchanges Api Cockpit Forensics Get
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/cockpit/forensics/{exchange_id}:
    get:
      tags:
      - Cockpit
      - Cockpit
      summary: Get forensic exchange details
      description: Retrieve a forensic exchange artifact from disk.
      operationId: get_forensic_exchange_api_cockpit_forensics__exchange_id__get
      security:
      - APIKeyHeader: []
      parameters:
      - name: exchange_id
        in: path
        required: true
        schema:
          type: string
          title: Exchange Id
      - name: target
        in: query
        required: true
        schema:
          type: string
          minLength: 1
          title: Target
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Forensic Exchange Api Cockpit Forensics  Exchange
                  Id  Get
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/cockpit/probes:
    post:
      tags:
      - Cockpit
      - Cockpit
      summary: Trigger a manual forensic probe
      description: Trigger a manual probe with scope validation and forensic capture.
      operationId: trigger_cockpit_probe_api_cockpit_probes_post
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          minLength: 1
          title: Target
      - name: url
        in: query
        required: true
        schema:
          type: string
          minLength: 1
          title: Url
      - name: method
        in: query
        required: false
        schema:
          type: string
          default: GET
          title: Method
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Trigger Cockpit Probe Api Cockpit Probes Post
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs:
    get:
      tags:
      - Jobs
      summary: List all jobs
      description: List all scan jobs with sorting, filtering and pagination.
      operationId: list_jobs_api_jobs_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: page
        in: query
        required: false
        schema:
          type: integer
          minimum: 1
          description: Page number
          default: 1
          title: Page
        description: Page number
      - name: page_size
        in: query
        required: false
        schema:
          type: integer
          maximum: 100
          minimum: 1
          description: Items per page
          default: 20
          title: Page Size
        description: Items per page
      - name: status
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by status
          title: Status
        description: Filter by status
      - name: sort_by
        in: query
        required: false
        schema:
          type: string
          description: Sort field
          default: started_at
          title: Sort By
        description: Sort field
      - name: sort_order
        in: query
        required: false
        schema:
          type: string
          pattern: ^(asc|desc)$
          description: Sort order
          default: desc
          title: Sort Order
        description: Sort order
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobListResponse'
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      x-ai-action: list_jobs
      x-ai-idempotency: true
    post:
      tags:
      - Jobs
      summary: Start a new scan job
      description: 'Start a new pipeline scan job.


        Creates a job record, writes config/scope files, and launches

        the pipeline subprocess in a background thread.'
      operationId: start_job_api_jobs_post
      security:
      - APIKeyHeader: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/JobCreateRequest'
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
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
        '429':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Too Many Requests
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      x-ai-action: start_scan
      x-ai-requires:
      - base_url
      x-ai-idempotency: false
      x-ai-impact: high
  /api/jobs/historical-durations:
    get:
      tags:
      - Jobs
      summary: Get historical stage durations
      description: Return historical duration statistics for each pipeline stage based
        on past job runs. Requires ENABLE_DURATION_FORECAST=true.
      operationId: get_historical_durations_api_jobs_historical_durations_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                title: Response Get Historical Durations Api Jobs Historical Durations
                  Get
        '501':
          description: Not Implemented
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/jobs/{job_id}:
    get:
      tags:
      - Jobs
      summary: Get job details
      operationId: get_job_api_jobs__job_id__get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/{job_id}/trace:
    get:
      tags:
      - Jobs
      summary: Get the Jaeger deep link for a job trace
      operationId: get_job_trace_link_api_jobs__job_id__trace_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties:
                  type: string
                title: Response Get Job Trace Link Api Jobs  Job Id  Trace Get
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/{job_id}/remediation:
    get:
      tags:
      - Jobs
      summary: Get fix-command suggestions for a failed job
      operationId: get_job_remediation_api_jobs__job_id__remediation_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Job Remediation Api Jobs  Job Id  Remediation
                  Get
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/{job_id}/logs:
    get:
      tags:
      - Jobs
      summary: Get job logs
      operationId: get_job_logs_api_jobs__job_id__logs_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobLogsResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/{job_id}/logs/stream:
    get:
      tags:
      - Jobs
      summary: Stream job logs (SSE)
      description: Stream process logs in real-time, optionally enriched with progress
        metadata.
      operationId: stream_job_logs_api_jobs__job_id__logs_stream_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema: {}
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/{job_id}/progress/stream:
    get:
      tags:
      - Jobs
      summary: Stream job progress events (SSE)
      description: Stream real-time job execution stage transitions, metrics, and
        consistent hashing topology.
      operationId: stream_job_progress_api_jobs__job_id__progress_stream_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema: {}
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
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
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/start:
    post:
      tags:
      - Jobs
      summary: Start a new scan job
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
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
        '400':
          description: Bad Request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '429':
          description: Too Many Requests
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      security:
      - APIKeyHeader: []
  /api/jobs/{job_id}/stop:
    post:
      tags:
      - Jobs
      summary: Stop a running job
      operationId: stop_job_api_jobs__job_id__stop_post
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/{job_id}/restart-safe:
    post:
      tags:
      - Jobs
      summary: Restart a job with safe defaults
      operationId: restart_job_safe_api_jobs__job_id__restart_safe_post
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/jobs/{job_id}/timeline:
    get:
      tags:
      - Jobs
      summary: Get job execution timeline
      description: Return execution timeline for a job showing stage transitions.
      operationId: get_job_timeline_api_jobs__job_id__timeline_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: path
        required: true
        schema:
          type: string
          title: Job Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Job Timeline Api Jobs  Job Id  Timeline Get
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/learning/thresholds:
    get:
      tags:
      - Learning
      - learning
      summary: Get Threshold History
      description: Get the history of automated threshold calibrations (Phase 5.3).
      operationId: get_threshold_history_api_learning_thresholds_get
      parameters:
      - name: run_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run Id
      - name: category
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Category
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          default: 50
          title: Limit
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ThresholdHistoryEntry'
                title: Response Get Threshold History Api Learning Thresholds Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/learning/fp-patterns:
    get:
      tags:
      - Learning
      - learning
      summary: Get Fp Patterns
      description: Get the current repository of learned false positive patterns (Phase
        5.3).
      operationId: get_fp_patterns_api_learning_fp_patterns_get
      parameters:
      - name: category
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Category
      - name: active_only
        in: query
        required: false
        schema:
          type: boolean
          default: true
          title: Active Only
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/FpPatternEntry'
                title: Response Get Fp Patterns Api Learning Fp Patterns Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/learning/kpis:
    get:
      tags:
      - Learning
      - learning
      summary: Get Learning Kpis
      description: Get high-level learning performance indicators (Phase 5.3).
      operationId: get_learning_kpis_api_learning_kpis_get
      parameters:
      - name: target
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TelemetryKpis'
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/learning/feedback:
    get:
      tags:
      - Learning
      - learning
      summary: Get Feedback Events
      description: Get feedback events for analysis and inspection (Phase 5.3).
      operationId: get_feedback_events_api_learning_feedback_get
      parameters:
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 10000
          minimum: 1
          default: 100
          title: Limit
      - name: run_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Run Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/FeedbackEventEntry'
                title: Response Get Feedback Events Api Learning Feedback Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/learning/db-stats:
    get:
      tags:
      - Learning
      - learning
      summary: Get Learning Db Stats
      description: Get statistics about the telemetry database (Phase 5.3).
      operationId: get_learning_db_stats_api_learning_db_stats_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties:
                  type: integer
                type: object
                title: Response Get Learning Db Stats Api Learning Db Stats Get
  /api/mesh/elect-leader:
    post:
      tags:
      - Mesh
      - Mesh
      summary: Elect Leader
      description: Manually trigger deterministic local leader election.
      operationId: elect_leader_api_mesh_elect_leader_post
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Elect Leader Api Mesh Elect Leader Post
  /api/targets:
    get:
      tags:
      - Targets
      summary: List all targets
      operationId: list_targets_api_targets_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TargetListResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/targets/{target_name}:
    delete:
      tags:
      - Targets
      summary: Delete a target
      description: Delete a target output directory.
      operationId: delete_target_api_targets__target_name__delete
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Delete Target Api Targets  Target Name  Delete
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/targets/{target_name}/findings:
    get:
      tags:
      - Targets
      summary: Get findings for a target
      operationId: get_target_findings_api_targets__target_name__findings_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      - name: run
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Specific run name
          title: Run
        description: Specific run name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TargetFindingsResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/targets/{target_name}/risk-score:
    get:
      tags:
      - Targets
      summary: Get risk score for a target
      operationId: get_risk_score_api_targets__target_name__risk_score_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RiskScoreResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/targets/{target_name}/timeline:
    get:
      tags:
      - Targets
      summary: Get timeline data for a target
      operationId: get_timeline_api_targets__target_name__timeline_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TimelineResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/targets/{target_name}/historical-scores:
    get:
      tags:
      - Targets
      summary: Get historical scores for a target
      operationId: get_historical_scores_api_targets__target_name__historical_scores_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HistoricalScoreResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/targets/{target_name}/compliance:
    get:
      tags:
      - Targets
      summary: Get compliance report for a target
      description: Get the latest compliance coverage and maturity report (Phase 6).
      operationId: get_target_compliance_api_targets__target_name__compliance_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Target Compliance Api Targets  Target Name  Compliance
                  Get
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/targets/findings/list:
    get:
      tags:
      - Targets
      summary: List all findings with pagination
      description: List all findings across all targets with pagination support.
      operationId: list_all_findings_api_targets_findings_list_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: page
        in: query
        required: false
        schema:
          type: integer
          minimum: 1
          description: Page number
          default: 1
          title: Page
        description: Page number
      - name: page_size
        in: query
        required: false
        schema:
          type: integer
          maximum: 200
          minimum: 1
          description: Items per page
          default: 50
          title: Page Size
        description: Items per page
      - name: severity
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by severity
          title: Severity
        description: Filter by severity
      - name: target
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by target name
          title: Target
        description: Filter by target name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response List All Findings Api Targets Findings List Get
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/targets/compare:
    get:
      tags:
      - Targets
      summary: Compare two targets side by side
      operationId: compare_targets_api_targets_compare_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_a
        in: query
        required: true
        schema:
          type: string
          description: First target name
          title: Target A
        description: First target name
      - name: target_b
        in: query
        required: true
        schema:
          type: string
          description: Second target name
          title: Target B
        description: Second target name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TargetComparisonResponse'
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/findings:
    get:
      tags:
      - Findings
      - Findings
      summary: Get summary of all findings
      description: Return a global summary of findings across all targets.
      operationId: get_findings_summary_api_findings_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/FindingsSummaryResponse'
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/findings/timeline:
    get:
      tags:
      - Findings
      - Findings
      summary: Get finding discovery events across jobs
      operationId: get_findings_timeline_api_findings_timeline_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: job_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by job or run identifier
          title: Job Id
        description: Filter by job or run identifier
      - name: severity
        in: query
        required: false
        schema:
          anyOf:
          - type: string
            pattern: ^(critical|high|medium|low|info)$
          - type: 'null'
          title: Severity
      - name: target
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Filter by target name
          title: Target
        description: Filter by target name
      - name: start_date
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Inclusive ISO start date
          title: Start Date
        description: Inclusive ISO start date
      - name: end_date
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Inclusive ISO end date
          title: End Date
        description: Inclusive ISO end date
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 200
          minimum: 1
          default: 50
          title: Limit
      - name: offset
        in: query
        required: false
        schema:
          type: integer
          minimum: 0
          default: 0
          title: Offset
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  additionalProperties: true
                title: Response Get Findings Timeline Api Findings Timeline Get
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/findings/{finding_id}:
    get:
      tags:
      - Findings
      - Findings
      summary: Get individual finding details
      description: Retrieve full details for a specific finding by ID.
      operationId: get_finding_detail_api_findings__finding_id__get
      security:
      - APIKeyHeader: []
      parameters:
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Finding Detail Api Findings  Finding Id  Get
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
    put:
      tags:
      - Findings
      - Findings
      summary: Update a finding
      description: Update finding metadata (status, severity, etc.) on disk.
      operationId: update_finding_api_findings__finding_id__put
      security:
      - APIKeyHeader: []
      parameters:
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: true
              title: Update Data
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Update Finding Api Findings  Finding Id  Put
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      x-ai-action: update_finding
      x-ai-idempotency: false
    delete:
      tags:
      - Findings
      - Findings
      summary: Delete a finding
      description: Remove a finding from disk.
      operationId: delete_finding_api_findings__finding_id__delete
      security:
      - APIKeyHeader: []
      parameters:
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties:
                  type: boolean
                title: Response Delete Finding Api Findings  Finding Id  Delete
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      x-ai-action: delete_finding
      x-ai-idempotency: false
      x-ai-impact: high
  /api/findings/{finding_id}/remediation:
    get:
      tags:
      - Findings
      - Findings
      summary: Get fix-command suggestions for a finding
      operationId: get_finding_remediation_api_findings__finding_id__remediation_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Finding Remediation Api Findings  Finding Id  Remediation
                  Get
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/findings/{finding_id}/explain:
    get:
      tags:
      - Findings
      - Findings
      summary: Get ML explainability analysis (SHAP) for a finding
      operationId: explain_finding_severity_api_findings__finding_id__explain_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Explain Finding Severity Api Findings  Finding Id  Explain
                  Get
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/findings/bulk:
    put:
      tags:
      - Findings
      - Findings
      summary: Bulk update findings
      description: Apply updates to multiple findings.
      operationId: bulk_update_findings_api_findings_bulk_put
      requestBody:
        content:
          application/json:
            schema:
              additionalProperties: true
              type: object
              title: Payload
        required: true
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                items:
                  additionalProperties: true
                  type: object
                type: array
                title: Response Bulk Update Findings Api Findings Bulk Put
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      security:
      - APIKeyHeader: []
  /api/cache/stats:
    get:
      tags:
      - Cache
      - Cache
      summary: Get cache statistics
      description: Return cache statistics including hit/miss rates and entry counts.
      operationId: get_cache_stats_api_cache_stats_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheStatsResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/cache/status:
    get:
      tags:
      - Cache
      - Cache
      summary: Get cache backend status
      description: Return Redis and SQLite cache status without mutating cache contents.
      operationId: get_cache_status_api_cache_status_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheStatusResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/cache/keys:
    get:
      tags:
      - Cache
      - Cache
      summary: List Redis keys
      description: List Redis keys matching a glob pattern with TTL and size metadata.
      operationId: list_cache_keys_api_cache_keys_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: pattern
        in: query
        required: false
        schema:
          type: string
          minLength: 1
          maxLength: 512
          default: '*'
          title: Pattern
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 1000
          minimum: 1
          default: 100
          title: Limit
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheKeysResponse'
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
    delete:
      tags:
      - Cache
      - Cache
      summary: Delete Redis keys by pattern
      description: Delete Redis keys matching a pattern using SCAN and batched DEL.
      operationId: delete_cache_keys_api_cache_keys_delete
      security:
      - APIKeyHeader: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CacheKeyDeleteRequest'
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheKeyDeleteResponse'
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/cache/performance-history:
    get:
      tags:
      - Cache
      - Cache
      summary: Get cache performance history
      description: Return the last hour of one-minute cache hit/miss samples.
      operationId: get_cache_performance_history_api_cache_performance_history_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CachePerformanceHistoryResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/cache/cleanup:
    post:
      tags:
      - Cache
      - Cache
      summary: Trigger cache cleanup
      description: Run cache cleanup to remove expired entries.
      operationId: trigger_cache_cleanup_api_cache_cleanup_post
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheCleanupResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/cache/clear:
    post:
      tags:
      - Cache
      - Cache
      summary: Clear all cache entries
      description: Clear all entries from the configured cache manager.
      operationId: clear_all_cache_api_cache_clear_post
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheNamespaceResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/cache/{namespace}:
    delete:
      tags:
      - Cache
      - Cache
      summary: Invalidate cache namespace
      description: Clear all entries in the specified cache namespace.
      operationId: invalidate_cache_namespace_api_cache__namespace__delete
      security:
      - APIKeyHeader: []
      parameters:
      - name: namespace
        in: path
        required: true
        schema:
          type: string
          title: Namespace
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheNamespaceResponse'
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/defaults:
    get:
      tags:
      - Defaults
      - Defaults
      summary: Get form and system defaults
      description: Return default settings for forms and UI components.
      operationId: get_defaults_api_defaults_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ApiDefaults'
      security:
      - APIKeyHeader: []
  /api/notes/{target_name}:
    get:
      tags:
      - Notes
      - Notes
      summary: Get notes for a target
      description: Return all notes for a target.
      operationId: get_notes_api_notes__target_name__get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteListResponse'
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
    post:
      tags:
      - Notes
      - Notes
      summary: Create a new note
      description: Create a new analyst note for a target.
      operationId: create_note_api_notes__target_name__post
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NoteCreateRequest'
      responses:
        '201':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteResponse'
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/notes/{target_name}/{note_id}:
    put:
      tags:
      - Notes
      - Notes
      summary: Update a note
      description: Update an existing note.
      operationId: update_note_api_notes__target_name___note_id__put
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      - name: note_id
        in: path
        required: true
        schema:
          type: string
          title: Note Id
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NoteUpdateRequest'
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteResponse'
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
    delete:
      tags:
      - Notes
      - Notes
      summary: Delete a note
      description: Delete a note.
      operationId: delete_note_api_notes__target_name___note_id__delete
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      - name: note_id
        in: path
        required: true
        schema:
          type: string
          title: Note Id
      - name: finding_id
        in: query
        required: true
        schema:
          type: string
          title: Finding Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NoteDeleteResponse'
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/export/findings/all:
    get:
      tags:
      - Export
      - Export
      summary: Export findings from all targets
      description: Export findings from all targets in CSV or JSON format.
      operationId: export_all_findings_api_export_findings_all_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: format
        in: query
        required: false
        schema:
          type: string
          pattern: ^(csv|json)$
          description: 'Export format: csv or json'
          default: json
          title: Format
        description: 'Export format: csv or json'
      - name: max_targets
        in: query
        required: false
        schema:
          type: integer
          maximum: 200
          minimum: 1
          description: Maximum number of targets to export
          default: 50
          title: Max Targets
        description: Maximum number of targets to export
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema: {}
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/export/findings/{target_name}:
    get:
      tags:
      - Export
      - Export
      summary: Export findings for a target
      description: Export all findings for a target in CSV or JSON format.
      operationId: export_findings_api_export_findings__target_name__get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      - name: format
        in: query
        required: false
        schema:
          type: string
          pattern: ^(csv|json)$
          description: 'Export format: csv or json'
          default: json
          title: Format
        description: 'Export format: csv or json'
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema: {}
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/export/findings/{target_name}/latest:
    get:
      tags:
      - Export
      - Export
      summary: Export latest findings for a target
      description: Export findings from the latest run for a target.
      operationId: export_latest_findings_api_export_findings__target_name__latest_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      - name: format
        in: query
        required: false
        schema:
          type: string
          pattern: ^(csv|json)$
          description: 'Export format: csv or json'
          default: json
          title: Format
        description: 'Export format: csv or json'
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema: {}
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/export/compliance/{target_name}/attestation:
    get:
      tags:
      - Export
      - Export
      summary: Export compliance attestation (SOC 2 / PCI DSS)
      description: Export a high-fidelity HTML compliance attestation (Phase 6.3).
      operationId: export_compliance_attestation_api_export_compliance__target_name__attestation_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: path
        required: true
        schema:
          type: string
          title: Target Name
      - name: format
        in: query
        required: false
        schema:
          type: string
          pattern: ^(html|pdf)$
          description: 'Export format: html or pdf'
          default: pdf
          title: Format
        description: 'Export format: html or pdf'
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema: {}
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/replay:
    get:
      tags:
      - Replay
      - Replay
      summary: Replay a captured request
      description: Replay a previously captured request and compare responses.
      operationId: replay_request_api_replay_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          description: Target name
          title: Target
        description: Target name
      - name: run
        in: query
        required: true
        schema:
          type: string
          description: Run name
          title: Run
        description: Run name
      - name: replay_id
        in: query
        required: true
        schema:
          type: string
          description: Replay ID
          title: Replay Id
        description: Replay ID
      - name: auth_mode
        in: query
        required: false
        schema:
          type: string
          description: Authentication mode
          default: inherit
          title: Auth Mode
        description: Authentication mode
      - name: authorization
        in: query
        required: false
        schema:
          type: string
          description: Authorization header value
          default: ''
          title: Authorization
        description: Authorization header value
      - name: cookie
        in: query
        required: false
        schema:
          type: string
          description: Cookie value
          default: ''
          title: Cookie
        description: Cookie value
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReplayResponse'
        '400':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Bad Request
        '404':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Not Found
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/risk/history:
    get:
      tags:
      - Risk
      - Risk
      summary: Get historical composite security index values
      operationId: get_risk_history_api_risk_history_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Target name to filter
          title: Target Id
        description: Target name to filter
      - name: days
        in: query
        required: false
        schema:
          type: integer
          maximum: 120
          minimum: 1
          default: 30
          title: Days
      - name: group_by
        in: query
        required: false
        schema:
          anyOf:
          - type: string
            pattern: ^(target)$
          - type: 'null'
          title: Group By
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  additionalProperties: true
                title: Response Get Risk History Api Risk History Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/risk/factors:
    get:
      tags:
      - Risk
      - Risk
      summary: Get CSI factor documentation and weights
      operationId: get_risk_factors_api_risk_factors_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Get Risk Factors Api Risk Factors Get
      security:
      - APIKeyHeader: []
  /api/remediation/planner:
    get:
      tags:
      - Remediation
      - Remediation
      summary: Get Remediation Plan
      description: Generate a tactical remediation plan by grouping findings across
        all targets.
      operationId: get_remediation_plan_api_remediation_planner_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Get Remediation Plan Api Remediation Planner Get
      security:
      - APIKeyHeader: []
  /api/reports/library:
    get:
      tags:
      - Reports
      summary: List signed report artefacts across pipeline runs
      operationId: list_report_library_api_reports_library_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response List Report Library Api Reports Library Get
      security:
      - APIKeyHeader: []
  /api/reports/compliance/pdf:
    get:
      tags:
      - Reports
      summary: Download SOC 2 / PCI-DSS compliance attestation PDF
      description: Return the compliance attestation PDF for the latest run of *target*.
      operationId: get_compliance_pdf_api_reports_compliance_pdf_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: true
        schema:
          type: string
          title: Target
      responses:
        '200':
          description: Successful Response
        '404':
          description: No run artifacts found for the given target
        '503':
          description: reportlab is not installed
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/registry/modules:
    get:
      tags:
      - Registry
      - Registry
      summary: Get module options
      description: Return available module options and groups.
      operationId: get_module_options_api_registry_modules_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryModuleOptions'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/registry/analysis:
    get:
      tags:
      - Registry
      - Registry
      summary: Get analysis check options
      description: Return analysis check options, control groups, and focus presets.
      operationId: get_analysis_options_api_registry_analysis_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryAnalysisOptions'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/registry/modes:
    get:
      tags:
      - Registry
      - Registry
      summary: Get mode presets
      description: Return mode presets and stage labels.
      operationId: get_mode_presets_api_registry_modes_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryModePresets'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/registry:
    get:
      tags:
      - Registry
      - Registry
      summary: Get combined registry data
      description: Return all registry data (modules, analysis, modes) in a single
        response.
      operationId: get_registry_api_registry_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegistryResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/registry/plugins:
    get:
      tags:
      - Registry
      - Registry
      summary: Get dynamic plugin catalog
      description: Return hot-loaded third-party plugin manifests and validation errors.
      operationId: get_dynamic_plugins_api_registry_plugins_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Get Dynamic Plugins Api Registry Plugins Get
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/registry/capabilities:
    get:
      tags:
      - Registry
      - Registry
      summary: Get generated capability manifest
      description: Return the generated capability manifest for built-in and dynamic
        plugins.
      operationId: get_capabilities_api_registry_capabilities_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Get Capabilities Api Registry Capabilities Get
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/webhooks/test:
    post:
      tags:
      - Webhooks
      - Webhooks
      summary: Test Webhook
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
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Test Webhook Api Webhooks Test Post
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      security:
      - APIKeyHeader: []
  /api/webhooks/test-slack:
    post:
      tags:
      - Webhooks
      - Webhooks
      summary: Test Slack
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
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Test Slack Api Webhooks Test Slack Post
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      security:
      - APIKeyHeader: []
  /api/imports/semgrep:
    post:
      tags:
      - Imports
      - Imports
      summary: Import Semgrep JSON for a target
      operationId: import_semgrep_api_imports_semgrep_post
      security:
      - APIKeyHeader: []
      parameters:
      - name: target_name
        in: query
        required: true
        schema:
          type: string
          description: Target name for the imported results
          title: Target Name
        description: Target name for the imported results
      - name: run
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          description: Optional run name (will be created if omitted)
          title: Run
        description: Optional run name (will be created if omitted)
      - name: overwrite
        in: query
        required: false
        schema:
          type: boolean
          description: Overwrite existing semgrep.json if present
          default: false
          title: Overwrite
        description: Overwrite existing semgrep.json if present
      requestBody:
        content:
          multipart/form-data:
            schema:
              $ref: '#/components/schemas/Body_import_semgrep_api_imports_semgrep_post'
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties:
                  type: string
                title: Response Import Semgrep Api Imports Semgrep Post
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
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/gap-analysis:
    get:
      tags:
      - Gap Analysis
      - Gap Analysis
      summary: Get detection gap analysis
      description: Analyze coverage gaps across vulnerability categories using real
        telemetry.
      operationId: get_gap_analysis_api_gap_analysis_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: target
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DetectionGapResponse'
        '401':
          content:
            application/json:
              schema:
                title: Response 401 Get Gap Analysis Api Gap Analysis Get
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/gap-analysis/refresh:
    post:
      tags:
      - Gap Analysis
      - Gap Analysis
      summary: Trigger fresh gap analysis
      description: Trigger a fresh analysis of findings vs coverage registry.
      operationId: refresh_gap_analysis_api_gap_analysis_refresh_post
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties:
                  type: string
                type: object
                title: Response Refresh Gap Analysis Api Gap Analysis Refresh Post
      security:
      - APIKeyHeader: []
  /api/csrf-token:
    get:
      tags:
      - Security
      - Security
      summary: Retrieve the current active CSRF token for the session
      description: Exposes the session's active CSRF token securely to verified SPA
        clients.
      operationId: get_csrf_token_api_csrf_token_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties:
                  type: string
                type: object
                title: Response Get Csrf Token Api Csrf Token Get
  /api/auth/token:
    post:
      tags:
      - Security
      - Security
      summary: Exchange an API key for a short-lived dashboard token
      operationId: create_dashboard_token_api_auth_token_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TokenRequest'
        required: true
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TokenResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '422':
          description: Unprocessable Content
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
  /api/security/rate-limit-status:
    get:
      tags:
      - Security
      - Security
      summary: Get current rate limiting telemetry
      operationId: rate_limit_status_api_security_rate_limit_status_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RateLimitStatusResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
  /api/security/events:
    get:
      tags:
      - Security
      - Security
      summary: List recent security events
      operationId: list_security_events_api_security_events_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 500
          minimum: 1
          default: 100
          title: Limit
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/SecurityEventResponse'
                title: Response List Security Events Api Security Events Get
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/security/api-keys:
    get:
      tags:
      - Security
      - Security
      summary: List API keys
      operationId: list_api_keys_api_security_api_keys_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                items:
                  $ref: '#/components/schemas/APIKeyResponse'
                type: array
                title: Response List Api Keys Api Security Api Keys Get
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
      security:
      - APIKeyHeader: []
    post:
      tags:
      - Security
      - Security
      summary: Generate an API key
      operationId: generate_api_key_api_security_api_keys_post
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/APIKeyCreateRequest'
        required: true
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/APIKeyCreateResponse'
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
      security:
      - APIKeyHeader: []
  /api/security/api-keys/{key_id}:
    delete:
      tags:
      - Security
      - Security
      summary: Revoke an API key
      operationId: revoke_api_key_api_security_api_keys__key_id__delete
      security:
      - APIKeyHeader: []
      parameters:
      - name: key_id
        in: path
        required: true
        schema:
          type: string
          title: Key Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties:
                  anyOf:
                  - type: boolean
                  - type: string
                title: Response Revoke Api Key Api Security Api Keys  Key Id  Delete
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
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/security/csp-reports:
    get:
      tags:
      - Security
      - Security
      summary: List CSP violation reports
      operationId: list_csp_reports_api_security_csp_reports_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 200
          minimum: 1
          default: 50
          title: Limit
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/CSPReportResponse'
                title: Response List Csp Reports Api Security Csp Reports Get
        '401':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
          description: Unauthorized
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/csp-report:
    post:
      tags:
      - Security
      - Security
      summary: Accept a CSP violation report
      operationId: csp_report_api_csp_report_post
      responses:
        '204':
          description: Successful Response
  /api/tracing/config:
    get:
      tags:
      - Tracing
      - Tracing
      summary: Tracing Config
      description: Return OTLP exporter configuration and reachability.
      operationId: tracing_config_api_tracing_config_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Tracing Config Api Tracing Config Get
  /api/traces:
    get:
      tags:
      - Tracing
      - Tracing
      summary: List Traces
      description: List recent traces from the local SQLite span store.
      operationId: list_traces_api_traces_get
      parameters:
      - name: service_name
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Service Name
      - name: start_ms
        in: query
        required: false
        schema:
          anyOf:
          - type: integer
          - type: 'null'
          title: Start Ms
      - name: end_ms
        in: query
        required: false
        schema:
          anyOf:
          - type: integer
          - type: 'null'
          title: End Ms
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 500
          minimum: 1
          default: 100
          title: Limit
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response List Traces Api Traces Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/traces/{trace_id}:
    get:
      tags:
      - Tracing
      - Tracing
      summary: Get Trace
      description: Return all spans for a trace in waterfall order.
      operationId: get_trace_api_traces__trace_id__get
      parameters:
      - name: trace_id
        in: path
        required: true
        schema:
          type: string
          title: Trace Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Trace Api Traces  Trace Id  Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/triage/runs/{run_id}/findings/{finding_id}:
    get:
      tags:
      - Triage Collaboration
      - Triage Collaboration
      summary: Get Finding Triage State
      operationId: get_finding_triage_state_api_triage_runs__run_id__findings__finding_id__get
      security:
      - APIKeyHeader: []
      parameters:
      - name: run_id
        in: path
        required: true
        schema:
          type: string
          title: Run Id
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Finding Triage State Api Triage Runs  Run Id  Findings  Finding
                  Id  Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/triage/runs/{run_id}/audit:
    get:
      tags:
      - Triage Collaboration
      - Triage Collaboration
      summary: Get Triage Audit
      operationId: get_triage_audit_api_triage_runs__run_id__audit_get
      security:
      - APIKeyHeader: []
      parameters:
      - name: run_id
        in: path
        required: true
        schema:
          type: string
          title: Run Id
      - name: finding_id
        in: query
        required: false
        schema:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Id
      - name: limit
        in: query
        required: false
        schema:
          type: integer
          maximum: 1000
          minimum: 1
          default: 200
          title: Limit
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Get Triage Audit Api Triage Runs  Run Id  Audit Get
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/triage/audit/verify:
    get:
      tags:
      - Triage Collaboration
      - Triage Collaboration
      summary: Verify Triage Audit
      operationId: verify_triage_audit_api_triage_audit_verify_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Verify Triage Audit Api Triage Audit Verify Get
      security:
      - APIKeyHeader: []
  /api/triage/runs/{run_id}/findings/{finding_id}/actions:
    post:
      tags:
      - Triage Collaboration
      - Triage Collaboration
      summary: Record Triage Action
      operationId: record_triage_action_api_triage_runs__run_id__findings__finding_id__actions_post
      security:
      - APIKeyHeader: []
      parameters:
      - name: run_id
        in: path
        required: true
        schema:
          type: string
          title: Run Id
      - name: finding_id
        in: path
        required: true
        schema:
          type: string
          title: Finding Id
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: true
              title: Payload
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
                title: Response Record Triage Action Api Triage Runs  Run Id  Findings  Finding
                  Id  Actions Post
        '422':
          description: Validation Error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HTTPValidationError'
  /api/evasion/metrics:
    get:
      tags:
      - Evasion Telemetry
      - Evasion Telemetry
      summary: Get WAF evasion effectiveness metrics
      description: 'Returns aggregated and per-target/per-session WAF evasion benchmarks.

        Calculates evasion success rates per target/session.'
      operationId: get_evasion_metrics_api_evasion_metrics_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Get Evasion Metrics Api Evasion Metrics Get
      security:
      - APIKeyHeader: []
  /api/evasion/reset:
    post:
      tags:
      - Evasion Telemetry
      - Evasion Telemetry
      summary: Reset Chameleon Evasion Telemetry metrics
      description: Resets the WAF evasion metrics repository.
      operationId: reset_evasion_metrics_api_evasion_reset_post
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Reset Evasion Metrics Api Evasion Reset Post
      security:
      - APIKeyHeader: []
  /api/version:
    get:
      tags:
      - System
      summary: Get Version
      description: Return build and runtime version metadata.
      operationId: get_version_api_version_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                additionalProperties: true
                type: object
                title: Response Get Version Api Version Get
  /api/dashboard:
    get:
      tags:
      - Analytics
      summary: Get Dashboard Stats
      description: Compute and return global pipeline health and risk metrics.
      operationId: get_dashboard_stats_api_dashboard_get
      responses:
        '200':
          description: Successful Response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DashboardStatsResponse'
components:
  schemas:
    APIKeyCreateRequest:
      properties:
        role:
          type: string
          pattern: ^(read_only|worker|admin)$
          title: Role
      additionalProperties: false
      type: object
      required:
      - role
      title: APIKeyCreateRequest
      description: Request body for generating an API key.
    APIKeyCreateResponse:
      properties:
        id:
          type: string
          title: Id
        masked_key:
          type: string
          title: Masked Key
        role:
          type: string
          title: Role
        created_at:
          type: string
          title: Created At
        last_used_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Used At
        revoked_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Revoked At
        active:
          type: boolean
          title: Active
          default: true
        api_key:
          type: string
          title: Api Key
      type: object
      required:
      - id
      - masked_key
      - role
      - created_at
      - api_key
      title: APIKeyCreateResponse
      description: Generated API key response. The raw key is returned once.
    APIKeyResponse:
      properties:
        id:
          type: string
          title: Id
        masked_key:
          type: string
          title: Masked Key
        role:
          type: string
          title: Role
        created_at:
          type: string
          title: Created At
        last_used_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Used At
        revoked_at:
          anyOf:
          - type: string
          - type: 'null'
          title: Revoked At
        active:
          type: boolean
          title: Active
          default: true
      type: object
      required:
      - id
      - masked_key
      - role
      - created_at
      title: APIKeyResponse
      description: Masked API key inventory item.
    ApiDefaults:
      properties:
        default_mode:
          type: string
          title: Default Mode
        form_defaults:
          additionalProperties:
            type: string
          type: object
          title: Form Defaults
      type: object
      required:
      - default_mode
      - form_defaults
      title: ApiDefaults
    AttackChainSchema:
      properties:
        id:
          type: string
          title: Id
        steps:
          items:
            $ref: '#/components/schemas/AttackStepSchema'
          type: array
          title: Steps
        confidence:
          type: number
          title: Confidence
        description:
          type: string
          title: Description
      type: object
      required:
      - id
      - steps
      - confidence
      - description
      title: AttackChainSchema
      description: Complete lateral movement path.
    AttackStepSchema:
      properties:
        asset_id:
          type: string
          title: Asset Id
        finding_id:
          type: string
          title: Finding Id
        severity:
          type: string
          title: Severity
      type: object
      required:
      - asset_id
      - finding_id
      - severity
      title: AttackStepSchema
      description: Single hop in a multi-stage attack chain.
    Body_import_semgrep_api_imports_semgrep_post:
      properties:
        file:
          anyOf:
          - type: string
            contentMediaType: application/octet-stream
          - type: 'null'
          title: File
          description: Semgrep JSON file (multipart/form-data)
      type: object
      title: Body_import_semgrep_api_imports_semgrep_post
    CSPReportResponse:
      properties:
        id:
          type: integer
          title: Id
        timestamp:
          type: string
          title: Timestamp
        client_ip:
          anyOf:
          - type: string
          - type: 'null'
          title: Client Ip
        user_agent:
          type: string
          title: User Agent
          default: ''
        report:
          additionalProperties: true
          type: object
          title: Report
      type: object
      required:
      - id
      - timestamp
      title: CSPReportResponse
      description: Persisted CSP report.
    CacheCleanupResponse:
      properties:
        cleaned:
          type: integer
          title: Cleaned
        duration_seconds:
          type: number
          title: Duration Seconds
      type: object
      required:
      - cleaned
      - duration_seconds
      title: CacheCleanupResponse
      description: Cache cleanup response.
    CacheKeyDeleteRequest:
      properties:
        pattern:
          type: string
          maxLength: 512
          minLength: 1
          title: Pattern
      additionalProperties: false
      type: object
      required:
      - pattern
      title: CacheKeyDeleteRequest
      description: Request body for deleting Redis keys by pattern.
    CacheKeyDeleteResponse:
      properties:
        pattern:
          type: string
          title: Pattern
        matched:
          type: integer
          title: Matched
          default: 0
        deleted:
          type: integer
          title: Deleted
          default: 0
        connected:
          type: boolean
          title: Connected
          default: false
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
      type: object
      required:
      - pattern
      title: CacheKeyDeleteResponse
      description: Redis key deletion response.
    CacheKeyInfo:
      properties:
        key:
          type: string
          title: Key
        ttl:
          anyOf:
          - type: integer
          - type: 'null'
          title: Ttl
        size:
          anyOf:
          - type: integer
          - type: 'null'
          title: Size
        type:
          anyOf:
          - type: string
          - type: 'null'
          title: Type
      type: object
      required:
      - key
      title: CacheKeyInfo
      description: Redis key metadata for key explorer views.
    CacheKeysResponse:
      properties:
        pattern:
          type: string
          title: Pattern
        limit:
          type: integer
          title: Limit
        count:
          type: integer
          title: Count
          default: 0
        truncated:
          type: boolean
          title: Truncated
          default: false
        connected:
          type: boolean
          title: Connected
          default: false
        keys:
          items:
            $ref: '#/components/schemas/CacheKeyInfo'
          type: array
          title: Keys
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
      type: object
      required:
      - pattern
      - limit
      title: CacheKeysResponse
      description: Redis key listing response.
    CacheNamespaceResponse:
      properties:
        cleared:
          type: integer
          title: Cleared
          default: 0
        namespace:
          type: string
          title: Namespace
          default: ''
      type: object
      title: CacheNamespaceResponse
      description: Cache namespace invalidation response.
    CachePerformanceHistoryResponse:
      properties:
        points:
          items:
            $ref: '#/components/schemas/CachePerformancePoint'
          type: array
          title: Points
      type: object
      title: CachePerformanceHistoryResponse
      description: Rolling one-hour cache performance history.
    CachePerformancePoint:
      properties:
        timestamp:
          type: string
          title: Timestamp
        epoch:
          type: number
          title: Epoch
        hit_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Hit Rate
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
      type: object
      required:
      - timestamp
      - epoch
      title: CachePerformancePoint
      description: Single sampled cache performance point.
    CacheStatsResponse:
      properties:
        total_entries:
          type: integer
          title: Total Entries
        active_entries:
          type: integer
          title: Active Entries
        expired_entries:
          type: integer
          title: Expired Entries
        total_size_bytes:
          type: integer
          title: Total Size Bytes
        namespaces:
          additionalProperties:
            type: integer
          type: object
          title: Namespaces
        metrics:
          additionalProperties: true
          type: object
          title: Metrics
        backend_type:
          type: string
          title: Backend Type
          default: ''
        l1_entries:
          type: integer
          title: L1 Entries
          default: 0
        l2_entries:
          type: integer
          title: L2 Entries
          default: 0
        l3_entries:
          type: integer
          title: L3 Entries
          default: 0
      type: object
      required:
      - total_entries
      - active_entries
      - expired_entries
      - total_size_bytes
      title: CacheStatsResponse
      description: Cache statistics response.
    CacheStatusResponse:
      properties:
        redis:
          $ref: '#/components/schemas/RedisCacheOverview'
        sqlite:
          $ref: '#/components/schemas/SQLiteCacheOverview'
      type: object
      required:
      - redis
      - sqlite
      title: CacheStatusResponse
      description: Combined cache introspection response.
    DashboardStatsResponse:
      properties:
        active_jobs:
          type: integer
          title: Active Jobs
        completed_jobs:
          type: integer
          title: Completed Jobs
        failed_jobs:
          type: integer
          title: Failed Jobs
        completed_targets:
          type: integer
          title: Completed Targets
        total_findings:
          type: integer
          title: Total Findings
        total_targets:
          type: integer
          title: Total Targets
        avg_progress:
          type: integer
          title: Avg Progress
        stage_counts:
          additionalProperties:
            type: integer
          type: object
          title: Stage Counts
        severity_counts:
          additionalProperties:
            type: integer
          type: object
          title: Severity Counts
        pipeline_health_score:
          type: integer
          title: Pipeline Health Score
        pipeline_health_label:
          type: string
          title: Pipeline Health Label
        trend_data:
          items:
            type: integer
          type: array
          title: Trend Data
        findings_summary:
          additionalProperties: true
          type: object
          title: Findings Summary
        mesh_health:
          additionalProperties: true
          type: object
          title: Mesh Health
      type: object
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
      description: Dashboard statistics response.
    DeduplicationStats:
      properties:
        removed:
          type: integer
          title: Removed
          default: 0
        remaining:
          type: integer
          title: Remaining
          default: 0
      type: object
      title: DeduplicationStats
      description: Duplicate removal statistics.
    DetectionGapResponse:
      properties:
        target:
          anyOf:
          - type: string
          - type: 'null'
          title: Target
        results:
          items:
            $ref: '#/components/schemas/GapAnalysisEntry'
          type: array
          title: Results
        overall_coverage:
          type: integer
          title: Overall Coverage
          default: 0
        total_modules:
          type: integer
          title: Total Modules
          default: 0
        modules_with_gaps:
          type: integer
          title: Modules With Gaps
          default: 0
      type: object
      title: DetectionGapResponse
      description: Detection gap response.
    DropOffStats:
      properties:
        input:
          type: integer
          title: Input
          default: 0
        kept:
          type: integer
          title: Kept
          default: 0
        dropped:
          type: integer
          title: Dropped
          default: 0
      type: object
      title: DropOffStats
      description: Drop-off tracking stats between stages.
    ErrorResponse:
      properties:
        error:
          type: string
          title: Error
        detail:
          anyOf:
          - type: string
          - type: 'null'
          title: Detail
        code:
          anyOf:
          - type: string
          - type: 'null'
          title: Code
      type: object
      required:
      - error
      title: ErrorResponse
      description: Standard error response.
    FeedbackEventEntry:
      properties:
        event_id:
          type: string
          title: Event Id
        run_id:
          type: string
          title: Run Id
        timestamp:
          type: string
          title: Timestamp
        target_host:
          type: string
          title: Target Host
        target_endpoint:
          type: string
          title: Target Endpoint
        finding_category:
          type: string
          title: Finding Category
        finding_severity:
          anyOf:
          - type: string
          - type: 'null'
          title: Finding Severity
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
        plugin_name:
          anyOf:
          - type: string
          - type: 'null'
          title: Plugin Name
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
        was_validated:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Was Validated
        was_false_positive:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Was False Positive
        validation_method:
          anyOf:
          - type: string
          - type: 'null'
          title: Validation Method
        response_delta_score:
          anyOf:
          - type: number
          - type: 'null'
          title: Response Delta Score
        endpoint_type:
          anyOf:
          - type: string
          - type: 'null'
          title: Endpoint Type
        tech_stack:
          anyOf:
          - type: string
          - type: 'null'
          title: Tech Stack
        scan_mode:
          anyOf:
          - type: string
          - type: 'null'
          title: Scan Mode
        feedback_weight:
          anyOf:
          - type: number
          - type: 'null'
          title: Feedback Weight
      type: object
      required:
      - event_id
      - run_id
      - timestamp
      - target_host
      - target_endpoint
      - finding_category
      title: FeedbackEventEntry
      description: FastAPI response schema for feedback events.
    FindingsSummaryResponse:
      properties:
        total_findings:
          type: integer
          title: Total Findings
        severity_totals:
          additionalProperties:
            type: integer
          type: object
          title: Severity Totals
        by_severity:
          additionalProperties:
            type: integer
          type: object
          title: By Severity
        by_module:
          additionalProperties:
            type: integer
          type: object
          title: By Module
        findings:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Findings
        targets:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Targets
        targets_with_findings:
          type: integer
          title: Targets With Findings
          default: 0
        total_targets:
          type: integer
          title: Total Targets
          default: 0
      type: object
      required:
      - total_findings
      title: FindingsSummaryResponse
      description: Findings summary response.
    FpPatternEntry:
      properties:
        pattern_id:
          type: string
          title: Pattern Id
        category:
          type: string
          title: Category
        status_code_pattern:
          anyOf:
          - type: string
          - type: 'null'
          title: Status Code Pattern
        body_pattern:
          anyOf:
          - type: string
          - type: 'null'
          title: Body Pattern
        header_pattern:
          anyOf:
          - type: string
          - type: 'null'
          title: Header Pattern
        response_similarity:
          anyOf:
          - type: number
          - type: 'null'
          title: Response Similarity
        first_seen:
          type: string
          title: First Seen
        last_seen:
          type: string
          title: Last Seen
        occurrence_count:
          anyOf:
          - type: integer
          - type: 'null'
          title: Occurrence Count
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
        fp_probability:
          anyOf:
          - type: number
          - type: 'null'
          title: Fp Probability
        confidence:
          anyOf:
          - type: number
          - type: 'null'
          title: Confidence
        is_active:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Is Active
        suppression_action:
          anyOf:
          - type: string
          - type: 'null'
          title: Suppression Action
        created_at:
          type: string
          title: Created At
        updated_at:
          type: string
          title: Updated At
      type: object
      required:
      - pattern_id
      - category
      - first_seen
      - last_seen
      - created_at
      - updated_at
      title: FpPatternEntry
      description: Learned false positive pattern entry.
    GapAnalysisEntry:
      properties:
        module:
          type: string
          title: Module
        category:
          type: string
          title: Category
        total_checks:
          type: integer
          title: Total Checks
        covered_checks:
          type: integer
          title: Covered Checks
        missing_checks:
          type: integer
          title: Missing Checks
        coverage_percent:
          type: integer
          title: Coverage Percent
        status:
          type: string
          title: Status
        missing_check_details:
          items:
            type: string
          type: array
          title: Missing Check Details
      type: object
      required:
      - module
      - category
      - total_checks
      - covered_checks
      - missing_checks
      - coverage_percent
      - status
      title: GapAnalysisEntry
      description: Entry for detection gap analysis.
    HTTPValidationError:
      properties:
        detail:
          items:
            $ref: '#/components/schemas/ValidationError'
          type: array
          title: Detail
      type: object
      title: HTTPValidationError
    HealthResponse:
      properties:
        status:
          type: string
          title: Status
        timestamp:
          type: string
          title: Timestamp
        version:
          type: string
          title: Version
          default: 2.0.0
        uptime_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Uptime Seconds
        dependencies:
          additionalProperties: true
          type: object
          title: Dependencies
        mesh:
          items:
            $ref: '#/components/schemas/MeshNodeSchema'
          type: array
          title: Mesh
      type: object
      required:
      - status
      - timestamp
      title: HealthResponse
      description: Health check response.
    HistoricalScoreResponse:
      properties:
        target:
          type: string
          title: Target
        endpoints:
          additionalProperties:
            additionalProperties: true
            type: object
          type: object
          title: Endpoints
        runs_analyzed:
          type: integer
          title: Runs Analyzed
          default: 0
      type: object
      required:
      - target
      title: HistoricalScoreResponse
      description: Historical scores response.
    JobCreateRequest:
      properties:
        base_url:
          type: string
          minLength: 1
          title: Base Url
          description: Target base URL
        target_name:
          type: string
          title: Target Name
          description: Target name for output directory
          default: ''
        scope_text:
          type: string
          title: Scope Text
          description: Additional scope entries
          default: ''
        mode:
          type: string
          title: Mode
          description: Pipeline mode
          default: idor
        modules:
          anyOf:
          - items:
              type: string
            type: array
          - type: 'null'
          title: Modules
          description: Selected module names
        runtime_overrides:
          additionalProperties:
            type: string
          type: object
          title: Runtime Overrides
        execution_options:
          additionalProperties:
            type: boolean
          type: object
          title: Execution Options
      additionalProperties: false
      type: object
      required:
      - base_url
      title: JobCreateRequest
      description: Request body for starting a new scan job.
    JobListResponse:
      properties:
        jobs:
          items:
            $ref: '#/components/schemas/JobResponse'
          type: array
          title: Jobs
        total:
          type: integer
          title: Total
          default: 0
      type: object
      required:
      - jobs
      title: JobListResponse
      description: List of jobs response.
    JobLogsResponse:
      properties:
        job_id:
          type: string
          title: Job Id
        logs:
          items:
            type: string
          type: array
          title: Logs
        total_logs:
          type: integer
          title: Total Logs
          default: 0
        status:
          anyOf:
          - type: string
          - type: 'null'
          title: Status
      type: object
      required:
      - job_id
      - logs
      title: JobLogsResponse
      description: Job logs response.
    JobResponse:
      properties:
        id:
          type: string
          title: Id
        base_url:
          type: string
          title: Base Url
        hostname:
          type: string
          title: Hostname
        scope_entries:
          items:
            type: string
          type: array
          title: Scope Entries
        enabled_modules:
          items:
            type: string
          type: array
          title: Enabled Modules
        mode:
          type: string
          title: Mode
        target_name:
          type: string
          title: Target Name
        status:
          type: string
          title: Status
        stage:
          type: string
          title: Stage
        stage_label:
          type: string
          title: Stage Label
        status_message:
          type: string
          title: Status Message
        failed_stage:
          type: string
          title: Failed Stage
          default: ''
        failure_reason_code:
          type: string
          title: Failure Reason Code
          default: ''
        failure_step:
          type: string
          title: Failure Step
          default: ''
        failure_reason:
          type: string
          title: Failure Reason
          default: ''
        progress_percent:
          type: integer
          title: Progress Percent
        started_at:
          type: string
          title: Started At
        started_at_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Started At Label
        updated_at_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Updated At Label
        finished_at_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Finished At Label
        returncode:
          anyOf:
          - type: integer
          - type: 'null'
          title: Returncode
        error:
          type: string
          title: Error
          default: ''
        warnings:
          items:
            type: string
          type: array
          title: Warnings
        execution_options:
          additionalProperties:
            type: boolean
          type: object
          title: Execution Options
        can_stop:
          type: boolean
          title: Can Stop
        latest_logs:
          items:
            type: string
          type: array
          title: Latest Logs
        config_href:
          type: string
          title: Config Href
        scope_href:
          type: string
          title: Scope Href
        stdout_href:
          type: string
          title: Stdout Href
        stderr_href:
          type: string
          title: Stderr Href
        target_href:
          type: string
          title: Target Href
        elapsed_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Elapsed Seconds
        elapsed_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Elapsed Label
        eta_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Eta Label
        has_eta:
          type: boolean
          title: Has Eta
          default: false
        last_update_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Update Label
        stalled:
          type: boolean
          title: Stalled
          default: false
        stage_progress_label:
          anyOf:
          - type: string
          - type: 'null'
          title: Stage Progress Label
        stage_progress:
          items:
            $ref: '#/components/schemas/StageProgressEntry'
          type: array
          title: Stage Progress
        progress_telemetry:
          $ref: '#/components/schemas/ProgressTelemetry'
        telemetry_events:
          items:
            $ref: '#/components/schemas/PipelineTelemetryEvent'
          type: array
          title: Telemetry Events
        concurrent_stage_count:
          type: integer
          title: Concurrent Stage Count
          default: 0
      type: object
      required:
      - id
      - base_url
      - hostname
      - scope_entries
      - enabled_modules
      - mode
      - target_name
      - status
      - stage
      - stage_label
      - status_message
      - progress_percent
      - started_at
      - warnings
      - execution_options
      - can_stop
      - latest_logs
      - config_href
      - scope_href
      - stdout_href
      - stderr_href
      - target_href
      title: JobResponse
      description: Single job response.
    MeshNodeSchema:
      properties:
        id:
          type: string
          title: Id
        host:
          type: string
          title: Host
        port:
          type: integer
          title: Port
        status:
          type: string
          title: Status
        cpu_usage:
          type: number
          title: Cpu Usage
        ram_available_mb:
          type: number
          title: Ram Available Mb
        active_jobs:
          type: integer
          title: Active Jobs
        last_seen:
          type: number
          title: Last Seen
      type: object
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
      description: Schema for distributed mesh node telemetry.
    NoteCreateRequest:
      properties:
        finding_id:
          type: string
          minLength: 1
          title: Finding Id
        note:
          type: string
          maxLength: 10000
          minLength: 1
          title: Note
        tags:
          items:
            type: string
          type: array
          title: Tags
        author:
          type: string
          title: Author
          default: ''
        graph_node_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Node Id
        graph_edge_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Edge Id
        exchange_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Exchange Id
      additionalProperties: false
      type: object
      required:
      - finding_id
      - note
      title: NoteCreateRequest
      description: Request body for creating a note.
    NoteDeleteResponse:
      properties:
        deleted:
          type: boolean
          title: Deleted
          default: false
        note_id:
          type: string
          title: Note Id
          default: ''
      type: object
      title: NoteDeleteResponse
      description: Note deletion response.
    NoteListResponse:
      properties:
        notes:
          items:
            $ref: '#/components/schemas/NoteResponse'
          type: array
          title: Notes
        target:
          type: string
          title: Target
          default: ''
        count:
          type: integer
          title: Count
          default: 0
      type: object
      required:
      - notes
      title: NoteListResponse
      description: List of notes response.
    NoteResponse:
      properties:
        note_id:
          type: string
          title: Note Id
        finding_id:
          type: string
          title: Finding Id
        note:
          type: string
          title: Note
        tags:
          items:
            type: string
          type: array
          title: Tags
        author:
          type: string
          title: Author
        created_at:
          type: string
          title: Created At
        updated_at:
          type: string
          title: Updated At
        graph_node_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Node Id
        graph_edge_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Edge Id
        exchange_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Exchange Id
      type: object
      required:
      - note_id
      - finding_id
      - note
      - tags
      - author
      - created_at
      - updated_at
      title: NoteResponse
      description: Single note response.
    NoteUpdateRequest:
      properties:
        finding_id:
          type: string
          minLength: 1
          title: Finding Id
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
        graph_node_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Node Id
        graph_edge_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Graph Edge Id
        exchange_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Exchange Id
      additionalProperties: false
      type: object
      required:
      - finding_id
      title: NoteUpdateRequest
      description: Request body for updating a note.
    PipelineTelemetryEvent:
      properties:
        event_id:
          type: string
          title: Event Id
        schema_version:
          type: string
          title: Schema Version
          default: telemetry.v2
        event_type:
          type: string
          title: Event Type
        timestamp:
          type: string
          title: Timestamp
        epoch:
          type: number
          title: Epoch
        stage:
          type: string
          title: Stage
        status:
          type: string
          title: Status
        message:
          type: string
          title: Message
          default: ''
        source:
          type: string
          title: Source
          default: ''
        trace_id:
          type: string
          title: Trace Id
          default: ''
        parent_id:
          type: string
          title: Parent Id
          default: ''
        check_id:
          type: string
          title: Check Id
          default: ''
        artifact_type:
          type: string
          title: Artifact Type
          default: ''
        artifact_id:
          type: string
          title: Artifact Id
          default: ''
        finding_id:
          type: string
          title: Finding Id
          default: ''
        severity:
          type: string
          title: Severity
          default: ''
        target:
          type: string
          title: Target
          default: ''
        run_id:
          type: string
          title: Run Id
          default: ''
        sequence:
          type: integer
          title: Sequence
          default: 0
        metrics:
          additionalProperties: true
          type: object
          title: Metrics
        payload:
          additionalProperties: true
          type: object
          title: Payload
      type: object
      required:
      - event_id
      - event_type
      - timestamp
      - epoch
      - stage
      - status
      title: PipelineTelemetryEvent
      description: Replayable structured event emitted by the pipeline.
    ProgressTelemetry:
      properties:
        active_task_count:
          type: integer
          title: Active Task Count
          default: 0
        requests_per_second:
          anyOf:
          - type: number
          - type: 'null'
          title: Requests Per Second
        throughput_per_second:
          anyOf:
          - type: number
          - type: 'null'
          title: Throughput Per Second
        eta_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Eta Seconds
        high_value_target_count:
          type: integer
          title: High Value Target Count
          default: 0
        vulnerability_likelihood_score:
          anyOf:
          - type: number
          - type: 'null'
          title: Vulnerability Likelihood Score
        signal_noise_ratio:
          anyOf:
          - type: number
          - type: 'null'
          title: Signal Noise Ratio
        confidence_score:
          anyOf:
          - type: number
          - type: 'null'
          title: Confidence Score
        drop_off:
          anyOf:
          - $ref: '#/components/schemas/DropOffStats'
          - type: 'null'
        deduplication:
          anyOf:
          - $ref: '#/components/schemas/DeduplicationStats'
          - type: 'null'
        targets:
          $ref: '#/components/schemas/TargetProgressStats'
        retry_count:
          type: integer
          title: Retry Count
          default: 0
        failure_count:
          type: integer
          title: Failure Count
          default: 0
        stage_transitions:
          items:
            $ref: '#/components/schemas/StageTransitionEntry'
          type: array
          title: Stage Transitions
        event_triggers:
          items:
            type: string
          type: array
          title: Event Triggers
        skipped_stages:
          items:
            $ref: '#/components/schemas/SkippedStageEntry'
          type: array
          title: Skipped Stages
        top_active_targets:
          items:
            type: string
          type: array
          title: Top Active Targets
        bottleneck_stage:
          type: string
          title: Bottleneck Stage
          default: ''
        bottleneck_seconds:
          anyOf:
          - type: number
          - type: 'null'
          title: Bottleneck Seconds
        next_best_action:
          type: string
          title: Next Best Action
          default: ''
        learning_feedback:
          anyOf:
          - additionalProperties: true
            type: object
          - type: string
          - type: 'null'
          title: Learning Feedback
        event_counts:
          additionalProperties:
            type: integer
          type: object
          title: Event Counts
        artifact_counts:
          additionalProperties:
            type: integer
          type: object
          title: Artifact Counts
        last_update_epoch:
          anyOf:
          - type: number
          - type: 'null'
          title: Last Update Epoch
      type: object
      title: ProgressTelemetry
      description: Rich progress telemetry surfaced to dashboard clients.
    RateLimitBucketResponse:
      properties:
        endpoint:
          type: string
          title: Endpoint
        requests_per_second:
          type: number
          title: Requests Per Second
        recent_count:
          type: integer
          title: Recent Count
        limit_per_second:
          anyOf:
          - type: integer
          - type: 'null'
          title: Limit Per Second
      type: object
      required:
      - endpoint
      - requests_per_second
      - recent_count
      title: RateLimitBucketResponse
      description: Current request-rate telemetry for an endpoint.
    RateLimitStatusResponse:
      properties:
        enabled:
          type: boolean
          title: Enabled
        buckets:
          items:
            $ref: '#/components/schemas/RateLimitBucketResponse'
          type: array
          title: Buckets
      type: object
      required:
      - enabled
      title: RateLimitStatusResponse
      description: Rate-limit telemetry response.
    ReadinessResponse:
      properties:
        ready:
          type: boolean
          title: Ready
        checks:
          additionalProperties:
            type: boolean
          type: object
          title: Checks
      type: object
      required:
      - ready
      title: ReadinessResponse
      description: Readiness check response.
    RedisCacheOverview:
      properties:
        connected:
          type: boolean
          title: Connected
          default: false
        keys_count:
          type: integer
          title: Keys Count
          default: 0
        used_memory_human:
          type: string
          title: Used Memory Human
          default: 0 B
        used_memory_bytes:
          type: integer
          title: Used Memory Bytes
          default: 0
        max_memory_bytes:
          anyOf:
          - type: integer
          - type: 'null'
          title: Max Memory Bytes
        hit_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Hit Rate
        miss_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Miss Rate
        connected_clients:
          type: integer
          title: Connected Clients
          default: 0
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
      type: object
      title: RedisCacheOverview
      description: Redis cache status and runtime counters.
    RegistryAnalysisOptions:
      properties:
        check_options:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Check Options
        control_groups:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Control Groups
        focus_presets:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Focus Presets
        dynamic_plugins:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Dynamic Plugins
        invalid_dynamic_plugins:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Invalid Dynamic Plugins
      type: object
      title: RegistryAnalysisOptions
      description: Analysis check options registry.
    RegistryModePresets:
      properties:
        presets:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Presets
        stage_labels:
          additionalProperties:
            type: string
          type: object
          title: Stage Labels
      type: object
      title: RegistryModePresets
      description: Mode presets registry.
    RegistryModuleOptions:
      properties:
        options:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Options
        groups:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Groups
      type: object
      title: RegistryModuleOptions
      description: Module options registry.
    RegistryResponse:
      properties:
        modules:
          $ref: '#/components/schemas/RegistryModuleOptions'
        analysis:
          $ref: '#/components/schemas/RegistryAnalysisOptions'
        modes:
          $ref: '#/components/schemas/RegistryModePresets'
        capabilities:
          additionalProperties: true
          type: object
          title: Capabilities
      type: object
      required:
      - modules
      - analysis
      - modes
      title: RegistryResponse
      description: Combined registry response.
    ReplayResponse:
      properties:
        replay_id:
          type: string
          title: Replay Id
        auth_mode:
          type: string
          title: Auth Mode
        applied_header_names:
          items:
            type: string
          type: array
          title: Applied Header Names
        requested_url:
          type: string
          title: Requested Url
        final_url:
          type: string
          title: Final Url
        redirect_chain:
          items:
            type: string
          type: array
          title: Redirect Chain
        status_code:
          anyOf:
          - type: integer
          - type: 'null'
          title: Status Code
        body_similarity:
          anyOf:
          - type: number
          - type: 'null'
          title: Body Similarity
        status_changed:
          anyOf:
          - type: boolean
          - type: 'null'
          title: Status Changed
        redirect_changed:
          anyOf:
          - type: boolean
          - type: 'null'
          title: Redirect Changed
        content_changed:
          anyOf:
          - type: boolean
          - type: 'null'
          title: Content Changed
      type: object
      required:
      - replay_id
      - auth_mode
      - applied_header_names
      - requested_url
      - final_url
      title: ReplayResponse
      description: Replay result response.
    RiskScoreResponse:
      properties:
        target:
          type: string
          title: Target
        aggregate_score:
          type: number
          title: Aggregate Score
        severity:
          type: string
          title: Severity
        total_findings:
          type: integer
          title: Total Findings
        severity_breakdown:
          additionalProperties:
            type: integer
          type: object
          title: Severity Breakdown
        timestamp:
          type: string
          title: Timestamp
          default: ''
      type: object
      required:
      - target
      - aggregate_score
      - severity
      - total_findings
      title: RiskScoreResponse
      description: Risk score response.
    SQLiteCacheOverview:
      properties:
        connected:
          type: boolean
          title: Connected
          default: false
        db_path:
          type: string
          title: Db Path
          default: ''
        file_size_mb:
          type: number
          title: File Size Mb
          default: 0.0
        query_count:
          type: integer
          title: Query Count
          default: 0
        entry_count:
          type: integer
          title: Entry Count
          default: 0
        cache_hit_ratio:
          anyOf:
          - type: number
          - type: 'null'
          title: Cache Hit Ratio
        error:
          anyOf:
          - type: string
          - type: 'null'
          title: Error
      type: object
      title: SQLiteCacheOverview
      description: SQLite cache file and query status.
    SecurityEventResponse:
      properties:
        id:
          type: integer
          title: Id
        timestamp:
          type: string
          title: Timestamp
        event_type:
          type: string
          title: Event Type
        status_code:
          anyOf:
          - type: integer
          - type: 'null'
          title: Status Code
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
        client_ip:
          anyOf:
          - type: string
          - type: 'null'
          title: Client Ip
        api_key_id:
          anyOf:
          - type: string
          - type: 'null'
          title: Api Key Id
        detail:
          type: string
          title: Detail
          default: ''
      type: object
      required:
      - id
      - timestamp
      - event_type
      title: SecurityEventResponse
      description: Security event log entry.
    SkippedStageEntry:
      properties:
        stage:
          type: string
          title: Stage
        reason:
          type: string
          title: Reason
          default: ''
      type: object
      required:
      - stage
      title: SkippedStageEntry
      description: Skipped stage reason entry.
    SlackTestRequest:
      properties:
        url:
          type: string
          title: Url
          description: The Slack Incoming Webhook URL
        channel:
          type: string
          title: Channel
          description: The Slack channel to post to
          default: '#security-alerts'
      type: object
      required:
      - url
      title: SlackTestRequest
    StageProgressEntry:
      properties:
        stage:
          type: string
          title: Stage
        stage_label:
          type: string
          title: Stage Label
        status:
          type: string
          title: Status
        processed:
          type: integer
          title: Processed
          default: 0
        total:
          anyOf:
          - type: integer
          - type: 'null'
          title: Total
        percent:
          type: integer
          title: Percent
          default: 0
        reason:
          type: string
          title: Reason
          default: ''
        error:
          type: string
          title: Error
          default: ''
        retry_count:
          type: integer
          title: Retry Count
          default: 0
        last_event:
          type: string
          title: Last Event
          default: ''
        started_at:
          anyOf:
          - type: number
          - type: 'null'
          title: Started At
        updated_at:
          anyOf:
          - type: number
          - type: 'null'
          title: Updated At
      type: object
      required:
      - stage
      - stage_label
      - status
      title: StageProgressEntry
      description: Per-stage progress status entry.
    StageTransitionEntry:
      properties:
        stage:
          type: string
          title: Stage
        status:
          type: string
          title: Status
        timestamp:
          type: number
          title: Timestamp
        message:
          type: string
          title: Message
          default: ''
      type: object
      required:
      - stage
      - status
      - timestamp
      title: StageTransitionEntry
      description: Stage transition audit trail entry.
    TargetComparisonDetail:
      properties:
        name:
          type: string
          title: Name
        risk_score:
          type: number
          title: Risk Score
          default: 0.0
        finding_count:
          type: integer
          title: Finding Count
          default: 0
        url_count:
          type: integer
          title: Url Count
          default: 0
        parameter_count:
          type: integer
          title: Parameter Count
          default: 0
        attack_chain_count:
          type: integer
          title: Attack Chain Count
          default: 0
        run_count:
          type: integer
          title: Run Count
          default: 0
        latest_run:
          type: string
          title: Latest Run
          default: ''
        severity_counts:
          additionalProperties:
            type: integer
          type: object
          title: Severity Counts
      type: object
      required:
      - name
      title: TargetComparisonDetail
      description: Comparative stats for a single target.
    TargetComparisonResponse:
      properties:
        target_a:
          $ref: '#/components/schemas/TargetComparisonDetail'
        target_b:
          $ref: '#/components/schemas/TargetComparisonDetail'
      type: object
      required:
      - target_a
      - target_b
      title: TargetComparisonResponse
      description: Comparison response between two targets.
    TargetFindingsResponse:
      properties:
        findings:
          items:
            additionalProperties: true
            type: object
          type: array
          title: Findings
        total:
          type: integer
          title: Total
          default: 0
        target:
          type: string
          title: Target
          default: ''
      type: object
      title: TargetFindingsResponse
      description: Findings for a specific target.
    TargetInfo:
      properties:
        name:
          type: string
          title: Name
        href:
          type: string
          title: Href
          default: ''
        latest_run:
          anyOf:
          - type: string
          - type: 'null'
          title: Latest Run
        latest_generated_at:
          type: string
          title: Latest Generated At
          default: ''
        latest_report_href:
          type: string
          title: Latest Report Href
          default: ''
        priority_url_count:
          type: integer
          title: Priority Url Count
          default: 0
        finding_count:
          type: integer
          title: Finding Count
          default: 0
        severity_counts:
          additionalProperties:
            type: integer
          type: object
          title: Severity Counts
        validated_leads:
          type: integer
          title: Validated Leads
          default: 0
        url_count:
          type: integer
          title: Url Count
          default: 0
        parameter_count:
          type: integer
          title: Parameter Count
          default: 0
        new_findings:
          type: integer
          title: New Findings
          default: 0
        attack_chain_count:
          type: integer
          title: Attack Chain Count
          default: 0
        max_attack_chain_confidence:
          type: number
          title: Max Attack Chain Confidence
          default: 0.0
        validation_plan_count:
          type: integer
          title: Validation Plan Count
          default: 0
        top_finding_title:
          type: string
          title: Top Finding Title
          default: ''
        top_finding_severity:
          type: string
          title: Top Finding Severity
          default: ''
        top_finding_url:
          type: string
          title: Top Finding Url
          default: ''
        run_count:
          type: integer
          title: Run Count
          default: 0
        last_scan:
          anyOf:
          - type: string
          - type: 'null'
          title: Last Scan
      type: object
      required:
      - name
      title: TargetInfo
      description: Target summary information.
    TargetListResponse:
      properties:
        targets:
          items:
            $ref: '#/components/schemas/TargetInfo'
          type: array
          title: Targets
        total:
          type: integer
          title: Total
          default: 0
      type: object
      required:
      - targets
      title: TargetListResponse
      description: List of targets response.
    TargetProgressStats:
      properties:
        queued:
          type: integer
          title: Queued
          default: 0
        scanning:
          type: integer
          title: Scanning
          default: 0
        done:
          type: integer
          title: Done
          default: 0
      type: object
      title: TargetProgressStats
      description: Per-target queue/scanning/done progress counters.
    TelemetryKpis:
      properties:
        detection_rate:
          type: number
          title: Detection Rate
          default: 0.0
        precision:
          type: number
          title: Precision
          default: 0.0
        recall:
          type: number
          title: Recall
          default: 0.0
        f1_score:
          type: number
          title: F1 Score
          default: 0.0
        fp_rate:
          type: number
          title: Fp Rate
          default: 0.0
        fn_rate:
          type: number
          title: Fn Rate
          default: 0.0
        learning_velocity_precision:
          type: number
          title: Learning Velocity Precision
          default: 0.0
        learning_velocity_recall:
          type: number
          title: Learning Velocity Recall
          default: 0.0
        threshold_convergence:
          type: boolean
          title: Threshold Convergence
          default: false
        fp_pattern_count:
          type: integer
          title: Fp Pattern Count
          default: 0
        active_suppression_rules:
          type: integer
          title: Active Suppression Rules
          default: 0
        findings_per_scan_hour:
          type: number
          title: Findings Per Scan Hour
          default: 0.0
        scan_duration_minutes:
          type: number
          title: Scan Duration Minutes
          default: 0.0
        urls_per_minute:
          type: number
          title: Urls Per Minute
          default: 0.0
        active_exploits_per_run:
          type: integer
          title: Active Exploits Per Run
          default: 0
        validation_success_rate:
          type: number
          title: Validation Success Rate
          default: 0.0
        endpoint_coverage:
          type: number
          title: Endpoint Coverage
          default: 0.0
        parameter_coverage:
          type: number
          title: Parameter Coverage
          default: 0.0
        category_coverage:
          type: number
          title: Category Coverage
          default: 0.0
        attack_chain_coverage:
          type: number
          title: Attack Chain Coverage
          default: 0.0
        validated_findings_ratio:
          type: number
          title: Validated Findings Ratio
          default: 0.0
        mean_time_to_detect_minutes:
          type: number
          title: Mean Time To Detect Minutes
          default: 0.0
        mean_time_to_validate_minutes:
          type: number
          title: Mean Time To Validate Minutes
          default: 0.0
        auto_validated_ratio:
          type: number
          title: Auto Validated Ratio
          default: 0.0
        pipeline_uptime:
          type: number
          title: Pipeline Uptime
          default: 1.0
        regression_count:
          type: integer
          title: Regression Count
          default: 0
        safety_violations:
          type: integer
          title: Safety Violations
          default: 0
      type: object
      title: TelemetryKpis
      description: FastAPI response schema for learning subsystem KPIs.
    ThresholdHistoryEntry:
      properties:
        history_id:
          type: string
          title: History Id
        run_id:
          type: string
          title: Run Id
        category:
          type: string
          title: Category
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
        high_threshold:
          anyOf:
          - type: number
          - type: 'null'
          title: High Threshold
        observed_fp_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Observed Fp Rate
        target_fp_rate:
          anyOf:
          - type: number
          - type: 'null'
          title: Target Fp Rate
        error:
          anyOf:
          - type: number
          - type: 'null'
          title: Error
        adjustment:
          anyOf:
          - type: number
          - type: 'null'
          title: Adjustment
        is_converged:
          anyOf:
          - type: boolean
          - type: integer
          - type: 'null'
          title: Is Converged
        recorded_at:
          type: string
          title: Recorded At
      type: object
      required:
      - history_id
      - run_id
      - category
      - recorded_at
      title: ThresholdHistoryEntry
      description: Threshold history entry.
    TimelineEntry:
      properties:
        timestamp:
          type: string
          title: Timestamp
        severity:
          type: string
          title: Severity
        url:
          type: string
          title: Url
        title:
          type: string
          title: Title
        module:
          type: string
          title: Module
          default: ''
      type: object
      required:
      - timestamp
      - severity
      - url
      - title
      title: TimelineEntry
      description: Single timeline entry.
    TimelineResponse:
      properties:
        target:
          type: string
          title: Target
          default: ''
        timeline:
          items:
            $ref: '#/components/schemas/TimelineEntry'
          type: array
          title: Timeline
        count:
          type: integer
          title: Count
          default: 0
      type: object
      required:
      - timeline
      title: TimelineResponse
      description: Timeline response.
    TokenRequest:
      properties:
        api_key:
          type: string
          minLength: 1
          title: Api Key
      additionalProperties: false
      type: object
      required:
      - api_key
      title: TokenRequest
      description: Request body for dashboard token exchange.
    TokenResponse:
      properties:
        access_token:
          type: string
          title: Access Token
        token_type:
          type: string
          title: Token Type
          default: bearer
        expires_in:
          type: integer
          title: Expires In
        role:
          type: string
          title: Role
      type: object
      required:
      - access_token
      - expires_in
      - role
      title: TokenResponse
      description: Short-lived dashboard token response.
    ValidationError:
      properties:
        loc:
          items:
            anyOf:
            - type: string
            - type: integer
          type: array
          title: Location
        msg:
          type: string
          title: Message
        type:
          type: string
          title: Error Type
        input:
          title: Input
        ctx:
          type: object
          title: Context
      type: object
      required:
      - loc
      - msg
      - type
      title: ValidationError
    WebhookTestRequest:
      properties:
        url:
          type: string
          title: Url
          description: The webhook URL to test
        secret:
          anyOf:
          - type: string
          - type: 'null'
          title: Secret
          description: Optional HMAC signing secret
      type: object
      required:
      - url
      title: WebhookTestRequest
  securitySchemes:
    APIKeyHeader:
      type: apiKey
      in: header
      name: X-API-Key
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
