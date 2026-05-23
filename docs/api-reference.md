# API Reference (Machine-Readable)

This document provides the OpenAPI 3.1.0 specification for the Cyber Security Test Pipeline, enriched with AI metadata for autonomous agent orchestration.

---

```yaml
openapi: 3.1.0
info:
  title: Cyber Security Pipeline API
  version: 2.0.0
  x-ai-metadata:
    agent_roles: [orchestrator, worker, dashboard, auditor]
    stateful_endpoints: ["/api/jobs/{id}", "/api/jobs/{id}/progress/stream"]
    mesh_aware: true

components:
  schemas:
    ErrorResponse:
      type: object
      required: [error]
      properties:
        error: {type: string}
        detail: {type: string}
        error_code: {type: string}
    JobStatus:
      type: object
      properties:
        id: {type: string}
        status: {enum: [running, completed, failed, cancelled]}
        progress: {type: integer, minimum: 0, maximum: 100}
    CacheNamespaceResponse:
      type: object
      properties:
        cleared: {type: integer}
        namespace: {type: string}
    MeshNodeSchema:
      type: object
      properties:
        id: {type: string}
        host: {type: string}
        port: {type: integer}
        status: {type: string}
        cpu_usage: {type: number}
        ram_available_mb: {type: number}
        active_jobs: {type: integer}
        last_seen: {type: number}
    JobResponse:
      type: object
      properties:
        id: {type: string}
        base_url: {type: string}
        hostname: {type: string}
        scope_entries: {type: array, items: {type: string}}
        enabled_modules: {type: array, items: {type: string}}
        mode: {type: string}
        target_name: {type: string}
        status: {type: string}
        stage: {type: string}
        stage_label: {type: string}
        status_message: {type: string}
        progress_percent: {type: integer}
        started_at: {type: string}

paths:
  /api/jobs:
    get:
      summary: List all jobs
      x-ai-action: list_jobs
      x-ai-idempotency: true
      responses:
        '200':
          description: OK
    post:
      summary: Start a new scan job
      x-ai-action: start_scan
      x-ai-requires: [base_url]
      x-ai-idempotency: false
      x-ai-impact: high
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [base_url]
              properties:
                base_url: {type: string, description: Target base URL}
                target_name: {type: string, default: "", description: Target name for output directory}
                scope_text: {type: string, default: "", description: Additional scope entries}
                mode: {type: string, default: idor, description: Pipeline mode}
                modules: {type: array, items: {type: string}, nullable: true, description: Selected module names}
                runtime_overrides: {type: object, additionalProperties: {type: string}, description: Runtime configuration overrides}
                execution_options: {type: object, additionalProperties: {type: boolean}, description: Execution option flags}
      responses:
        '201': {description: Job created}
        '422': {$ref: '#/components/schemas/ErrorResponse'}

  /api/jobs/{id}:
    get:
      summary: Get job status
      x-ai-action: get_job_status
      x-ai-idempotency: true
      parameters:
        - name: id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200': {content: {application/json: {schema: {$ref: '#/components/schemas/JobStatus'}}}}
        '404': {$ref: '#/components/schemas/ErrorResponse'}
  /api/jobs/{id}/stop:
    post:
      summary: Stop/cancel a job
      x-ai-action: stop_scan
      x-ai-idempotency: false
      x-ai-impact: medium
      parameters:
        - name: id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: Job stopped
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
        '401': {$ref: '#/components/schemas/ErrorResponse'}
        '404': {$ref: '#/components/schemas/ErrorResponse'}

  /api/jobs/{id}/progress/stream:
    get:
      summary: SSE progress stream
      x-ai-stream: true
      x-ai-event-types: [stage_started, stage_change, progress_update, iteration_change, finding_batch, completed, error, log, heartbeat]
      x-ai-reconnect-strategy: {backoff: exponential, max_retries: 5}
      responses:
        '200': {description: Event stream}

  /api/health:
    get:
      summary: System health status
      x-ai-action: check_health
      x-ai-idempotency: true
      responses:
        '200':
          content:
            application/json:
              schema:
                type: object
                properties:
                  status: {type: string}
                  timestamp: {type: string}
                  version: {type: string, default: "2.0.0"}
                  uptime_seconds: {type: number, nullable: true}
                  dependencies: {type: object, description: "Introspection check status of critical dependencies"}
                  mesh:
                    type: array
                    items:
                      $ref: '#/components/schemas/MeshNodeSchema'

  /api/cache/clear:
    post:
      summary: Clear system caches
      x-ai-action: clear_cache
      x-ai-requires: [admin]
      x-ai-idempotency: false
      x-ai-impact: high
      responses:
        '200':
          description: Cache cleared
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CacheNamespaceResponse'
        '401': {$ref: '#/components/schemas/ErrorResponse'}
        '403': {$ref: '#/components/schemas/ErrorResponse'}

  /api/health/live:
    get:
      summary: Liveness check
      x-ai-action: check_liveness
      x-ai-idempotency: true
      responses:
        '200':
          content:
            application/json:
              schema:
                type: object
                properties:
                  status: {type: string}
                  timestamp: {type: string}

  /api/health/ready:
    get:
      summary: Readiness check — returns ready=true when all critical dependencies are UP
      x-ai-action: check_readiness
      x-ai-idempotency: true
      responses:
        '200':
          content:
            application/json:
              schema:
                type: object
                properties:
                  ready: {type: boolean}
                  checks: {type: object}

  /api/health/mesh:
    get:
      summary: Mesh health — raw view of mesh membership and transport statistics
      x-ai-action: get_mesh_health
      x-ai-idempotency: true
      responses:
        '200': {description: Mesh telemetry JSON}

  /api/bloom/health:
    get:
      summary: Bloom filter mesh health — per-node memory, element count, FP probability, saturation history
      x-ai-action: get_bloom_health
      x-ai-idempotency: true
      responses:
        '200': {description: Bloom mesh health JSON}

  /api/bloom/reconcile:
    post:
      summary: Force an immediate Bloom snapshot publish across all online mesh nodes
      x-ai-action: reconcile_bloom_mesh
      x-ai-idempotency: true
      x-ai-impact: medium
      responses:
        '200': {description: Reconciliation status JSON}

  /api/findings/{finding_id}:
    put:
      summary: Update a finding's metadata (e.g. status, notes)
      x-ai-action: update_finding
      x-ai-idempotency: false
      parameters:
        - name: finding_id
          in: path
          required: true
          schema: {type: string}
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                status: {type: string, description: "Updated status of the finding (e.g. false_positive, detected)"}
                severity: {type: string, enum: [low, medium, high, critical], description: "Adjusted finding severity"}
                decision: {type: string, enum: [DROP, KEEP], description: "False positive suppression action"}
                lifecycle_state: {type: string, enum: [FALSE_POSITIVE, TRUE_POSITIVE, CONFIRMED], description: "Lifecycle tracking state"}
                notes: {type: string, description: "Triage notes/explanation"}
      responses:
        '200': {description: Finding updated}
        '404': {$ref: '#/components/schemas/ErrorResponse'}
        '401': {$ref: '#/components/schemas/ErrorResponse'}
    delete:
      summary: Remove a finding
      x-ai-action: delete_finding
      x-ai-idempotency: false
      x-ai-impact: high
      parameters:
        - name: finding_id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200': {description: Finding deleted}
        '404': {$ref: '#/components/schemas/ErrorResponse'}
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
