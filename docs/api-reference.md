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
      x-ai-requires: [scope, config]
      x-ai-idempotency: false
      x-ai-impact: high
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [scope]
              properties:
                scope: {type: array, items: {type: string}, minItems: 1}
                config_override: {type: object}
                mode: {enum: [full, quick, recon-only], default: full}
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
    delete:
      summary: Stop/cancel a job
      x-ai-action: stop_scan
      x-ai-idempotency: false
      x-ai-impact: medium
      responses:
        '204': {description: Job cancelled}
        '404': {$ref: '#/components/schemas/ErrorResponse'}

  /api/jobs/{id}/progress/stream:
    get:
      summary: SSE progress stream
      x-ai-stream: true
      x-ai-event-types: [stage_started, stage_completed, finding_detected, progress_update, pipeline_error]
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
                  components:
                    type: object
                    properties:
                      redis: {type: string}
                      database: {type: string}
                      mesh: {type: string}
                      workers: {type: integer}

  /api/cache/clear:
    post:
      summary: Clear system caches
      x-ai-action: clear_cache
      x-ai-idempotency: false
      x-ai-impact: high
      responses:
        '200': {description: Cache cleared}

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
            schema: {type: object}
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
- **Message Format**: JSON strings with keys `timestamp`, `level`, `module`, `message`.
- **Auth**: Requires `X-API-Key` header or `token` query parameter.
