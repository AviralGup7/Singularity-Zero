# Observability Catalog

Cyber Security Test Pipeline — Metrics, Alerts, Dashboards, and Cardinality Audit

---

## 1. Metrics Catalog

### 1.1 HTTP API Metrics

| Metric Name | Type | Labels | Buckets/Quantiles | Source File | Description |
|---|---|---|---|---|---|
| `cyber_pipeline_http_request_duration_seconds` | Histogram | `method`, `route`, `status` | 5ms–30s | `http_metrics.py` | Per-endpoint request latency |
| `cyber_pipeline_http_requests_total` | Counter | `method`, `route`, `status` | — | `http_metrics.py` | Total requests by endpoint |
| `cyber_pipeline_http_request_errors_total` | Counter | `method`, `route`, `status_class` | — | `http_metrics.py` | 4xx/5xx errors by endpoint |
| `cyber_pipeline_http_requests_in_flight` | Gauge | `method` | — | `http_metrics.py` | Currently processing requests |
| `cyber_pipeline_request_latency_seconds` | Histogram | — | default | `metrics.py` | Legacy API latency (global) |

**Cardinality controls:** Route labels normalized (UUIDs→`{uuid}`, IDs→`{id}`), max 256 unique routes, overflow→`__other__`.

### 1.2 Database Metrics

| Metric Name | Type | Labels | Buckets/Quantiles | Source File | Description |
|---|---|---|---|---|---|
| `cyber_pipeline_db_query_duration_seconds` | Histogram | `operation` | 1ms–10s | `db_metrics.py` | Query execution latency by op type |
| `cyber_pipeline_db_queries_total` | Counter | `operation` | — | `db_metrics.py` | Total queries by operation |
| `cyber_pipeline_db_query_errors_total` | Counter | — | — | `db_metrics.py` | Total query errors |
| `cyber_pipeline_db_connections_total` | Counter | — | — | `db_metrics.py` | Connections created |
| `cyber_pipeline_db_connection_checkouts_total` | Counter | — | — | `db_metrics.py` | Connection checkouts |
| `cyber_pipeline_db_pool_size` | Gauge | — | — | `db_metrics.py` | Pool total size |
| `cyber_pipeline_db_pool_checked_out` | Gauge | — | — | `db_metrics.py` | Connections in use |
| `cyber_pipeline_db_pool_checked_in` | Gauge | — | — | `db_metrics.py` | Idle connections |
| `cyber_pipeline_db_pool_overflow` | Gauge | — | — | `db_metrics.py` | Overflow connections |

**Cardinality controls:** `operation` label bounded to 6 values (select/insert/update/delete/ddl/other).

### 1.3 Queue Metrics

| Metric Name | Type | Labels | Buckets/Quantiles | Source File | Description |
|---|---|---|---|---|---|
| `cyber_pipeline_queue_enqueued_total` | Counter | `queue`, `job_type` | — | `queue_metrics.py` | Jobs enqueued |
| `cyber_pipeline_queue_dequeued_total` | Counter | `queue`, `worker_id`, `job_type` | — | `queue_metrics.py` | Jobs dequeued |
| `cyber_pipeline_queue_throughput_total` | Counter | `queue`, `operation` | — | `queue_metrics.py` | Total queue ops |
| `cyber_pipeline_queue_consumer_lag` | Gauge | `queue` | — | `queue_metrics.py` | Pending minus capacity |
| `cyber_pipeline_queue_depth_current` | Gauge | `queue` | — | `queue_metrics.py` | Current queue depth |
| `cyber_pipeline_queue_job_processing_seconds` | Histogram | `queue`, `job_type` | 1ms–5min | `queue_metrics.py` | Job processing duration |
| `cyber_pipeline_queue_batch_size` | Histogram | `queue`, `worker_id` | — | `queue_metrics.py` | Batch processing size |
| `cyber_pipeline_queue_retries_total` | Counter | `queue`, `job_type`, `reason` | — | `queue_metrics.py` | Job retries |
| `cyber_pipeline_queue_dead_letter_events_total` | Counter | `queue`, `job_type`, `error_type` | — | `queue_metrics.py` | Dead-letter events |

**Cardinality controls:** `job_type` bounded to 32 unique values, `worker_id` bounded to 128, overflow→`__other__`.

### 1.4 Resource Pool Metrics

| Metric Name | Type | Labels | Buckets/Quantiles | Source File | Description |
|---|---|---|---|---|---|
| `cyber_pipeline_pool_active` | Gauge | `pool` | — | `resource_pool_metrics.py` | Active resources |
| `cyber_pipeline_pool_idle` | Gauge | `pool` | — | `resource_pool_metrics.py` | Idle resources |
| `cyber_pipeline_pool_max_size` | Gauge | `pool` | — | `resource_pool_metrics.py` | Pool capacity |
| `cyber_pipeline_pool_waiting` | Gauge | `pool` | — | `resource_pool_metrics.py` | Callers waiting |
| `cyber_pipeline_pool_utilization_ratio` | Gauge | `pool` | — | `resource_pool_metrics.py` | active/max ratio |
| `cyber_pipeline_pool_saturation_ratio` | Gauge | `pool` | — | `resource_pool_metrics.py` | (active+waiting)/max ratio |
| `cyber_pipeline_pool_wait_time_seconds` | Histogram | `pool` | 1ms–5s | `resource_pool_metrics.py` | Wait time for resource |
| `cyber_pipeline_pool_timeouts_total` | Counter | `pool` | — | `resource_pool_metrics.py` | Pool access timeouts |
| `cyber_pipeline_pool_exhaustion_events_total` | Counter | `pool` | — | `resource_pool_metrics.py` | Exhaustion events |
| `cyber_pipeline_thread_pool_active_count` | Gauge | `pool` | — | `resource_pool_metrics.py` | Active threads |
| `cyber_pipeline_asyncio_tasks_pending` | Gauge | `pool` | — | `resource_pool_metrics.py` | Pending asyncio tasks |

**Cardinality controls:** `pool` label bounded by known pool names (db_pool, thread_pool, etc.).

### 1.5 Analyzer Metrics

| Metric Name | Type | Labels | Buckets/Quantiles | Source File | Description |
|---|---|---|---|---|---|
| `cyber_pipeline_analyzer_execution_duration_seconds` | Histogram | `analyzer_type`, `category` | 100ms–5min | `analyzer_metrics.py` | Execution duration |
| `cyber_pipeline_analyzer_executions_total` | Counter | `analyzer_type`, `category`, `status` | — | `analyzer_metrics.py` | Total executions |
| `cyber_pipeline_analyzer_findings_total` | Counter | `analyzer_type`, `category` | — | `analyzer_metrics.py` | Findings produced |
| `cyber_pipeline_analyzer_errors_total` | Counter | `analyzer_type`, `error_type` | — | `analyzer_metrics.py` | Errors by type |
| `cyber_pipeline_analyzer_active_executions` | Gauge | `analyzer_type` | — | `analyzer_metrics.py` | Currently executing |
| `cyber_pipeline_analyzer_throughput_items_per_second` | Gauge | `analyzer_type`, `category` | — | `analyzer_metrics.py` | Processing throughput |
| `cyber_pipeline_analyzer_items_processed_total` | Counter | `analyzer_type`, `category` | — | `analyzer_metrics.py` | Total items processed |
| `cyber_pipeline_analyzer_skips_total` | Counter | `analyzer_type`, `reason` | — | `analyzer_metrics.py` | Skip events |

**Cardinality controls:** `analyzer_type` bounded to 64 unique values, `category` bounded to 10 known categories.

### 1.6 Pipeline Core Metrics (Existing)

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `cyber_pipeline_total_jobs` | Counter | — | Total jobs enqueued |
| `cyber_pipeline_completed_jobs` | Counter | — | Completed jobs |
| `cyber_pipeline_failed_jobs` | Counter | — | Failed jobs |
| `cyber_pipeline_cache_hits` | Counter | — | Cache hits |
| `cyber_pipeline_cache_misses` | Counter | — | Cache misses |
| `cyber_pipeline_retries_total` | Counter | — | Job retries |
| `cyber_pipeline_dead_letter_total` | Counter | — | Dead-lettered jobs |
| `cyber_pipeline_active_workers` | Gauge | — | Active workers |
| `cyber_pipeline_queue_depth` | Gauge | — | Queue depth |
| `cyber_pipeline_active_connections` | Gauge | — | WebSocket connections |
| `cyber_pipeline_memory_usage_mb` | Gauge | — | Memory usage |
| `cyber_pipeline_cpu_usage_percent` | Gauge | — | CPU usage |
| `cyber_pipeline_job_duration_seconds` | Histogram | — | Job execution duration |
| `cyber_pipeline_scan_duration_seconds` | Histogram | — | Scan duration |
| `cyber_pipeline_analyzer_duration_seconds` | Histogram | — | Analyzer execution (legacy) |
| `cyber_pipeline_pipeline_stage_duration_seconds` | Histogram | — | Pipeline stage duration |

### 1.7 WebSocket Metrics (Existing, prometheus_client)

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `cyber_pipeline_ws_active_connections` | Gauge | `user_id` | Active WS connections |
| `cyber_pipeline_ws_messages_broadcast_total` | Counter | `scope` | Messages broadcast |
| `cyber_pipeline_ws_dispatch_latency_seconds` | Histogram | — | Dispatch latency |
| `cyber_pipeline_ws_reconnections_total` | Counter | `status` | Reconnections |
| `cyber_pipeline_ws_dropped_messages_total` | Counter | `scope`, `job_id`, `user_id` | Dropped messages |

### 1.8 Recon Metrics (Existing, prometheus_client)

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `cyber_pipeline_recon_provider_requests_total` | Counter | `provider` | Provider requests |
| `cyber_pipeline_recon_provider_errors_total` | Counter | `provider` | Provider errors |
| `cyber_pipeline_recon_provider_duration_seconds` | Histogram | `provider` | Provider duration |

---

## 2. Alert Catalog

### 2.1 Infrastructure Alerts

| Alert Name | Severity | Metric | Condition | Duration | Runbook |
|---|---|---|---|---|---|
| `queue_depth_high` | WARNING | `cyber_pipeline_queue_depth` | > 1000 | 60s | Check worker health, scale up |
| `worker_count_low` | CRITICAL | `cyber_pipeline_active_workers` | < 2 | 30s | Restart workers |
| `error_rate_high` | CRITICAL | `cyber_pipeline_error_rate` | > 5% | 120s | Review changes, check logs |
| `cache_hit_rate_low` | WARNING | `cyber_pipeline_cache_hit_rate` | < 50% | 300s | Check cache backend health |
| `memory_usage_high` | WARNING | `cyber_pipeline_memory_usage_mb` | > 4096 MB | 60s | Check for leaks |
| `response_latency_sla_breach` | CRITICAL | `cyber_pipeline_response_time_seconds` | > 5s | 30s | Check API and DB performance |
| `dead_letter_queue_growing` | WARNING | `cyber_pipeline_dead_letter_total` | > 10 | 300s | Review dead-letter jobs |
| `websocket_connections_high` | INFO | `cyber_pipeline_active_connections` | > 500 | 60s | Monitor resources |

### 2.2 Pipeline State Alerts

| Alert Name | Severity | Condition | Runbook |
|---|---|---|---|
| `CRITICAL_FINDING_DISCOVERED` | CRITICAL | Finding with severity=critical | Immediate triage required |
| `SCOPE_VIOLATION` | CRITICAL | Request outside scope | Validate scope configuration |
| `PIPELINE_FAILURE` | CRITICAL | Stage has failed status | Check module_metrics |
| `TOOL_UNAVAILABLE` | WARNING | Configured tool not on PATH | Install missing tool |
| `RECON_COVERAGE_LOW` | WARNING | Subdomain count < 5 | Review recon configuration |

### 2.3 Database Alerts (NEW)

| Alert Name | Severity | Metric | Condition | Duration | Runbook |
|---|---|---|---|---|---|
| `db_query_latency_high` | WARNING | `cyber_pipeline_db_query_duration_seconds` | > 1s (p95) | 120s | Check slow queries, indexes |
| `db_query_error_rate_high` | CRITICAL | `cyber_pipeline_db_query_errors_total` | > 10/min | 60s | Check DB connectivity, locks |
| `db_pool_exhausted` | CRITICAL | `cyber_pipeline_db_pool_checked_out` | >= 9 | 30s | Check for leaks, increase pool |

### 2.4 Queue Performance Alerts (NEW)

| Alert Name | Severity | Metric | Condition | Duration | Runbook |
|---|---|---|---|---|---|
| `queue_consumer_lag_high` | WARNING | `cyber_pipeline_queue_consumer_lag` | > 100 | 180s | Scale workers, check slow jobs |
| `queue_processing_time_high` | WARNING | `cyber_pipeline_queue_job_processing_seconds` | > 300s | 60s | Check for stuck jobs |

### 2.5 HTTP Performance Alerts (NEW)

| Alert Name | Severity | Metric | Condition | Duration | Runbook |
|---|---|---|---|---|---|
| `http_error_rate_high` | WARNING | `cyber_pipeline_http_request_errors_total` | > 50/min | 120s | Check API logs, downstream health |
| `http_latency_sla_breach` | CRITICAL | `cyber_pipeline_http_request_duration_seconds` | > 5s | 60s | Check slow queries, API calls |

### 2.6 Analyzer Performance Alerts (NEW)

| Alert Name | Severity | Metric | Condition | Duration | Runbook |
|---|---|---|---|---|---|
| `analyzer_failure_rate_high` | WARNING | `cyber_pipeline_analyzer_errors_total` | > 20/min | 300s | Check analyzer logs |
| `analyzer_duration_high` | WARNING | `cyber_pipeline_analyzer_execution_duration_seconds` | > 120s | 120s | Check target size, network |

### 2.7 Resource Pool Alerts (NEW)

| Alert Name | Severity | Metric | Condition | Duration | Runbook |
|---|---|---|---|---|---|
| `pool_utilization_high` | WARNING | `cyber_pipeline_pool_utilization_ratio` | > 85% | 120s | Scale pool, optimize usage |
| `pool_timeouts_increasing` | CRITICAL | `cyber_pipeline_pool_timeouts_total` | > 5/min | 60s | Check exhaustion, increase pool |

---

## 3. Grafana Dashboard Specification

### 3.1 Dashboard Inventory

| Dashboard | UID | Panels | Refresh | Description |
|---|---|---|---|---|
| Pipeline Overview | `pipeline-overview` | 16 | 30s | Main pipeline health, jobs, workers |
| HTTP API Performance | `http-api-performance` | 8 | 30s | Request latency, throughput, errors |
| Database Performance | `db-performance` | 9 | 30s | Query latency, connection pool, transactions |
| Queue Throughput | `queue-throughput` | 10 | 30s | Enqueue/dequeue rates, consumer lag, workers |
| Analyzer Execution | `analyzer-execution` | 10 | 30s | Per-analyzer duration, throughput, findings |

### 3.2 HTTP API Performance Dashboard

**Rows:**
1. **HTTP Overview** (4 stat panels): Requests/min, Error Rate, P95 Latency, P99 Latency
2. **Latency Distribution** (2 time-series): Percentiles (P50/P95/P99), Request Rate by Status Class
3. **Top Endpoints** (2 time-series): Top 10 by Request Rate, Top 10 by P95 Latency

**Key Queries:**
- `sum(rate(cyber_pipeline_http_requests_total[5m])) * 60` — Requests/min
- `histogram_quantile(0.95, sum(rate(cyber_pipeline_http_request_duration_seconds_bucket[5m])) by (le))` — P95 latency
- `topk(10, sum(rate(cyber_pipeline_http_requests_total[5m])) by (route))` — Top endpoints

### 3.3 Database Performance Dashboard

**Rows:**
1. **Database Overview** (4 panels): P95 Query Latency, QPS, Query Errors, Pool Health
2. **Query Performance** (2 time-series): Latency by Operation Type, Query Rate by Operation
3. **Connection Pool** (3 panels): Pool State (stacked), Utilization (gauge), Creates & Checkouts

**Key Queries:**
- `histogram_quantile(0.95, sum(rate(cyber_pipeline_db_query_duration_seconds_bucket[5m])) by (le))` — P95 query latency
- `cyber_pipeline_db_pool_checked_out / cyber_pipeline_db_pool_max_size` — Pool utilization

### 3.4 Queue Throughput Dashboard

**Rows:**
1. **Queue Overview** (6 stats): Queue Depth, Consumer Lag, DLQ, Active Workers, Retries/min, Avg Processing Time
2. **Throughput** (2 time-series): Enqueue vs Dequeue Rate, Consumer Lag Over Time
3. **Processing Details** (2 time-series): Processing Time by Job Type, Batch Size Over Time

**Key Queries:**
- `cyber_pipeline_queue_consumer_lag{queue="security-pipeline"}` — Consumer lag
- `histogram_quantile(0.95, sum(rate(cyber_pipeline_queue_job_processing_seconds_bucket[5m])) by (le, job_type))` — Processing time by type

### 3.5 Analyzer Execution Dashboard

**Rows:**
1. **Analyzer Overview** (6 stats): Executions/min, Error Rate, P95 Duration, Findings/min, Active Analyzers, Skipped
2. **Execution Performance** (2 time-series): P95 Duration by Type (top 10), Execution Rate by Type
3. **Errors and Findings** (2 time-series): Errors by Type, Findings by Type

**Key Queries:**
- `topk(10, histogram_quantile(0.95, sum(rate(cyber_pipeline_analyzer_execution_duration_seconds_bucket[5m])) by (le, analyzer_type)))` — Slowest analyzers
- `sum(rate(cyber_pipeline_analyzer_executions_total{status="error"}[5m])) / sum(rate(cyber_pipeline_analyzer_executions_total[5m]))` — Error rate

---

## 4. Cardinality Audit

### 4.1 Cardinality Risk Summary

| Label Set | Max Cardinality | Risk Level | Mitigation |
|---|---|---|---|
| `route` (HTTP) | 256 | **MEDIUM** | Path normalization, `__other__` fallback |
| `job_type` (Queue) | 32 | **LOW** | Bounded set with overflow |
| `analyzer_type` | 64 | **LOW** | Bounded set with overflow |
| `worker_id` | 128 | **LOW** | Bounded set with overflow |
| `operation` (DB) | 6 | **NONE** | Fixed allowlist |
| `method` (HTTP) | 7 | **NONE** | Fixed allowlist |
| `status` (HTTP) | ~5 | **NONE** | 3-digit status codes |
| `status_class` (HTTP) | 4 | **NONE** | Fixed allowlist (2xx/3xx/4xx/5xx) |
| `category` (Analyzer) | 10 | **NONE** | Fixed categories |
| `pool` (Resource) | ~5 | **NONE** | Known pool names |
| `queue` | 1 | **NONE** | Single queue name |

### 4.2 Total Estimated Series Count

| Metric Category | Estimated Series | Notes |
|---|---|---|
| HTTP Metrics | ~320 | 256 routes × ~1.25 avg labels |
| DB Metrics | ~30 | 6 operations × 5 metrics |
| Queue Metrics | ~128 | 32 job_types × 4 metrics |
| Resource Pool | ~50 | 5 pools × 10 metrics |
| Analyzer Metrics | ~192 | 64 types × 3 metrics |
| Pipeline Core | ~30 | Existing metrics |
| WebSocket | ~60 | Existing metrics |
| Recon | ~20 | Existing metrics |
| **Total** | **~830** | **Well under 10K safe limit** |

### 4.3 Cardinality Controls Implemented

1. **Bounded Label Sets** (`cardinality.py`):
   - `BoundedLabelSet`: Tracks unique values with max cardinality, overflow→`__other__`
   - `LabelAllowlist`: Restricts to predefined values, overflow→`__invalid__`
   - Global registry for audit

2. **Path Normalization** (`http_metrics.py`):
   - UUIDs → `{uuid}`
   - Numeric IDs → `{id}`
   - SHA hashes → `{sha}` / `{sha256}`
   - Max 256 unique route templates

3. **Label Value Truncation** (`cardinality.py`):
   - Max 128 characters per label value
   - Control character removal
   - Non-empty guarantee

4. **Pre-defined Allowlists** (`cardinality.py`):
   - HTTP methods: GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS
   - Status classes: 2xx/3xx/4xx/5xx
   - DB operations: select/insert/update/delete/ddl/other

### 4.4 Recommendations

1. **Monitor cardinality** via `cardinality_audit()` function — run weekly
2. **Alert on cardinality growth** — add alert when any bounded set exceeds 80% capacity
3. **Review `__other__` overflow** — if significant, investigate new label values
4. **Avoid user-controlled labels** — never use request bodies, query params, or user IDs as labels
5. **Use recording rules** for expensive aggregations in production

---

## 5. Integration Guide

### 5.1 HTTP Middleware

```python
# In src/dashboard/fastapi/middleware_setup.py
from src.dashboard.fastapi.http_metrics import HTTPMetricsMiddleware

def setup_middleware(app, config):
    app.add_middleware(HTTPMetricsMiddleware)
    # ... existing middleware
```

### 5.2 DB Instrumentation

```python
# In database initialization code
from src.infrastructure.observability.db_metrics import install_db_metrics

engine = create_engine(DATABASE_URL)
install_db_metrics(engine)
```

### 5.3 Queue Instrumentation

```python
# In worker or queue code
from src.infrastructure.observability.queue_metrics import QueueMetricsCollector

collector = QueueMetricsCollector(queue_name="security-pipeline")
await collector.record_enqueue(job_type="scan", count=1)
await collector.record_dequeue(worker_id="w-1", job_type="scan", count=1)
await collector.update_lag(lag=42)
```

### 5.4 Analyzer Instrumentation

```python
# In analyzer execution code
from src.infrastructure.observability.analyzer_metrics import AnalyzerMetrics

analyzer_metrics = AnalyzerMetrics()
with analyzer_metrics.track_execution("xss_detector") as tracker:
    results = run_xss_scan()
    tracker.set_findings_count(len(results))
```

### 5.5 Resource Pool Monitoring

```python
# In background task
from src.infrastructure.observability.resource_pool_metrics import ResourcePoolMetrics

pool_metrics = ResourcePoolMetrics()
pool_metrics.record_pool_state("db_pool", active=5, idle=3, max_size=10, waiting=0)
```
