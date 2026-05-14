import { apiClient, cachedGet } from './core';

export interface TracingConfig {
  endpoint: string;
  status: 'connected' | 'unreachable';
  otel_available: boolean;
  local_span_db: string;
  initialization_error?: string;
}

export interface TraceSummary {
  trace_id: string;
  name: string;
  stage_name: string;
  service_name: string;
  start_ns: number;
  end_ns: number;
  duration_ms: number;
  status: 'OK' | 'ERROR' | string;
  span_count: number;
}

export interface TraceSpan {
  trace_id: string;
  span_id: string;
  parent_span_id: string | null;
  name: string;
  service_name: string;
  stage_name: string;
  start_time_unix_nano: number;
  end_time_unix_nano: number;
  duration_ms: number;
  status: 'OK' | 'ERROR' | string;
  attributes: Record<string, unknown>;
  events: Array<Record<string, unknown>>;
}

export interface TraceDetail {
  trace_id: string;
  spans: TraceSpan[];
}

export async function getTracingConfig(signal?: AbortSignal): Promise<TracingConfig> {
  return cachedGet<TracingConfig>('/api/tracing/config', { signal, bypassCache: true });
}

export async function getTraces(params: {
  serviceName?: string;
  startMs?: number;
  endMs?: number;
  limit?: number;
  signal?: AbortSignal;
} = {}): Promise<TraceSummary[]> {
  const queryParams: Record<string, string | number> = {
    limit: params.limit ?? 100,
  };
  if (params.serviceName) queryParams.service_name = params.serviceName;
  if (params.startMs) queryParams.start_ms = params.startMs;
  if (params.endMs) queryParams.end_ms = params.endMs;

  const res = await apiClient.get<{ traces: TraceSummary[] }>('/api/traces', {
    params: queryParams,
    signal: params.signal,
  });
  return res.data.traces ?? [];
}

export async function getTrace(traceId: string, signal?: AbortSignal): Promise<TraceDetail> {
  const res = await apiClient.get<TraceDetail>(`/api/traces/${traceId}`, { signal });
  return res.data;
}

