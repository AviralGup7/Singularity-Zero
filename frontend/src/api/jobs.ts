import type { Job, JobLogs, RemediationResponse, TraceLink } from '@/types/api';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';
import { appendStreamToken } from './streamAuth';

import { asNumber, asRecord, asString, readPageEnvelope, toJobListParams, type JobListQuery, type PageEnvelope } from './contract';

export interface JobsListParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_dir?: 'asc' | 'desc';
  status?: string;
  search?: string;
}

export function normalizeJobRecord(raw: unknown): Job | null {
  const rec = asRecord(raw);
  if (!rec) return null;
  const id = asString(rec.id);
  if (!id) return null;
  const status = asString(rec.status || 'queued') as Job['status'];
  return {
    ...(rec as unknown as Job),
    id,
    status,
    base_url: asString(rec.base_url),
    hostname: asString(rec.hostname || rec.target_name),
    target_name: asString(rec.target_name || rec.hostname),
    mode: asString(rec.mode),
    stage_label: asString(rec.stage_label || rec.stage),
    progress_percent: asNumber(rec.progress_percent, 0),
    has_eta: Boolean(rec.has_eta),
    eta_label: asString(rec.eta_label),
    stalled: Boolean(rec.stalled),
    started_at: asString(rec.started_at),
    latest_logs: Array.isArray(rec.latest_logs) ? rec.latest_logs.map((line) => asString(line)) : [],
    error: rec.error == null ? null : asString(rec.error),
    warnings: Array.isArray(rec.warnings) ? rec.warnings.map((line) => asString(line)) : [],
    enabled_modules: Array.isArray(rec.enabled_modules) ? rec.enabled_modules.map((item) => asString(item)) : [],
    scope_entries: Array.isArray(rec.scope_entries) ? rec.scope_entries.map((item) => asString(item)) : [],
    status_message: asString(rec.status_message),
    execution_options: (asRecord(rec.execution_options) as Record<string, boolean>) ?? {},
  };
}

export async function getJobsPage(params?: JobListQuery, signal?: AbortSignal, ttl?: number): Promise<PageEnvelope<Job>> {
  const res = await cachedGet<unknown>('/api/jobs', {
    signal,
    ttl,
    params: toJobListParams(params),
  });
  return readPageEnvelope(res, 'jobs', (item) => normalizeJobRecord(item));
}

export async function getJobs(params?: JobsListParams, signal?: AbortSignal, ttl?: number): Promise<Job[]> {
  const query: JobListQuery = {
    page: params?.page ?? 1,
    page_size: params?.page_size ?? 100,
    status: params?.status,
    search: params?.search,
    sort_by: params?.sort_by,
    sort_dir: params?.sort_dir,
  };
  const first = await getJobsPage(query, signal, ttl);
  if (first.total <= first.items.length) return first.items;
  const pages = Math.min(8, Math.ceil(first.total / first.pageSize));
  const rest = await Promise.all(
    Array.from({ length: pages - 1 }, (_, index) =>
      getJobsPage({ ...query, page: index + 2, page_size: first.pageSize }, signal, ttl),
    ),
  );
  return rest.reduce((acc, page) => acc.concat(page.items), first.items);
}

export async function getJob(jobId: string, signal?: AbortSignal, ttl?: number): Promise<Job | null> {
  try {
    const raw = await cachedGet<unknown>(`/api/jobs/${jobId}`, { signal, ttl });
    return normalizeJobRecord(raw);
  } catch (error) {
    const status = (error as { status?: number } | undefined)?.status;
    if (status === 404) {
      return null;
    }
    throw error;
  }
}

export async function getJobLogs(jobId: string, signal?: AbortSignal): Promise<JobLogs> {
  const res = await cachedGet<JobLogs>(`/api/jobs/${jobId}/logs`, { signal });
  return res;
}

export async function getJobTraceLink(jobId: string, signal?: AbortSignal): Promise<TraceLink> {
  return cachedGet<TraceLink>(`/api/jobs/${jobId}/trace`, { signal, ttl: 5000 });
}

export async function getJobRemediation(jobId: string, signal?: AbortSignal): Promise<RemediationResponse> {
  return cachedGet<RemediationResponse>(`/api/jobs/${jobId}/remediation`, { signal, ttl: 5000 });
}

export interface StartJobPayload {
  base_url: string;
  scope_text?: string;
  mode?: string;
  modules?: string[];
  runtime_overrides?: Record<string, string>;
  execution_options?: Record<string, boolean>;
  project_id?: string;
  /**
   * High-level scan tuning knobs surfaced in the cockpit (P1-3) so operators
   * do not need to open the 4-step wizard to tune a 12-hour scan. Values are
   * forwarded to the runtime as `runtime_overrides` so the backend picks
   * them up uniformly with the wizard's hidden step-3 inputs.
   */
  depth?: number;
  concurrency?: number;
  rate_limit_rps?: number;
  /** Newline-separated regex/path patterns the scan will skip. */
  excluded_paths?: string;
}

export async function startJob(payload: StartJobPayload, signal?: AbortSignal): Promise<Job> {
  const { depth, concurrency, rate_limit_rps, excluded_paths: _excluded_paths, ...rest } = payload;

  const runtime_overrides = { ...(rest.runtime_overrides ?? {}) };
  if (concurrency !== undefined) {
    runtime_overrides['httpx_threads'] = String(concurrency);
  }
  if (rate_limit_rps !== undefined) {
    runtime_overrides['request_rate_per_second'] = String(rate_limit_rps);
  }
  if (depth !== undefined) {
    // If the backend template supports depth settings, pass it here
    runtime_overrides['depth'] = String(depth);
  }

  const finalPayload = {
    ...rest,
    runtime_overrides,
  };

  const { data } = await apiClient.post<Job>('/api/jobs/start', finalPayload, { signal });
  apiCache.invalidatePrefix('/api/jobs');
  apiCache.invalidatePrefix('/api/targets');
  apiCache.invalidatePrefix('/api/findings');
  console.debug(`[startJob] returned job id=${data.id} base_url=${data.base_url}`);
  return data;
}

export async function stopJob(jobId: string, signal?: AbortSignal): Promise<Job> {
  const { data } = await apiClient.post<Job>(`/api/jobs/${jobId}/stop`, undefined, { signal });
  apiCache.invalidatePrefix('/api/jobs');
  return data;
}

export async function restartJob(jobId: string, signal?: AbortSignal): Promise<Job> {
  const { data } = await apiClient.post<Job>(`/api/jobs/${jobId}/restart-safe`, undefined, { signal });
  apiCache.invalidatePrefix('/api/jobs');
  return data;
}

export async function pauseJob(jobId: string, signal?: AbortSignal): Promise<Job> {
  const { data } = await apiClient.post<Job>(`/api/jobs/${jobId}/pause`, undefined, { signal });
  apiCache.invalidatePrefix('/api/jobs');
  return data;
}

export async function resumeJob(jobId: string, signal?: AbortSignal): Promise<Job> {
  const { data } = await apiClient.post<Job>(`/api/jobs/${jobId}/resume`, undefined, { signal });
  apiCache.invalidatePrefix('/api/jobs');
  return data;
}

export interface HistoricalDurationEntry {
  module: string;
  avg_duration_sec: number;
  p50_duration_sec: number;
  p95_duration_sec: number;
  sample_count: number;
}

export async function getHistoricalDurations(signal?: AbortSignal): Promise<HistoricalDurationEntry[] | null> {
  try {
    return asDurationEntries(await cachedGet<unknown>('/api/jobs/historical-durations', { signal }));
  } catch (error) {
    if ((error as { status?: number })?.status === 501) {
      return null;
    }
    throw error;
  }
}

export function jobProgressStreamUrl(jobId: string): string {
  const id = String(jobId ?? '').trim();
  if (!id) return '';
  return appendStreamToken(`/api/jobs/${encodeURIComponent(id)}/progress/stream`);
}

export function asJobList(value: unknown): Job[] {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeJobRecord(item)).filter((item): item is Job => Boolean(item));
  }
  return readPageEnvelope(value, 'jobs', (item) => normalizeJobRecord(item)).items;
}

export function asDurationEntries(value: unknown): HistoricalDurationEntry[] {
  if (Array.isArray(value)) return value as HistoricalDurationEntry[];
  if (value && typeof value === 'object' && Array.isArray((value as { entries?: unknown }).entries)) {
    return (value as { entries: HistoricalDurationEntry[] }).entries;
  }
  return [];
}
