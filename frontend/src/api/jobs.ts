import type { Job, JobLogs, RemediationResponse, TraceLink } from '@/types/api';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';

import { JobSchema } from './schemas';
import { z } from 'zod';

export async function getJobs(signal?: AbortSignal, ttl?: number): Promise<Job[]> {
  const res = await cachedGet<{ jobs: Job[]; total: number }>('/api/jobs', { 
    signal, 
    ttl,
    schema: z.object({ jobs: z.array(JobSchema) })
  });
  return res.jobs ?? [];
}

export async function getJob(jobId: string, signal?: AbortSignal, ttl?: number): Promise<Job | null> {
  try {
    return await cachedGet<Job>(`/api/jobs/${jobId}`, { 
      signal, 
      ttl,
      schema: JobSchema
    });
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
}

export async function startJob(payload: StartJobPayload, signal?: AbortSignal): Promise<Job> {
  const { data } = await apiClient.post<Job>('/api/jobs/start', payload, { signal });
  apiCache.invalidatePrefix('/api/jobs');
  apiCache.invalidatePrefix('/api/targets');
  apiCache.invalidatePrefix('/api/findings');
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

export interface HistoricalDurationEntry {
  module: string;
  avg_duration_sec: number;
  p50_duration_sec: number;
  p95_duration_sec: number;
  sample_count: number;
}

export async function getHistoricalDurations(signal?: AbortSignal): Promise<HistoricalDurationEntry[] | null> {
  try {
    return await cachedGet<HistoricalDurationEntry[]>('/api/jobs/historical-durations', { signal });
  } catch (error) {
    if ((error as { status?: number })?.status === 501) {
      return null;
    }
    throw error;
  }
}
