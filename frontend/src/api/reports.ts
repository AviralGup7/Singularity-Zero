import type { DetectionGapResponse, HealthStatus } from '@/types/api';
import { apiClient, cachedGet } from './core';

export async function getHealth(signal?: AbortSignal, ttl?: number): Promise<HealthStatus> {
  return cachedGet<HealthStatus>('/api/health', { signal, ttl });
}

export async function getGapAnalysis(target?: string | null, signal?: AbortSignal): Promise<DetectionGapResponse> {
  let targetStr: string | undefined = undefined;
  let abortSignal: AbortSignal | undefined = signal;
  
  if (typeof target === 'string') {
    targetStr = target;
  } else if (target instanceof AbortSignal || (target && 'aborted' in target)) {
    abortSignal = target as AbortSignal;
  }
  
  const params = targetStr ? { target: targetStr } : undefined;
  return cachedGet<DetectionGapResponse>('/api/gap-analysis', { signal: abortSignal, params });
}

export async function refreshGapAnalysis(signal?: AbortSignal): Promise<{ status: string }> {
  const { data } = await apiClient.post('/api/gap-analysis/refresh', {}, { signal });
  return data;
}

export async function exportFindings(options: { format: 'csv' | 'json'; signal?: AbortSignal; target?: string }): Promise<Blob> {
  const target = options.target || 'all';
  const { data } = await apiClient.get(`/api/export/findings/${target}`, {
    signal: options.signal,
    params: { format: options.format },
    responseType: 'blob',
  });
  return data;
}
