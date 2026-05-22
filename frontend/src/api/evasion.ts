import { apiClient } from './core';

export interface EvasionMetrics {
  total_requests: number;
  successes: number;
  evasion_success_rate: number;
  [key: string]: unknown;
}

export interface EvasionMetricsResponse {
  metrics: Record<string, EvasionMetrics>;
}

export async function getEvasionMetrics(signal?: AbortSignal): Promise<EvasionMetricsResponse> {
  const { data } = await apiClient.get<EvasionMetricsResponse>('/api/evasion/metrics', { signal });
  return data;
}

export async function resetEvasionMetrics(signal?: AbortSignal): Promise<{ status: string; message: string }> {
  const { data } = await apiClient.post<{ status: string; message: string }>('/api/evasion/reset', undefined, { signal });
  return data;
}
