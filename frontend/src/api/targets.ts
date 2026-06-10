import type { Target, Defaults } from '@/types/api';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';

export async function getTargets(signal?: AbortSignal, ttl?: number): Promise<{ targets: Target[] }> {
  return cachedGet<{ targets: Target[] }>('/api/targets', { signal, ttl });
}

export async function getDefaults(signal?: AbortSignal, ttl?: number): Promise<Defaults> {
  return cachedGet<Defaults>('/api/defaults', { signal, ttl });
}

export async function deleteTarget(id: string, signal?: AbortSignal): Promise<void> {
  await apiClient.delete(`/api/targets/${encodeURIComponent(id)}`, { signal });
  apiCache.invalidatePrefix('/api/targets');
}

export async function compareTargets(
  targetA: string,
  targetB: string,
  signal?: AbortSignal
): Promise<{ target_a: Target; target_b: Target }> {
  const { data } = await apiClient.get<{ target_a: Target; target_b: Target }>('/api/targets/compare', {
    params: { target_a: targetA, target_b: targetB },
    signal,
  });
  return data;
}

export async function getTargetFindings(
  targetName: string,
  run?: string,
  signal?: AbortSignal,
): Promise<{ target: string; findings: import('@/types/api').Finding[]; total: number }> {
  const { data } = await apiClient.get<{ target: string; findings: import('@/types/api').Finding[]; total: number }>(
    `/api/targets/${encodeURIComponent(targetName)}/findings`,
    { params: run ? { run } : undefined, signal },
  );
  return data;
}

