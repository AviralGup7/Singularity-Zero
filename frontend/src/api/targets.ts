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
  await apiClient.delete(`/api/targets/${id}`, { signal });
  apiCache.invalidatePrefix('/api/targets');
}
