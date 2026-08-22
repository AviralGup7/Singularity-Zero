import type { Target, Defaults } from '@/types/api';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';

export function asTargetList(value: unknown): Target[] {
  return Array.isArray(value) ? value as Target[] : [];
}

export function asTargetFindings(value: unknown): import('@/types/api').Finding[] {
  return Array.isArray(value) ? value as import('@/types/api').Finding[] : [];
}

export async function getTargets(signal?: AbortSignal, ttl?: number): Promise<{ targets: Target[] }> {
  const res = await cachedGet<{ targets: Target[] }>('/api/targets', { signal, ttl });
  return { ...res, targets: asTargetList(res.targets) };
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
  if (!String(targetA ?? '').trim() || !String(targetB ?? '').trim()) {
    throw new Error('Both targets are required');
  }
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
  const findings = Array.isArray(data.findings) ? data.findings : [];
  return { ...data, findings, total: Number.isFinite(data.total) ? data.total : findings.length };
}

