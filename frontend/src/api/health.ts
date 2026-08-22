import type { ReadinessResponse } from '@/types/extended';
import type { MeshHealth } from '@/types/api';
import { apiClient, cachedGet, cachedPost } from './core';

export async function getReadiness(signal?: AbortSignal): Promise<ReadinessResponse> {
  return cachedGet<ReadinessResponse>('/api/health/ready', { signal, bypassCache: true });
}

export async function getLiveness(signal?: AbortSignal): Promise<{ status: string; timestamp?: string; uptime?: number }> {
  return cachedGet<{ status: string; timestamp?: string; uptime?: number }>('/api/health/live', { signal, bypassCache: true });
}

/**
 * Pings the backend liveness endpoint and returns the server-stamped time
 * so callers can compute client ↔ server clock skew.
 *
 * Uses the raw `apiClient` (not the cached wrapper) because we always want
 * a fresh timestamp and the request is trivially cheap.
 */
export async function pingLivenessForTimeSync(): Promise<{ timestamp: string | null }> {
  const { data, headers } = await apiClient.get<{ status: string; timestamp?: string; uptime?: number }>('/api/health/live');
  const headerDate = headers?.date ? new Date(headers.date).toISOString() : null;
  return { timestamp: data?.timestamp ?? headerDate };
}

export async function getMeshHealth(signal?: AbortSignal): Promise<MeshHealth> {
  return cachedGet<MeshHealth>('/api/health/mesh', { signal, bypassCache: true });
}

export async function electMeshLeader(signal?: AbortSignal): Promise<{ leader_id: string; mesh: MeshHealth }> {
  return cachedPost<{ leader_id: string; mesh: MeshHealth }>('/api/mesh/elect-leader', undefined, { signal });
}

export async function forceMeshReconcile(signal?: AbortSignal): Promise<Record<string, unknown>> {
  return cachedPost<Record<string, unknown>>('/api/bloom/reconcile', undefined, { signal });
}
