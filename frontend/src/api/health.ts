import type { ReadinessResponse } from '@/types/extended';
import type { MeshHealth } from '@/types/api';
import { cachedGet, cachedPost } from './core';

export async function getReadiness(signal?: AbortSignal): Promise<ReadinessResponse> {
  return cachedGet<ReadinessResponse>('/api/health/ready', { signal, bypassCache: true });
}

export async function getLiveness(signal?: AbortSignal): Promise<{ status: string; timestamp: string }> {
  return cachedGet<{ status: string; timestamp: string }>('/api/health/live', { signal, bypassCache: true });
}

export async function getMeshHealth(signal?: AbortSignal): Promise<MeshHealth> {
  return cachedGet<MeshHealth>('/api/health/mesh', { signal, bypassCache: true });
}

export async function electMeshLeader(signal?: AbortSignal): Promise<{ leader_id: string; mesh: MeshHealth }> {
  return cachedPost<{ leader_id: string; mesh: MeshHealth }>('/api/mesh/elect-leader', undefined, { signal });
}
