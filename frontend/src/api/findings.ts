import type { FindingsSummary, Finding, RemediationResponse } from '@/types/api';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';

export async function getFindingsSummary(signal?: AbortSignal, ttl?: number): Promise<FindingsSummary> {
  return cachedGet<FindingsSummary>('/api/findings', { signal, ttl });
}

import { z } from 'zod';
import { FindingsListSchema } from './schemas';

export async function getFindings(signal?: AbortSignal): Promise<Finding[]> {
  const res = await cachedGet<{ findings: Finding[]; total: number }>(
    '/api/targets/findings/list',
    { 
      signal, 
      params: { page: 1, page_size: 500 },
      schema: z.object({ findings: FindingsListSchema })
    }
  );
  return res.findings ?? [];
}

export async function getFindingRemediation(
  findingId: string,
  signal?: AbortSignal
): Promise<RemediationResponse> {
  return cachedGet<RemediationResponse>(`/api/findings/${findingId}/remediation`, {
    signal,
    ttl: 5000,
  });
}

export async function deleteFinding(id: string, signal?: AbortSignal): Promise<void> {
  await apiClient.delete(`/api/findings/${id}`, { signal });
  apiCache.invalidatePrefix('/api/findings');
  apiCache.invalidatePrefix('/api/targets/findings');
}

export async function updateFinding(id: string, data: Partial<Finding>, signal?: AbortSignal): Promise<Finding> {
  const { data: result } = await apiClient.put<Finding>(`/api/findings/${id}`, data, { signal });
  apiCache.invalidatePrefix('/api/findings');
  apiCache.invalidatePrefix('/api/targets/findings');
  return result;
}

   
export async function bulkUpdateFindings(ids: string[], data: Partial<Finding>, signal?: AbortSignal): Promise<Finding[]> {
  const { data: result } = await apiClient.put<Finding[]>('/api/findings/bulk', { ids, ...data }, { signal });
  apiCache.invalidatePrefix('/api/findings');
  apiCache.invalidatePrefix('/api/targets/findings');
  return result;
}
