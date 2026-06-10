import type { FindingsSummary, Finding, RemediationResponse } from '@/types/api';
import type { FindingTimelineEvent } from '@/types/extended';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';

export async function getFindingsSummary(signal?: AbortSignal, ttl?: number): Promise<FindingsSummary> {
  return cachedGet<FindingsSummary>('/api/findings', { signal, ttl });
}

import { z } from 'zod';
import { FindingsListSchema } from './schemas';

export interface FindingsListParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_dir?: 'asc' | 'desc';
  severity?: string;
  search?: string;
}

export async function getFindings(params?: FindingsListParams, signal?: AbortSignal): Promise<Finding[]> {
  const res = await cachedGet<{ findings: Finding[]; total: number }>(
    '/api/targets/findings/list',
    { 
      signal, 
      params: { page: 1, page_size: 500, ...params },
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

export async function getFindingById(findingId: string, signal?: AbortSignal): Promise<Finding> {
  const { data } = await apiClient.get<Finding>(`/api/findings/${findingId}`, { signal });
  return data;
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

export interface FindingsTimelineParams {
  job_id?: string;
  severity?: string;
  target?: string;
  start_date?: string;
  end_date?: string;
  limit?: number;
  offset?: number;
}

export async function getFindingsTimeline(
  params?: FindingsTimelineParams,
  signal?: AbortSignal,
): Promise<{ events: FindingTimelineEvent[]; total: number }> {
  return cachedGet<{ events: FindingTimelineEvent[]; total: number }>(
    '/api/findings/timeline',
    { signal, params, bypassCache: true },
  );
}

export interface FindingExplainResponse {
  finding_id: string;
  feature_importance: Array<{
    feature: string;
    importance: number;
    direction: string;
  }>;
  shap_values?: Record<string, number>;
  model_version?: string;
}

export async function getFindingExplain(
  findingId: string,
  signal?: AbortSignal,
): Promise<FindingExplainResponse> {
  return cachedGet<FindingExplainResponse>(`/api/findings/${findingId}/explain`, {
    signal,
    bypassCache: true,
  });
}

export interface FindingAiExplainResponse {
  finding_id: string;
  persona: string;
  explanation: string;
  recommendations?: string[];
}

export async function getFindingAiExplain(
  findingId: string,
  persona?: string,
  signal?: AbortSignal,
): Promise<FindingAiExplainResponse> {
  return cachedGet<FindingAiExplainResponse>(`/api/findings/${findingId}/ai-explain`, {
    signal,
    params: persona ? { persona } : undefined,
    bypassCache: true,
  });
}
