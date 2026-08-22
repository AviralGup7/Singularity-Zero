import type { FindingsSummary, Finding, RemediationResponse } from '@/types/api';
import type { FindingTimelineEvent } from '@/types/extended';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';
import { FindingSchema } from './schemas';
import {
  collectAllPages,
  mapFindingUpdate,
  normalizeFindingRecord,
  readPageEnvelope,
  toFindingListParams,
  type FindingListQuery,
  type PageEnvelope,
} from './contract';

function toFinding(value: unknown): Finding | null {
  const rec = normalizeFindingRecord(value);
  if (!rec) return null;
  if (import.meta.env?.DEV) {
    const parsed = FindingSchema.safeParse(rec);
    if (!parsed.success) {
      console.debug('Finding payload drifted from FindingSchema', parsed.error.issues.slice(0, 3));
    }
  }
  return rec as unknown as Finding;
}

export function asFindingList(value: unknown): Finding[] {
  if (Array.isArray(value)) {
    return value.map(toFinding).filter((item): item is Finding => Boolean(item?.id));
  }
  return readPageEnvelope(value, 'findings', toFinding).items;
}

export function asTimelineEvents(value: unknown): FindingTimelineEvent[] {
  return Array.isArray(value) ? value as FindingTimelineEvent[] : [];
}

export async function getFindingsSummary(signal?: AbortSignal, ttl?: number): Promise<FindingsSummary> {
  return cachedGet<FindingsSummary>('/api/findings', { signal, ttl });
}

export interface FindingsListParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_dir?: 'asc' | 'desc';
  severity?: string;
  search?: string;
}

export async function getFindingsPage(
  params?: FindingListQuery,
  signal?: AbortSignal,
): Promise<PageEnvelope<Finding>> {
  const res = await cachedGet<unknown>('/api/targets/findings/list', {
    signal,
    params: toFindingListParams(params),
    ttl: 4000,
  });
  return readPageEnvelope(res, 'findings', toFinding);
}

export async function getFindings(params?: FindingsListParams, signal?: AbortSignal): Promise<Finding[]> {
  return collectAllPages(
    getFindingsPage,
    {
      page_size: Math.min(200, params?.page_size ?? 200),
      severity: params?.severity,
      search: params?.search,
    },
    signal,
  );
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
  const id = String(findingId ?? '').trim();
  if (!id) {
    throw new Error('Finding id is required');
  }
  const { data } = await apiClient.get<unknown>(`/api/findings/${encodeURIComponent(id)}`, { signal });
  const normalized = normalizeFindingRecord(data);
  if (!normalized) throw new Error('Finding payload was empty');
  return normalized as unknown as Finding;
}

export async function deleteFinding(id: string, signal?: AbortSignal): Promise<void> {
  await apiClient.delete(`/api/findings/${id}`, { signal });
  apiCache.invalidatePrefix('/api/findings');
  apiCache.invalidatePrefix('/api/targets/findings');
}

export async function updateFinding(id: string, data: Partial<Finding>, signal?: AbortSignal): Promise<Finding> {
  const body = mapFindingUpdate(data as Record<string, unknown>);
  const { data: result } = await apiClient.put<unknown>(`/api/findings/${id}`, body, { signal });
  apiCache.invalidatePrefix('/api/findings');
  apiCache.invalidatePrefix('/api/targets/findings');
  return toFinding(result) ?? ({ id, ...data } as Finding);
}

export async function bulkUpdateFindings(ids: string[], data: Partial<Finding>, signal?: AbortSignal): Promise<Finding[]> {
  const body = { ids, ...mapFindingUpdate(data as Record<string, unknown>) };
  const { data: result } = await apiClient.put<unknown>('/api/findings/bulk', body, { signal });
  apiCache.invalidatePrefix('/api/findings');
  apiCache.invalidatePrefix('/api/targets/findings');
  return asFindingList(result);
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
  const res = await cachedGet<{ events: FindingTimelineEvent[]; total: number }>(
    '/api/findings/timeline',
    { signal, params: params as Record<string, unknown>, ttl: 5000 },
  );
  return {
    events: asTimelineEvents(res.events),
    total: Number.isFinite(Number(res.total)) ? Number(res.total) : asTimelineEvents(res.events).length,
  };
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
