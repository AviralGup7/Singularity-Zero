import { cachedGet } from './core';
import type { RiskHistoryEntry, RiskFactorsResponse } from '@/types/extended';

export function asRiskHistory(value: unknown): RiskHistoryEntry[] {
  return Array.isArray(value) ? value as RiskHistoryEntry[] : [];
}

export async function getRiskHistory(
  params?: { target_id?: string; days?: number; group_by?: string },
  signal?: AbortSignal,
): Promise<{ history: RiskHistoryEntry[]; total: number }> {
  const res = await cachedGet<{ history: RiskHistoryEntry[]; total: number }>(
    '/api/risk/history',
    { signal, params, bypassCache: true },
  );
  const history = asRiskHistory(res.history);
  return { ...res, history, total: Number.isFinite(res.total) ? res.total : history.length };
}

export async function getRiskFactors(signal?: AbortSignal): Promise<RiskFactorsResponse> {
  return cachedGet<RiskFactorsResponse>('/api/risk/factors', { signal });
}
