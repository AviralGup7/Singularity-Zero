import { cachedGet } from './core';
import type { RiskHistoryEntry, RiskFactorsResponse } from '@/types/extended';

export async function getRiskHistory(
  params?: { target_id?: string; days?: number; group_by?: string },
  signal?: AbortSignal,
): Promise<{ history: RiskHistoryEntry[]; total: number }> {
  return cachedGet<{ history: RiskHistoryEntry[]; total: number }>(
    '/api/risk/history',
    { signal, params, bypassCache: true },
  );
}

export async function getRiskFactors(signal?: AbortSignal): Promise<RiskFactorsResponse> {
  return cachedGet<RiskFactorsResponse>('/api/risk/factors', { signal });
}
