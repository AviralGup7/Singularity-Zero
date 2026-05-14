import type { RiskScore, HistoricalScoreResponse, TimelineResponse } from '@/types/extended';
import { cachedGet } from './core';

export async function getTargetRiskScore(targetName: string, signal?: AbortSignal): Promise<RiskScore> {
  return cachedGet<RiskScore>(`/api/targets/${targetName}/risk-score`, { signal, bypassCache: true });
}

export async function getTargetHistoricalScores(targetName: string, signal?: AbortSignal): Promise<HistoricalScoreResponse> {
  return cachedGet<HistoricalScoreResponse>(`/api/targets/${targetName}/historical-scores`, { signal });
}

export async function getTargetTimeline(targetName: string, signal?: AbortSignal): Promise<TimelineResponse> {
  return cachedGet<TimelineResponse>(`/api/targets/${targetName}/timeline`, { signal });
}

export async function getJobTimeline(jobId: string, signal?: AbortSignal): Promise<TimelineResponse> {
  return cachedGet<TimelineResponse>(`/api/jobs/${jobId}/timeline`, { signal });
}
