import { apiClient } from './core';

export interface SelfHealingSnapshot {
  status: string;
  metrics: Record<string, unknown>[];
  findings: Record<string, unknown>[];
  corrections: Record<string, unknown>[];
  controller: string;
}

export interface SelfHealingTile {
  label: string;
  status: string;
  active_findings: number;
  metric_count?: number;
  last_action?: {
    action: string;
    success: boolean;
    message: string;
    executed_at: string;
  } | null;
}

export async function getSelfHealingSnapshot(signal?: AbortSignal): Promise<SelfHealingSnapshot> {
  const { data } = await apiClient.get<SelfHealingSnapshot>('/api/health/self-healing', { signal });
  return data;
}

export async function evaluateSelfHealing(signal?: AbortSignal): Promise<SelfHealingSnapshot> {
  const { data } = await apiClient.post<SelfHealingSnapshot>('/api/health/self-healing/evaluate', undefined, { signal });
  return data;
}

export async function getSelfHealingTile(signal?: AbortSignal): Promise<SelfHealingTile> {
  const { data } = await apiClient.get<SelfHealingTile>('/api/health/self-healing/tile', { signal });
  return data;
}
