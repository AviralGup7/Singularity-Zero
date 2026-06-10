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

export interface CircuitBreakerState {
  state: string;
  failure_count: number;
  success_count: number;
  last_failure_time: string | null;
  forced_open: boolean;
  recovery_timeout: number;
}

export interface CircuitBreakerSnapshot {
  tools: Record<string, CircuitBreakerState>;
  count: number;
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

export async function getCircuitBreakers(signal?: AbortSignal): Promise<CircuitBreakerSnapshot> {
  const { data } = await apiClient.get<CircuitBreakerSnapshot>('/api/health/self-healing/circuit-breakers', { signal });
  return data;
}

export async function forceOpenCircuitBreaker(
  toolName: string,
  reason = 'dashboard-operator',
  durationSeconds?: number,
  signal?: AbortSignal,
): Promise<{ tool: string; state: string; reason: string }> {
  const { data } = await apiClient.post<{ tool: string; state: string; reason: string }>(
    `/api/health/self-healing/circuit-breakers/${encodeURIComponent(toolName)}/force-open`,
    { reason, duration_seconds: durationSeconds },
    { signal },
  );
  return data;
}

export async function resetCircuitBreaker(
  toolName: string,
  signal?: AbortSignal,
): Promise<{ tool: string; state: string }> {
  const { data } = await apiClient.post<{ tool: string; state: string }>(
    `/api/health/self-healing/circuit-breakers/${encodeURIComponent(toolName)}/reset`,
    undefined,
    { signal },
  );
  return data;
}
