import { apiClient } from './core';

export interface EvasionMetrics {
  total_requests: number;
  successes: number;
  evasion_success_rate: number;
  [key: string]: unknown;
}

export interface EvasionMetricsResponse {
  metrics: Record<string, EvasionMetrics>;
  hunt_mode?: boolean;
  hunt_budget?: {
    max_duration_seconds?: number | null;
    elapsed_seconds?: number;
    remaining_seconds?: number;
    stop_when_total_findings?: number;
    stop_when_high_confidence_count?: number;
    findings_count?: number;
    high_confidence_count?: number;
    high_confidence_threshold?: number;
    high_value_target_time_budget_pct?: number;
    max_concurrent_probes?: number;
    exhausted?: boolean;
    label?: string;
  } | null;
  hunt_mode_details?: {
    enabled: boolean;
    skip_subdomain_enumeration: boolean;
    skip_passive_checks: boolean;
    high_value_categories: string[];
    low_hanging_fruit_path_keywords: string[];
    low_hanging_fruit_min_severity: string;
    low_hanging_fruit_min_confidence: number;
    low_hanging_fruit_max_findings: number;
    deduplicate_against_history: boolean;
  } | null;
  low_hanging_fruit?: LowHangingFruitSummary;
  high_value_categories?: string[];
  history_path?: string | null;
}

export interface LowHangingFruitSummary {
  total: number;
  findings: LowHangingFruitFinding[];
  criteria?: {
    min_severity?: string;
    min_confidence?: number;
    max_findings?: number;
    path_keywords?: string[];
  };
}

export interface LowHangingFruitFinding {
  id: string;
  title: string;
  category: string;
  severity: string;
  confidence: number;
  url: string;
  bounty_source?: string;
  is_high_value?: boolean;
}

export async function getEvasionMetrics(signal?: AbortSignal): Promise<EvasionMetricsResponse> {
  const { data } = await apiClient.get<EvasionMetricsResponse>('/api/evasion/metrics', { signal });
  return data;
}

export async function resetEvasionMetrics(signal?: AbortSignal): Promise<{ status: string; message: string }> {
  const { data } = await apiClient.post<{ status: string; message: string }>('/api/evasion/reset', undefined, { signal });
  return data;
}

export async function setHuntMode(
  payload: { enabled: boolean; reason?: string; actor?: string },
  signal?: AbortSignal,
): Promise<{ enabled: boolean; reason?: string; hunt_mode: EvasionMetricsResponse }> {
  const { data } = await apiClient.post<{ enabled: boolean; reason?: string; hunt_mode: EvasionMetricsResponse }>(
    '/api/evasion/hunt-mode',
    payload,
    { signal },
  );
  return data;
}
