import { apiClient } from './core';

export interface ThresholdHistoryEntry {
  history_id: string;
  run_id: string;
  category: string | null;
  low_threshold: number;
  medium_threshold: number;
  high_threshold: number;
  observed_fp_rate: number;
  target_fp_rate: number;
  error: number;
  adjustment: number;
  is_converged: boolean;
  recorded_at: string;
}

export interface FPPattern {
  pattern_id: string;
  category: string;
  status_code_pattern: string | null;
  body_pattern: string | null;
  header_pattern: string | null;
  fp_probability: number;
  confidence: number;
  is_active: boolean;
  occurrence_count: number;
  confirmed_fp_count: number;
  confirmed_tp_count: number;
  last_seen: string;
}

export interface LearningKPIs {
  total_feedback_events: number;
  average_precision: number;
  average_recall: number;
  active_fp_patterns: number;
  thresholds_converged: boolean;
  learning_efficiency_index: number;
}

export interface FeedbackEventEntry {
  feedback_id: string;
  run_id: string;
  category: string;
  signal_id: string | null;
  status_code: number | null;
  body_indicator: string | null;
  true_positive_probability: number | null;
  false_positive_probability: number | null;
  is_true_positive: boolean | null;
  source: string;
  recorded_at: string;
}

export async function getFeedbackEvents(limit = 100, runId?: string, signal?: AbortSignal): Promise<FeedbackEventEntry[]> {
  const { data } = await apiClient.get<FeedbackEventEntry[]>('/api/learning/feedback', {
    params: { limit, run_id: runId },
    signal,
  });
  return data;
}

export async function getThresholdHistory(signal?: AbortSignal): Promise<ThresholdHistoryEntry[]> {
  const { data } = await apiClient.get<ThresholdHistoryEntry[]>('/api/learning/thresholds', { signal });
  return data;
}

export async function getFPPatterns(activeOnly = true, signal?: AbortSignal): Promise<FPPattern[]> {
  const { data } = await apiClient.get<FPPattern[]>('/api/learning/fp-patterns', {
    params: { active_only: activeOnly },
    signal,
  });
  return data;
}

export async function getLearningKPIs(target?: string, signal?: AbortSignal): Promise<LearningKPIs> {
  const { data } = await apiClient.get<LearningKPIs>('/api/learning/kpis', {
    params: { target },
    signal,
  });
  return data;
}

export async function getLearningDbStats(signal?: AbortSignal): Promise<Record<string, number>> {
  const { data } = await apiClient.get<Record<string, number>>('/api/learning/db-stats', { signal });
  return data;
}
