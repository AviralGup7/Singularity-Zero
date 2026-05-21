import { apiClient } from './core';

export interface TriageAuditEvent {
  event_id: string;
  run_id: string;
  finding_id: string;
  action: string;
  analyst_id: string;
  analyst_name: string;
  payload: Record<string, unknown>;
  timestamp: string;
  previous_hash: string;
  hash: string;
}

export interface TriageComment {
  id: string;
  finding_id: string;
  author: string;
  text: string;
  mentions: string[];
  timestamp: string;
  updated_at?: string;
}

export interface TriageChainStatus {
  valid: boolean;
  entries: number;
  latest_hash: string;
  failed_at?: number;
}

export interface TriageFindingState {
  run_id: string;
  finding_id: string;
  status: string;
  comments: TriageComment[];
  annotations: TriageAuditEvent[];
  audit: TriageAuditEvent[];
  chain: TriageChainStatus;
}

export interface AnalystPresence {
  analyst_id: string;
  analyst_name: string;
  connection_id: string;
  finding_id?: string | null;
  cursor?: Record<string, unknown>;
  joined_at: number;
  last_seen: number;
}

export async function getTriageState(
  runId: string,
  findingId: string,
  signal?: AbortSignal,
): Promise<TriageFindingState> {
  const { data } = await apiClient.get<TriageFindingState>(
    `/api/triage/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}`,
    { signal },
  );
  return data;
}

export async function recordTriageAction(
  runId: string,
  findingId: string,
  action: string,
  payload: Record<string, unknown>,
  analyst: { analyst_id: string; analyst_name: string },
  signal?: AbortSignal,
): Promise<{ event: TriageAuditEvent; state: TriageFindingState }> {
  const { data } = await apiClient.post<{ event: TriageAuditEvent; state: TriageFindingState }>(
    `/api/triage/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/actions`,
    { action, payload, ...analyst },
    { signal },
  );
  return data;
}

export async function getTriageAudit(
  runId: string,
  findingId?: string,
  signal?: AbortSignal,
): Promise<{ events: TriageAuditEvent[]; chain: TriageChainStatus }> {
  const { data } = await apiClient.get<{ events: TriageAuditEvent[]; chain: TriageChainStatus }>(
    `/api/triage/runs/${encodeURIComponent(runId)}/audit`,
    { params: { finding_id: findingId }, signal },
  );
  return data;
}

export function triageWebSocketUrl(runId: string, analyst: { analyst_id: string; analyst_name: string }): string {
  const base = import.meta.env.VITE_API_BASE || window.location.origin;
  const url = new URL(`/ws/triage/${encodeURIComponent(runId)}`, base);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.searchParams.set('analyst_id', analyst.analyst_id);
  url.searchParams.set('analyst_name', analyst.analyst_name);
  return url.toString();
}

