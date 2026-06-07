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
  parent_id?: string | null;
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
  assigned_to?: string | null;
  assigned_to_name?: string | null;
  locked_by?: string | null;
  locked_by_name?: string | null;
  locked_at?: number | null;
  lock_expires_at?: number | null;
}

export interface TriageLockConflict {
  reason: 'locked_by_other' | 'assigned_to_other' | 'not_authorized';
  message: string;
  locked_by?: string;
  locked_by_name?: string;
  assigned_to?: string;
  assigned_to_name?: string;
  lock_expires_at?: number;
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

export async function assignFinding(
  runId: string,
  findingId: string,
  analystId: string,
  analystName: string,
  actor: { analyst_id: string; analyst_name: string },
  signal?: AbortSignal,
): Promise<{ state: TriageFindingState; conflict?: TriageLockConflict }> {
  try {
    const { data } = await apiClient.post<{ state: TriageFindingState }>(
      `/api/triage/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/assign`,
      { analyst_id: analystId, analyst_name: analystName, actor_id: actor.analyst_id, actor_name: actor.analyst_name },
      { signal },
    );
    return data;
  } catch (err: unknown) {
    const conflict = extractConflictFromError(err);
    if (conflict) {
      return { state: undefined as unknown as TriageFindingState, conflict };
    }
    throw err;
  }
}

export async function lockFinding(
  runId: string,
  findingId: string,
  actor: { analyst_id: string; analyst_name: string },
  signal?: AbortSignal,
): Promise<{ state: TriageFindingState; conflict?: TriageLockConflict }> {
  try {
    const { data } = await apiClient.post<{ state: TriageFindingState }>(
      `/api/triage/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/lock`,
      { ...actor },
      { signal },
    );
    return data;
  } catch (err: unknown) {
    const conflict = extractConflictFromError(err);
    if (conflict) {
      return { state: undefined as unknown as TriageFindingState, conflict };
    }
    throw err;
  }
}

export async function unlockFinding(
  runId: string,
  findingId: string,
  actor: { analyst_id: string; analyst_name: string },
  signal?: AbortSignal,
): Promise<{ state: TriageFindingState }> {
  const { data } = await apiClient.post<{ state: TriageFindingState }>(
    `/api/triage/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/unlock`,
    { ...actor },
    { signal },
  );
  return data;
}

function extractConflictFromError(err: unknown): TriageLockConflict | null {
  if (typeof err !== 'object' || err === null) return null;
  const anyErr = err as { response?: { status?: number; data?: { conflict?: TriageLockConflict } } };
  if (anyErr.response?.status === 409 && anyErr.response.data?.conflict) {
    return anyErr.response.data.conflict;
  }
  return null;
}

export interface TeamMember {
  analyst_id: string;
  analyst_name: string;
  email?: string;
  role?: 'analyst' | 'reviewer' | 'lead';
}

export async function listTeamMembers(signal?: AbortSignal): Promise<TeamMember[]> {
  const { data } = await apiClient.get<{ members: TeamMember[] }>(
    '/api/triage/team',
    { signal },
  );
  return data.members || [];
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
