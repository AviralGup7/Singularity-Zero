import { apiClient } from './core';

export interface BackendAuditEntry {
  id: number;
  timestamp: string;
  event: string;
  severity: string;
  user_id: string | null;
  source_ip: string | null;
  resource_id: string | null;
  details: Record<string, unknown>;
  entry_hash: string;
}

export async function getBackendAuditEntries(params: {
  limit?: number;
  offset?: number;
  event?: string;
  user_id?: string;
  severity?: string;
  signal?: AbortSignal;
} = {}): Promise<BackendAuditEntry[]> {
  const { data } = await apiClient.get<BackendAuditEntry[]>('/api/audit/entries', {
    params,
    signal: params.signal,
  });
  return data;
}

export async function verifyAuditIntegrity(signal?: AbortSignal): Promise<{
  is_valid: bool;
  compromised_ids: number[];
  entry_count: number;
}> {
  const { data } = await apiClient.get('/api/audit/verify', { signal });
  return data;
}
