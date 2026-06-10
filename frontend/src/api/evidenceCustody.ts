import { apiClient } from './core';

export interface CustodyEntry {
  id: string;
  evidence_id: string;
  action: 'created' | 'accessed' | 'modified' | 'exported' | 'deleted';
  user: string;
  timestamp: string;
  hash_before?: string | null;
  hash_after?: string | null;
  details: string;
}

export interface EvidenceRecord {
  id: string;
  finding_id: string;
  data: string;
  hash: string;
  created_at: string;
  created_by: string;
  custody_chain: CustodyEntry[];
}

export async function listEvidence(options?: {
  limit?: number;
  offset?: number;
  finding_id?: string;
  signal?: AbortSignal;
}): Promise<EvidenceRecord[]> {
  const params: Record<string, unknown> = {};
  if (options?.limit) params.limit = options.limit;
  if (options?.offset) params.offset = options.offset;
  if (options?.finding_id) params.finding_id = options.finding_id;
  const { data } = await apiClient.get<EvidenceRecord[]>('/api/evidence-custody', {
    params,
    signal: options?.signal,
  });
  return data;
}

export async function getEvidence(evidenceId: string, signal?: AbortSignal): Promise<EvidenceRecord> {
  const { data } = await apiClient.get<EvidenceRecord>(`/api/evidence-custody/${evidenceId}`, { signal });
  return data;
}

export async function createEvidence(payload: {
  finding_id: string;
  data: string;
  user?: string;
  signal?: AbortSignal;
}): Promise<EvidenceRecord> {
  const { signal, ...body } = payload;
  const { data } = await apiClient.post<EvidenceRecord>('/api/evidence-custody', body, { signal });
  return data;
}

export async function logEvidenceAccess(
  evidenceId: string,
  payload?: { user?: string; details?: string; signal?: AbortSignal },
): Promise<EvidenceRecord> {
  const { signal, ...body } = payload || {};
  const { data } = await apiClient.post<EvidenceRecord>(
    `/api/evidence-custody/${evidenceId}/access`,
    body || {},
    { signal },
  );
  return data;
}

export async function modifyEvidence(
  evidenceId: string,
  payload: {
    new_data: string;
    user?: string;
    details?: string;
    signal?: AbortSignal;
  },
): Promise<EvidenceRecord> {
  const { signal, ...body } = payload;
  const { data } = await apiClient.post<EvidenceRecord>(
    `/api/evidence-custody/${evidenceId}/modify`,
    body,
    { signal },
  );
  return data;
}

export async function verifyEvidence(
  evidenceId: string,
  signal?: AbortSignal,
): Promise<{ valid: boolean; message: string; stored_hash: string; computed_hash: string }> {
  const { data } = await apiClient.get(`/api/evidence-custody/${evidenceId}/verify`, { signal });
  return data;
}

export async function deleteEvidence(evidenceId: string, signal?: AbortSignal): Promise<{ status: string }> {
  const { data } = await apiClient.delete(`/api/evidence-custody/${evidenceId}`, { signal });
  return data;
}
