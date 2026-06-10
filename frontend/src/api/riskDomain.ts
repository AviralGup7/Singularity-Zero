import { apiClient, cachedGet } from './core';

export interface RiskAcceptance {
  acceptance_id: string;
  finding_id: string;
  asset_id?: string | null;
  accepted_until?: string | null;
  accepted_by: string;
  justification: string;
  scope: string;
  state: string;
  created_at?: string;
}

export async function listAcceptances(options?: {
  limit?: number;
  signal?: AbortSignal;
}): Promise<RiskAcceptance[]> {
  const { data } = await apiClient.get<RiskAcceptance[]>('/api/risk-domain/acceptances', {
    params: { limit: options?.limit ?? 200 },
    signal: options?.signal,
  });
  return data;
}

export async function createAcceptance(payload: {
  finding_id: string;
  accepted_by: string;
  justification: string;
  accepted_until?: string | null;
  scope?: string;
  signal?: AbortSignal;
}): Promise<RiskAcceptance> {
  const { signal, ...body } = payload;
  const { data } = await apiClient.post<RiskAcceptance>('/api/risk-domain/acceptances', body, { signal });
  return data;
}

export async function revokeAcceptance(
  acceptanceId: string,
  signal?: AbortSignal,
): Promise<{ status: string }> {
  const { data } = await apiClient.post(
    `/api/risk-domain/acceptances/${encodeURIComponent(acceptanceId)}/revoke`,
    undefined,
    { signal },
  );
  return data;
}

export interface AssetRecord {
  asset_id: string;
  name: string;
  host_pattern: string;
  path_prefix?: string | null;
  asset_type: string;
  entity_type: string;
  criticality: number;
  tier: string;
  business_value: number;
  compliance_requirements?: string | null;
  owner?: string | null;
  is_active: number;
}

export async function listAssets(options?: {
  limit?: number;
  signal?: AbortSignal;
}): Promise<AssetRecord[]> {
  const { data } = await apiClient.get<AssetRecord[]>('/api/risk-domain/assets', {
    params: { limit: options?.limit ?? 200 },
    signal: options?.signal,
  });
  return data;
}

export async function createAsset(payload: {
  name: string;
  host_pattern: string;
  asset_type: string;
  entity_type: string;
  criticality: number;
  tier: string;
  business_value: number;
  owner?: string;
  signal?: AbortSignal;
}): Promise<AssetRecord> {
  const { signal, ...body } = payload;
  const { data } = await apiClient.post<AssetRecord>('/api/risk-domain/assets', body, { signal });
  return data;
}

export async function deleteAsset(
  assetId: string,
  signal?: AbortSignal,
): Promise<{ status: string }> {
  const { data } = await apiClient.delete(
    `/api/risk-domain/assets/${encodeURIComponent(assetId)}`,
    { signal },
  );
  return data;
}

export interface CompensatingControl {
  control_id: string;
  finding_id: string;
  asset_id?: string | null;
  control_type: string;
  description: string;
  evidence_url?: string | null;
  approved_by?: string | null;
  state: string;
  created_at?: string;
  expires_at?: string | null;
}

export async function listControls(options?: {
  limit?: number;
  signal?: AbortSignal;
}): Promise<CompensatingControl[]> {
  const { data } = await apiClient.get<CompensatingControl[]>('/api/risk-domain/controls', {
    params: { limit: options?.limit ?? 200 },
    signal: options?.signal,
  });
  return data;
}

export async function createControl(payload: {
  finding_id: string;
  control_type: string;
  description: string;
  asset_id?: string;
  evidence_url?: string;
  expires_at?: string;
  signal?: AbortSignal;
}): Promise<CompensatingControl> {
  const { signal, ...body } = payload;
  const { data } = await apiClient.post<CompensatingControl>('/api/risk-domain/controls', body, { signal });
  return data;
}

export interface SlaSummaryEntry {
  finding_id: string;
  severity: string;
  created_at: string;
  deadline: string;
  status: 'on_track' | 'breached' | 'resolved';
  days_remaining: number;
}

export async function getSlaSummary(
  days?: number,
  signal?: AbortSignal,
): Promise<{ summary: SlaSummaryEntry[]; total: number; breached: number }> {
  return cachedGet<{ summary: SlaSummaryEntry[]; total: number; breached: number }>(
    '/api/risk-domain/sla/summary',
    { signal, params: days ? { days } : undefined, bypassCache: true },
  );
}

export interface FindingReview {
  finding_id: string;
  reviewer: string;
  decision: string;
  justification?: string;
  created_at: string;
}

export async function submitFindingReview(
  findingId: string,
  payload: {
    reviewer: string;
    decision: string;
    justification?: string;
    signal?: AbortSignal;
  },
): Promise<FindingReview> {
  const { signal, ...body } = payload;
  const { data } = await apiClient.post<FindingReview>(
    `/api/risk-domain/findings/${encodeURIComponent(findingId)}/review`,
    body,
    { signal },
  );
  return data;
}

export async function getFindingReviewHistory(
  findingId: string,
  signal?: AbortSignal,
): Promise<{ reviews: FindingReview[] }> {
  const { data } = await apiClient.get<{ reviews: FindingReview[] }>(
    `/api/risk-domain/findings/${encodeURIComponent(findingId)}/review-history`,
    { signal },
  );
  return data;
}

export interface FindingLifecycleEntry {
  finding_id: string;
  state: string;
  transition: string;
  actor?: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export async function getFindingLifecycle(
  findingId: string,
  signal?: AbortSignal,
): Promise<{ lifecycle: FindingLifecycleEntry[] }> {
  const { data } = await apiClient.get<{ lifecycle: FindingLifecycleEntry[] }>(
    `/api/risk-domain/findings/${encodeURIComponent(findingId)}/lifecycle`,
    { signal },
  );
  return data;
}

export async function transitionFinding(
  findingId: string,
  payload: {
    transition: string;
    actor?: string;
    reason?: string;
    signal?: AbortSignal;
  },
): Promise<FindingLifecycleEntry> {
  const { signal, ...body } = payload;
  const { data } = await apiClient.post<FindingLifecycleEntry>(
    `/api/risk-domain/findings/${encodeURIComponent(findingId)}/transition`,
    body,
    { signal },
  );
  return data;
}
