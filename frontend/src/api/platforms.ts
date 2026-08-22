import { apiClient } from './core';

export type Platform = 'hackerone' | 'bugcrowd' | 'intigriti' | 'synack';

export interface PlatformClientSummary {
  platform: Platform;
  ready: boolean;
  configured: boolean;
  last_error?: string | null;
}

export interface PlatformListResponse {
  clients: PlatformClientSummary[];
}

export interface SubmissionResult {
  platform: Platform;
  submitted: boolean;
  report_id?: string;
  url?: string;
  error?: string;
  status_code?: number;
  raw?: Record<string, unknown>;
}

export async function listPlatformClients(signal?: AbortSignal): Promise<PlatformClientSummary[]> {
  const { data } = await apiClient.get<PlatformListResponse>(
    '/api/reports/platforms',
    { signal },
  );
  return asPlatformClients(data.clients);
}

export function asPlatformClients(value: unknown): PlatformClientSummary[] {
  return Array.isArray(value) ? value as PlatformClientSummary[] : [];
}

export async function pushFindingToPlatform(
  runId: string,
  findingId: string,
  platform: Platform,
  options: { draft?: boolean; additionalNotes?: string } = {},
  signal?: AbortSignal,
): Promise<SubmissionResult> {
  if (!String(runId ?? '').trim() || !String(findingId ?? '').trim()) {
    return { platform, submitted: false, error: 'Run and finding ids are required' };
  }
  const { data } = await apiClient.post<SubmissionResult>(
    `/api/reports/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/submit`,
    { platform, draft: options.draft ?? true, additional_notes: options.additionalNotes ?? '' },
    { signal },
  );
  return data;
}
