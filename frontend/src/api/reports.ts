import type { DetectionGapResponse, HealthStatus } from '@/types/api';
import { apiClient, cachedGet } from './core';
import { getStreamToken } from './streamAuth';

export interface ReportLibraryItem {
  target: string;
  run_id: string;
  generated_at: string;
  finding_count: number;
  standards: string[];
  manifest_sha256: string;
  signature_valid: boolean;
  signature_errors: string[];
  version: string;
  previous_manifest_sha256: string;
  links: {
    html: string;
    json: string;
    sbom: string;
    attestation_html: string;
    attestation_pdf: string;
    manifest: string;
    signature: string;
  };
}

export interface ReportLibraryResponse {
  reports: ReportLibraryItem[];
  total: number;
}

export async function getHealth(signal?: AbortSignal, ttl?: number): Promise<HealthStatus> {
  return cachedGet<HealthStatus>('/api/health', { signal, ttl });
}

export async function getGapAnalysis(target?: string | null | AbortSignal, signal?: AbortSignal): Promise<DetectionGapResponse> {
  let targetStr: string | undefined = undefined;
  let abortSignal: AbortSignal | undefined = signal;
  
  if (typeof target === 'string') {
    targetStr = target;
  } else if (target instanceof AbortSignal) {
    abortSignal = target;
  } else if (target && typeof target === 'object' && 'aborted' in target) {
    abortSignal = target;
  }
  
  const params = targetStr ? { target: targetStr } : undefined;
  return cachedGet<DetectionGapResponse>('/api/gap-analysis', { signal: abortSignal, params });
}

export async function refreshGapAnalysis(signal?: AbortSignal): Promise<{ status: string }> {
  const { data } = await apiClient.post('/api/gap-analysis/refresh', {}, { signal });
  return data;
}

export async function getReportLibrary(signal?: AbortSignal): Promise<ReportLibraryResponse> {
  return cachedGet<ReportLibraryResponse>('/api/reports/library', { signal, bypassCache: true });
}

export function getCompliancePdfUrl(target: string): string {
  const params = new URLSearchParams({ target });
  return `/api/reports/compliance/pdf?${params.toString()}`;
}

/**
 * Auth headers required for a `fetch()` to the compliance PDF endpoint.
 * Returns an empty object when the user is unauthenticated, which will
 * result in the backend returning 401 (the standard auth flow).
 */
export function getCompliancePdfHeaders(): Record<string, string> {
  const token = getStreamToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function exportFindings(options: { format: 'csv' | 'json'; signal?: AbortSignal; target?: string }): Promise<Blob> {
  const target = options.target || 'all';
  const { data } = await apiClient.get(`/api/export/findings/${target}`, {
    signal: options.signal,
    params: { format: options.format },
    responseType: 'blob',
  });
  return data;
}
