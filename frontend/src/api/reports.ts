import type { DetectionGapResponse, HealthStatus } from '@/types/api';
import { apiClient, cachedGet } from './core';

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

export async function getGapAnalysis(target?: string | null, signal?: AbortSignal): Promise<DetectionGapResponse> {
  let targetStr: string | undefined = undefined;
  let abortSignal: AbortSignal | undefined = signal;
  
  if (typeof target === 'string') {
    targetStr = target;
  } else if (((target as unknown) instanceof AbortSignal) || (target && 'aborted' in (target as Record<string, unknown>))) {
    abortSignal = target as unknown as AbortSignal;
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
  const token = sessionStorage.getItem('auth_token');
  if (token) params.set('token', token);
  return `/api/reports/compliance/pdf?${params.toString()}`;
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
