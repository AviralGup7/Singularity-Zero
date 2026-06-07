import { apiClient } from './core';
import type { Finding } from '../types/api';

export interface RemediationUnitSuggestion {
  id: string;
  title: string;
  command: string;
  rationale: string;
  safety_note: string;
  cwe_id?: string;
  owasp_api?: string;
  owasp_top10?: string;
  source_file?: string;
  source_line?: number;
  source_function?: string;
  confidence?: number;
  fingerprint?: string;
}

export interface RemediationUnit {
  category: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  total_count: number;
  targets: string[];
  cwe_id?: string;
  owasp_api?: string;
  owasp_top10?: string;
  suggestions: RemediationUnitSuggestion[];
  sample_findings: Finding[];
}

export interface RemediationPlanResponse {
  status: string;
  units: RemediationUnit[];
  total_findings: number;
  total_units: number;
}

export interface RemediationCandidate {
  finding_key: string;
  endpoint: string;
  method: string;
  category: string;
  severity: string;
  confidence: number;
  test_contexts: string[];
  suggested_fix: string;
  fingerprint: string;
  evidence_keys: string[];
  cwe_id?: string;
  owasp_api?: string;
  owasp_top10?: string;
  source_file?: string;
  source_line?: number;
  source_function?: string;
  metadata?: Record<string, unknown>;
}

export const remediationApi = {
  getPlan: (signal?: AbortSignal) =>
    apiClient.get<RemediationPlanResponse>('/api/remediation/planner', { signal }),
  getCandidates: (params: { runId?: string; fingerprint?: string }, signal?: AbortSignal) =>
    apiClient.get<{ candidates: RemediationCandidate[] }>('/api/remediation/candidates', {
      params: { run_id: params.runId, fingerprint: params.fingerprint },
      signal,
    }),
  getCweCatalog: (signal?: AbortSignal) =>
    apiClient.get<{ entries: { cwe_id: string; name: string; description: string; url: string }[] }>(
      '/api/remediation/cwe-catalog',
      { signal },
    ),
};
