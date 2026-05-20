import { apiClient } from './core';
import type { Finding } from '../types/api';

export interface RemediationUnit {
  category: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  total_count: number;
  targets: string[];
  suggestions: {
    id: string;
    title: string;
    command: string;
    rationale: string;
    safety_note: string;
  }[];
  sample_findings: Finding[];
}

export interface RemediationPlanResponse {
  status: string;
  units: RemediationUnit[];
  total_findings: number;
  total_units: number;
}

export const remediationApi = {
  getPlan: (signal?: AbortSignal) =>
    apiClient.get<RemediationPlanResponse>('/api/remediation/planner', { signal }),
};
