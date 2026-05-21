import { apiClient } from './core';

export interface ComplianceControl {
  control_id: string;
  findings: {
    id: string;
    title: string;
    severity: string;
    url: string;
  }[];
  maturity: 'PASS' | 'PARTIAL' | 'AT_RISK' | 'FAIL' | 'UNKNOWN';
  recommendation: string;
}

export interface ComplianceReport {
  framework_coverage: Record<string, Record<string, ComplianceControl>>;
  category_counts: Record<string, number>;
  total_findings: number;
}

export async function getComplianceReport(targetName: string, signal?: AbortSignal): Promise<ComplianceReport> {
  const { data } = await apiClient.get<ComplianceReport>(`/api/targets/${targetName}/compliance`, { signal });
  return data;
}

export function getAttestationUrl(targetName: string): string {
  const baseUrl = import.meta.env.VITE_API_URL || '';
  return `${baseUrl}/api/export/compliance/${targetName}/attestation`;
}
