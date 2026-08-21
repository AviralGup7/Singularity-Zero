import type { Finding } from '@/types/api';

export function getFindingCvss(finding: Finding): number {
  const val = finding.cvss_v4_score ?? finding.cvss_score ?? (typeof finding.cvss === 'number' ? finding.cvss : null);
  return val ?? 0;
}

export function getFindingEpss(finding: Finding): number {
  return finding.threat_intel?.epss_score ?? finding.epss_score ?? 0;
}

export function getFindingBounty(finding: Finding): number {
  return finding.bounty_value ?? 0;
}
