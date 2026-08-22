import type { Finding } from '@/types/api';

export function finiteMetric(value: unknown, fallback = 0): number {
  const n = typeof value === 'number' ? value : typeof value === 'string' && value.trim() ? Number(value) : Number.NaN;
  return Number.isFinite(n) ? n : fallback;
}

export function normalizeCvss(value: unknown): number {
  return Math.min(10, Math.max(0, finiteMetric(value, 0)));
}

export function normalizeEpss(value: unknown): number {
  const n = finiteMetric(value, 0);
  if (n < 0) return 0;
  if (n <= 1) return n;
  if (n <= 100) return n / 100;
  return 1;
}

export function getFindingCvss(finding: Finding): number {
  const val = finding.cvss_v4_score ?? finding.cvss_score ?? (typeof finding.cvss === 'number' ? finding.cvss : null);
  return normalizeCvss(val);
}

export function getFindingEpss(finding: Finding): number {
  return normalizeEpss(finding.threat_intel?.epss_score ?? finding.epss_score ?? 0);
}

export function getFindingBounty(finding: Finding): number {
  const n = finiteMetric(finding.bounty_value, 0);
  return n < 0 ? 0 : n;
}
