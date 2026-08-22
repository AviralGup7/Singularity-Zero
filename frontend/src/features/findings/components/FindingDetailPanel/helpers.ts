import type { RemediationSuggestion } from '@/types/api';
import { getFindingRemediation } from '@/api/client';

export function estimateBounty(
  score: number,
  epss: number,
  criticality: number,
): { min: number; max: number } {
  let min = 0;
  let max = 0;
  if (score >= 9.0) {
    min = 2000;
    max = 10000;
  } else if (score >= 7.0) {
    min = 500;
    max = 2000;
  } else if (score >= 4.0) {
    min = 100;
    max = 500;
  } else if (score > 0) {
    min = 50;
    max = 100;
  }

  let multiplier = 1.0;
  if (epss > 0.1) multiplier += 0.2;
  if (criticality > 1.0) multiplier += criticality - 1.0;

  return {
    min: Math.round(min * multiplier),
    max: Math.round(max * multiplier),
  };
}

export const remediationCache = new Map<string, RemediationSuggestion[]>();

export function prefetchRemediation(id: string) {
  if (!id || remediationCache.has(id)) return;
  getFindingRemediation(id)
    .then((res) => {
      remediationCache.set(id, res.suggestions || []);
    })
    .catch(() => {});
}

export function shouldCloseFindingDetail(key: string, nestedDialogOpen: boolean): boolean {
  return key === 'Escape' && !nestedDialogOpen;
}

export type DetailTab =
  | 'cvss'
  | 'csi'
  | 'risk'
  | 'evidence'
  | 'custody'
  | 'simulation'
  | 'request'
  | 'logic'
  | 'comments'
  | 'activity'
  | 'bounty';

export interface ExtendedEvidence {
  chain_simulation?: import('@/types/api').AttackChain;
  replay?: { id: string };
  [key: string]: unknown;
}
