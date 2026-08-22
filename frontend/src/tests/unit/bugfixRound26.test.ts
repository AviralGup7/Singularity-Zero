import { describe, expect, it } from 'vitest';
import { computeDiff } from '@/pages/scanDiffModel';
import { getPageNumbers } from '@/lib/utils';
import { resolveTargetPageCount } from '@/hooks/useTargetPagination';
import { confidencePercent } from '@/utils/normalizeScale';
import { isExternalUrl } from '@/utils/routeValidation';
import type { Finding } from '@/types/api';

function finding(partial: Partial<Finding>): Finding {
  return {
    id: 'a',
    type: 'xss',
    title: 't',
    description: 'd',
    severity: 'high',
    confidence: 1,
    timestamp: 1,
    lifecycle_state: 'detected',
    target: 'app.test',
    ...partial,
  };
}

describe('run diff', () => {
  it('treats a bounty change as a change, not a no-op', () => {
    const diff = computeDiff(
      [finding({ id: '1', bounty_value: 100 })],
      [finding({ id: '1', bounty_value: 500 })],
    );
    expect(diff.changedFindings).toHaveLength(1);
    expect(diff.newFindings).toHaveLength(0);
  });
});

describe('pagination', () => {
  it('never returns an empty page list', () => {
    expect(getPageNumbers(0, 0)).toEqual([1]);
    expect(getPageNumbers(Number.NaN, Number.NaN)[0]).toBe(1);
  });

  it('keeps target pages at least 1', () => {
    expect(resolveTargetPageCount(0)).toBe(1);
    expect(resolveTargetPageCount(-4)).toBe(1);
  });
});

describe('jira confidence', () => {
  it('keeps percent-scale confidence', () => {
    expect(confidencePercent(85)).toBe(85);
  });
});

describe('external url', () => {
  it('treats javascript: as unsafe/external', () => {
    expect(isExternalUrl('javascript:alert(1)')).toBe(true);
    expect(isExternalUrl('/jobs')).toBe(false);
  });
});
