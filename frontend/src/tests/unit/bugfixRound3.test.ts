import { describe, expect, it } from 'vitest';
import { appendClientMetrics, clampUnitInterval } from '@/components/performanceMetrics';
import { computeDiff, nextScanDiffSearch } from '@/pages/scanDiffModel';
import type { Finding } from '@/types/api';

function finding(partial: Partial<Finding> & Pick<Finding, 'id'>): Finding {
  return {
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

describe('client metrics buffer', () => {
  it('caps growth so the observer cannot leak unbounded rows', () => {
    const seed = Array.from({ length: 38 }, (_, i) => ({ name: `m${i}`, value: i, timestamp: String(i) }));
    const next = appendClientMetrics(seed, [
      { name: 'a', value: 1, timestamp: 'a' },
      { name: 'b', value: 2, timestamp: 'b' },
      { name: 'c', value: 3, timestamp: 'c' },
    ], 40);
    expect(next).toHaveLength(40);
    expect(next[0].name).toBe('m1');
    expect(next[39].name).toBe('c');
  });

  it('clamps KPI gauges instead of inventing 85%', () => {
    expect(clampUnitInterval(undefined)).toBe(0);
    expect(clampUnitInterval(1.4)).toBe(1);
    expect(clampUnitInterval(-2)).toBe(0);
  });
});

describe('scan diff model', () => {
  it('does not collapse two same-type findings into one map key', () => {
    const a = [finding({ id: '1' }), finding({ id: '2' })];
    const b = [finding({ id: '1' }), finding({ id: '3' })];
    const diff = computeDiff(a, b);
    expect(diff.newFindings.map((item) => item.id)).toEqual(['3']);
    expect(diff.removedFindings.map((item) => item.id)).toEqual(['2']);
  });

  it('skips search param writes when the URL is already correct', () => {
    const current = new URLSearchParams('runA=one&runB=two');
    expect(nextScanDiffSearch(current, 'all', 'one', 'two')).toBe(current.toString());
  });
});
