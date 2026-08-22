import { describe, expect, it } from 'vitest';
import { compareSelectionKey, confidencePercent, normalizeProgressPercent } from '@/utils/normalizeScale';
import { mergePolledScanState } from '@/components/scanStatusMerge';

describe('confidence and progress scales', () => {
  it('treats 0-1 and 0-100 confidence as percents without overflowing', () => {
    expect(confidencePercent(0.8)).toBe(80);
    expect(confidencePercent(80)).toBe(80);
    expect(confidencePercent(800)).toBe(100);
  });

  it('promotes fractional scan progress into a percent', () => {
    expect(normalizeProgressPercent(0.42)).toBe(42);
    expect(normalizeProgressPercent(42)).toBe(42);
  });
});

describe('compare dismiss key', () => {
  it('is stable regardless of insertion order', () => {
    expect(compareSelectionKey(['b', 'a'])).toBe(compareSelectionKey(new Set(['a', 'b'])));
  });
});

describe('progress merge after scale normalize', () => {
  it('treats polled progress as a percent, not a 0-1 fraction', () => {
    const merged = mergePolledScanState(
      { jobId: 'j', targetName: 't', progress: 40, status: 'a', etaLabel: '', findingsCount: 1, urlsFound: 1 },
      { jobId: 'j', targetName: 't', progress: 0.9, status: 'b', etaLabel: '', findingsCount: 1, urlsFound: 1 },
    );
    expect(merged?.progress).toBe(40);
  });
});
