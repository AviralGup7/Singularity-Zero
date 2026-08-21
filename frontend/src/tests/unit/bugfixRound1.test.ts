import { describe, expect, it } from 'vitest';
import { clampFindingsPage, normalizeFindingsViewMode } from '@/features/findings/findingsViewMode';
import { resolveSessionTimeoutMs, resolveSessionWarningAt } from '@/hooks/sessionTimeoutPolicy';
import { applyLiveScanEvent, mergePolledScanState } from '@/components/scanStatusMerge';
import { sanitizePiiFromVisibility } from '@/utils/piiVisibility';

describe('findings view mode', () => {
  it('falls back to grid for unknown persisted values', () => {
    expect(normalizeFindingsViewMode('kanban')).toBe('kanban');
    expect(normalizeFindingsViewMode('cards')).toBe('grid');
    expect(normalizeFindingsViewMode(null)).toBe('grid');
  });

  it('clamps pagination so next/prev cannot walk off the last page', () => {
    expect(clampFindingsPage(5, 2)).toBe(2);
    expect(clampFindingsPage(0, 4)).toBe(1);
    expect(clampFindingsPage(Number.NaN, 3)).toBe(1);
  });
});

describe('session warning policy', () => {
  it('does not fire the warning almost immediately on a 60s timeout', () => {
    expect(resolveSessionTimeoutMs(15_000)).toBe(60_000);
    expect(resolveSessionWarningAt(60_000)).toBe(48_000);
    expect(resolveSessionWarningAt(15 * 60 * 1000)).toBe(13 * 60 * 1000);
  });
});

describe('scan status merge', () => {
  const live = {
    jobId: 'job-1',
    targetName: 'app.test',
    progress: 72,
    status: 'analysis',
    etaLabel: '2m',
    findingsCount: 8,
    urlsFound: 40,
  };

  it('does not let a stale poll rewind live progress', () => {
    const merged = mergePolledScanState(live, { ...live, progress: 40, findingsCount: 3, urlsFound: 10, status: 'Scanning' });
    expect(merged?.progress).toBe(72);
    expect(merged?.findingsCount).toBe(8);
    expect(merged?.urlsFound).toBe(40);
  });

  it('ignores live events from a different job', () => {
    expect(applyLiveScanEvent(live, 'job-2', { progress: 99 })?.progress).toBe(72);
    expect(applyLiveScanEvent(live, 'job-1', { progress: 80 })?.progress).toBe(80);
  });
});

describe('pii visibility mapping', () => {
  it('sanitizes reports only while PII is hidden', () => {
    expect(sanitizePiiFromVisibility(true)).toBe(false);
    expect(sanitizePiiFromVisibility(false)).toBe(true);
  });
});
