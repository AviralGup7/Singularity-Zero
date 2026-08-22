import { describe, expect, it } from 'vitest';
import { classifyLogLine } from '@/lib/utils';
import { sumFiniteDurations } from '@/hooks/useJobMonitor';
import { asNoteList } from '@/hooks/useCockpitData';

describe('log classification', () => {
  it('does not paint a URL containing "error" as a log error', () => {
    expect(classifyLogLine('GET https://app.test/error-page')).not.toContain('log-error');
    expect(classifyLogLine('Unhandled exception in scanner')).toContain('log-error');
  });
});

describe('duration forecast', () => {
  it('ignores NaN historical means', () => {
    expect(sumFiniteDurations([12, Number.NaN, 8])).toBe(20);
  });
});

describe('cockpit notes', () => {
  it('treats a non-array notes payload as empty', () => {
    expect(asNoteList({ notes: [] })).toEqual([]);
    expect(asNoteList([{ id: 'n1' }])).toHaveLength(1);
  });
});

describe('cockpit exchanges', () => {
  it('treats a missing exchanges list as empty', () => {
    expect(asNoteList(undefined)).toEqual([]);
  });
});

describe('graph debounce cancel', () => {
  it('cancels pending graph work on unmount', async () => {
    const { shouldCancelPendingGraphUpdate } = await import('@/hooks/useCockpitGraph');
    expect(shouldCancelPendingGraphUpdate(true)).toBe(true);
    expect(shouldCancelPendingGraphUpdate(false)).toBe(false);
  });
});
