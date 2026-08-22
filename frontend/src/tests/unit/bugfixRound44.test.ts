import { describe, expect, it } from 'vitest';
import { asSuggestedActions, formatStalledSeconds } from '@/components/StalledExplainerPanel';
import { asDurationEntries, asJobList, jobProgressStreamUrl } from '@/api/jobs';

describe('stalled clock', () => {
  it('does not print NaNs ago', () => {
    expect(formatStalledSeconds(Number.NaN)).toBe('0s');
    expect(formatStalledSeconds(90)).toBe('1m 30s');
  });
});

describe('suggested actions', () => {
  it('ignores a non-array suggestions payload', () => {
    expect(asSuggestedActions('wait')).toEqual([]);
    expect(asSuggestedActions(['retry', 1])).toEqual(['retry']);
  });
});

describe('jobs list', () => {
  it('treats a missing jobs array as empty', () => {
    expect(asJobList({ jobs: [] })).toEqual([]);
    expect(asJobList([{ id: 'j1' }])).toHaveLength(1);
  });
});

describe('historical durations', () => {
  it('unwraps an entries envelope', () => {
    expect(asDurationEntries({ entries: [{ module: 'urls' }] })).toHaveLength(1);
    expect(asDurationEntries(null)).toEqual([]);
  });
});

describe('progress stream url', () => {
  it('does not emit /jobs//progress for a blank id', () => {
    expect(jobProgressStreamUrl('  ')).toBe('');
    expect(jobProgressStreamUrl('abc')).toContain('/jobs/abc/progress/stream');
  });
});
