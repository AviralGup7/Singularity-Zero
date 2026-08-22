import { describe, expect, it } from 'vitest';
import { computeTotalP50, formatDuration } from '@/components/DurationForecast';
import { asAnalystPresenceList, parseTriageAnalyst } from '@/hooks/useTriageCollaboration';
import { getRetryAfterMs } from '@/api/retry';

describe('duration format', () => {
  it('does not print NaNs', () => {
    expect(formatDuration(Number.NaN)).toBe('0s');
    expect(formatDuration(90)).toBe('1m 30s');
  });
});

describe('forecast totals', () => {
  it('ignores non-finite percentile samples', () => {
    expect(computeTotalP50({ a: { mean: 1, p50: Number.NaN, p90: 2, p99: 3, count: 1 }, b: { mean: 1, p50: 10, p90: 12, p99: 14, count: 1 } })).toBe(10);
  });
});

describe('triage analyst', () => {
  it('rejects a corrupt identity blob', () => {
    expect(parseTriageAnalyst('{"analyst_id":123}')).toBeNull();
    expect(parseTriageAnalyst('{"analyst_id":"a1","analyst_name":"Ada"}')?.analyst_name).toBe('Ada');
  });
});

describe('presence list', () => {
  it('ignores a non-array analysts payload', () => {
    expect(asAnalystPresenceList({ analysts: [] })).toEqual([]);
    expect(asAnalystPresenceList([{ analyst_id: 'a' }])).toHaveLength(1);
  });
});

describe('retry-after', () => {
  it('caps a huge Retry-After and ignores junk numbers', () => {
    expect(getRetryAfterMs({ response: { headers: { 'retry-after': '99999' } } })).toBe(30_000);
    expect(getRetryAfterMs({ response: { headers: { 'retry-after': '-5' } } })).toBeNull();
  });
});
