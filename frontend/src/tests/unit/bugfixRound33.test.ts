import { describe, expect, it } from 'vitest';
import { mapToVisualState } from '@/lib/mapToVisualState';
import { nextCustodyRecordsAfterDelete, parseCustodyRecords } from '@/utils/chainOfCustody';
import { extractJobIdFromPath } from '@/hooks/useAutoBreadcrumbs';
import { mergeTelemetry } from '@/hooks/useJobMonitorUtils';

describe('visual progress', () => {
  it('does not treat a 42 percent poll as 0.42 flow', () => {
    const state = mapToVisualState({ progress_percent: 42, status: 'running' });
    expect(state.flow).toBeGreaterThan(0.1);
  });
});

describe('custody delete', () => {
  it('keeps the delete audit instead of dropping the record', () => {
    const next = nextCustodyRecordsAfterDelete([{
      id: 'e1',
      name: 'shot',
      type: 'json',
      created: 't',
      hash: 'h',
      custodyChain: [],
      metadata: {},
    }], 'e1', 'analyst');
    expect(next).toHaveLength(1);
    expect(next[0].custodyChain.at(-1)?.action).toBe('deleted');
    expect(parseCustodyRecords('{"id":"x"}')).toEqual([]);
  });
});

describe('targets search page', () => {
  it('resets to page 1 when the search changes', async () => {
    const { pageAfterSearchChange } = await import('@/hooks/useTargets');
    expect(pageAfterSearchChange()).toBe(1);
  });
});

describe('job breadcrumb', () => {
  it('does not treat /jobs/abc/logs as the job id', () => {
    expect(extractJobIdFromPath('/jobs/abc/logs')).toBe('abc');
    expect(extractJobIdFromPath('/jobs')).toBeUndefined();
  });
});

describe('telemetry merge', () => {
  it('ignores prototype-polluting keys', () => {
    const merged = mergeTelemetry({}, { __proto__: { hacked: true }, retries: 2 } as Record<string, unknown>);
    expect((merged as { retries?: number }).retries).toBe(2);
    expect(Object.prototype.hasOwnProperty.call(merged, 'hacked')).toBe(false);
  });
});
