import { describe, expect, it } from 'vitest';
import { isTerminalSseEvent, shouldEnqueueSseEvent } from '@/hooks/realtime/ssePolicy';
import { toDay } from '@/hooks/useRiskHistory';
import { sanitizeTargetNames } from '@/hooks/useGapAnalysis';
import { autoResolveDependencies } from '@/utils/moduleDependencies';

describe('sse lifecycle', () => {
  it('still delivers completed events before closing', () => {
    expect(shouldEnqueueSseEvent('completed')).toBe(true);
    expect(isTerminalSseEvent('completed')).toBe(true);
    expect(shouldEnqueueSseEvent('heartbeat')).toBe(false);
  });
});

describe('risk day keys', () => {
  it('accepts unix seconds instead of slicing them as a date', () => {
    expect(toDay(1_700_000_000)).toBe('2023-11-14');
    expect(toDay('2024-06-02T12:00:00Z')).toBe('2024-06-02');
  });
});

describe('gap target names', () => {
  it('drops blank names from the picker', () => {
    expect(sanitizeTargetNames(['app.test', '', '  ', 'app.test'])).toEqual(['app.test']);
  });
});

describe('target KPIs', () => {
  it('does not let a NaN finding_count poison the average', async () => {
    const { averageFindingCount } = await import('@/hooks/useTargetsKPIs');
    expect(averageFindingCount([{ finding_count: Number.NaN }, { finding_count: 4 }])).toBe(2);
  });
});

describe('module resolve', () => {
  it('removes an incompatible pair instead of leaving both selected', () => {
    const next = autoResolveDependencies(new Set(['subdomain_enum', 'active_scanner']), []);
    expect(next.has('subdomain_enum') && next.has('active_scanner')).toBe(false);
  });
});
