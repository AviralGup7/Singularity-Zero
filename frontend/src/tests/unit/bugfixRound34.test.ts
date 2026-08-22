import { describe, expect, it } from 'vitest';
import { classifyNucleiSeverity, telemetryEventLevel } from '@/hooks/useLiveTerminal';
import { parseAuditLog } from '@/utils/auditLogger';

describe('gap search flush', () => {
  it('keeps the last typed query on unmount', async () => {
    const { flushDebouncedSearch } = await import('@/hooks/useGapAnalysis');
    expect(flushDebouncedSearch('xss')).toBe('xss');
  });
});

describe('nuclei severity', () => {
  it('does not treat a low finding as debug', () => {
    expect(classifyNucleiSeverity('low')).toBe('info');
    expect(classifyNucleiSeverity('critical')).toBe('critical');
  });
});

describe('telemetry event type', () => {
  it('does not throw when event_type is missing', () => {
    expect(telemetryEventLevel({ status: 'ok' })).toBe('info');
    expect(telemetryEventLevel({ event_type: 'scan_completed' })).toBe('success');
  });
});

describe('job poll', () => {
  it('only polls while the job is running', async () => {
    const { shouldPollJob } = await import('@/hooks/useJobMonitor');
    expect(shouldPollJob('running')).toBe(true);
    expect(shouldPollJob('completed')).toBe(false);
  });
});

describe('audit log store', () => {
  it('ignores a non-array blob', () => {
    expect(parseAuditLog('{"id":"x"}')).toEqual([]);
    expect(parseAuditLog('[{"id":"a1"}]')).toHaveLength(1);
  });
});
