import { describe, expect, it } from 'vitest';
import { isCanceledHealthError } from '@/hooks/useHealthStatus';
import { isRetryable } from '@/features/bridge/errors';
import { rateWebVital } from '@/utils/webVitals';
import { formatDurationMs } from '@/components/performanceMetrics';
import { calculateHealthScore } from '@/lib/utils';

describe('health refetch cancel', () => {
  it('treats abort as a silent miss', () => {
    expect(isCanceledHealthError(Object.assign(new Error('Aborted'), { name: 'AbortError' }))).toBe(true);
    expect(isCanceledHealthError(new Error('offline'))).toBe(false);
  });
});

describe('bridge retry', () => {
  it('retries timeout and bad gateway', () => {
    expect(isRetryable('timeout')).toBe(true);
    expect(isRetryable('bad_gateway')).toBe(true);
    expect(isRetryable('not_found')).toBe(false);
  });
});

describe('web vital rating', () => {
  it('does not rate NaN as good', () => {
    expect(rateWebVital('LCP', Number.NaN)).toBe('needs-improvement');
    expect(rateWebVital('LCP', 1200)).toBe('good');
  });
});

describe('duration format', () => {
  it('does not print NaNms', () => {
    expect(formatDurationMs(Number.NaN)).toBe('—');
    expect(formatDurationMs(-4)).toBe('—');
    expect(formatDurationMs(250)).toBe('250ms');
  });
});

describe('health score', () => {
  it('does not improve the score on negative severity counts', () => {
    expect(calculateHealthScore({ critical: -2 }).score).toBe(100);
  });
});
