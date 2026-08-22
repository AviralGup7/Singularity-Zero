import { describe, expect, it } from 'vitest';
import { clampStagePercent, formatCount } from '@/components/StageProgressBars';
import { tenantsMatch } from '@/components/RouteGuard';
import { classifyInlineLogLine } from '@/components/LogLine';

describe('stage percent', () => {
  it('does not emit NaN% widths', () => {
    expect(clampStagePercent(Number.NaN)).toBe(0);
    expect(clampStagePercent(140)).toBe(100);
  });
});

describe('stage counts', () => {
  it('ignores non-finite processed totals', () => {
    expect(formatCount(Number.NaN, 10)).toBe('0/10');
    expect(formatCount(3, Number.NaN)).toBe('3');
  });
});

describe('tenant match', () => {
  it('treats tenant ids as case-insensitive and trimmed', () => {
    expect(tenantsMatch(' Tenant-A ', 'tenant-a')).toBe(true);
    expect(tenantsMatch('a', 'b')).toBe(false);
  });
});

describe('stage classification', () => {
  it('maps known failure codes without crashing on missing keys', async () => {
    const { getClassificationLabel } = await import('@/components/StageProgressBars');
    expect(getClassificationLabel('oom_error')).toContain('OOM');
    expect(getClassificationLabel(undefined)).toBe('');
  });
});

describe('inline log lines', () => {
  it('does not treat a URL with error in the path as an error line', () => {
    expect(classifyInlineLogLine('GET https://app.test/error')).not.toContain('rose');
    expect(classifyInlineLogLine('fatal exception')).toContain('rose');
  });
});
