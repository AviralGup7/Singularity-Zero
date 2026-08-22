import { describe, expect, it } from 'vitest';
import { escapeXml } from '@/utils/exporters';
import { ensureFocusable } from '@/hooks/useFocusManagement';
import { appendClientMetrics, clampUnitInterval, isRenderableMetric } from '@/components/performanceMetrics';
import { validateJobId } from '@/utils/routeValidation';

describe('xml export', () => {
  it('does not throw when a finding id is missing', () => {
    expect(escapeXml(undefined)).toBe('');
    expect(escapeXml('<id>')).toBe('&lt;id&gt;');
  });
});

describe('route focus', () => {
  it('adds tabindex so a heading can receive focus', () => {
    const el = document.createElement('h1');
    ensureFocusable(el);
    expect(el.getAttribute('tabindex')).toBe('-1');
  });
});

describe('client metrics', () => {
  it('drops non-finite samples', () => {
    expect(isRenderableMetric({ name: 'CLS', value: Number.NaN, timestamp: 't' })).toBe(false);
    expect(appendClientMetrics([], [{ name: 'CLS', value: Number.NaN, timestamp: 't' }])).toEqual([]);
  });
});

describe('unit interval', () => {
  it('treats a 92 percent KPI as 0.92 not 100%', () => {
    expect(clampUnitInterval(92)).toBe(0.92);
    expect(clampUnitInterval(0.4)).toBe(0.4);
  });
});

describe('job ids', () => {
  it('accepts slug-style job ids used by the console', () => {
    expect(validateJobId('job-abc_12')).toBe('job-abc_12');
    expect(validateJobId('../etc/passwd')).toBeNull();
  });
});
