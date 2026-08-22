import { describe, expect, it } from 'vitest';
import { escapeCSVValue, parseComplianceLogs } from '@/utils/complianceLogger';
import { shouldFallbackFromWs } from '@/hooks/useWebSocket';

describe('error tracker store', () => {
  it('ignores a non-array persisted blob', async () => {
    const { parseTrackedErrorBlob } = await import('@/utils/errorTracker');
    expect(parseTrackedErrorBlob('{"id":"x"}')).toEqual([]);
  });
});

describe('compliance store', () => {
  it('ignores a non-array blob', () => {
    expect(parseComplianceLogs('{"id":"x"}')).toEqual([]);
    expect(parseComplianceLogs('[{"id":"c1"}]')).toHaveLength(1);
  });
});

describe('compliance csv', () => {
  it('escapes quotes and formulas', () => {
    expect(escapeCSVValue('=cmd')).toBe("'=cmd");
    expect(escapeCSVValue('say "hi"')).toBe('say ""hi""');
  });
});

describe('compliance cap', () => {
  it('trims the log so sessionStorage cannot grow without bound', async () => {
    const { capComplianceLogs } = await import('@/utils/complianceLogger');
    expect(capComplianceLogs(Array.from({ length: 5 }, (_, i) => i), 3)).toEqual([0, 1, 2]);
  });
});

describe('websocket fallback', () => {
  it('does not fall back on the first drop after a live connection', () => {
    expect(shouldFallbackFromWs(false, 1)).toBe(false);
    expect(shouldFallbackFromWs(true, 0)).toBe(true);
    expect(shouldFallbackFromWs(false, 4)).toBe(true);
  });
});
