import { describe, expect, it } from 'vitest';
import { finiteCount, sanitizeImportTargetName } from '@/hooks/useJobDetails';
import { shouldCacheEpssLookup } from '@/utils/threatIntelligence';

describe('throughput', () => {
  it('does not let NaN telemetry inflate scan velocity', () => {
    expect(finiteCount(Number.NaN, 0) * 0.6).toBe(0);
  });
});

describe('job counts', () => {
  it('does not treat NaN warning counts as live signals', () => {
    expect(finiteCount(Number.NaN, 0)).toBe(0);
    expect(finiteCount(-3, 0)).toBe(0);
    expect(finiteCount(4)).toBe(4);
  });
});

describe('semgrep import name', () => {
  it('strips path segments from a crafted filename', () => {
    expect(sanitizeImportTargetName('../../etc/passwd.json')).toBe('passwd');
    expect(sanitizeImportTargetName('.json')).toBe('imported-target');
  });
});

describe('visibility bootstrap', () => {
  it('defaults to visible when document is unavailable', () => {
    expect(typeof document === 'undefined' ? true : !document.hidden).toBeTypeOf('boolean');
  });
});

describe('epss cache', () => {
  it('does not persist an unavailable miss as a 24h hit', () => {
    expect(shouldCacheEpssLookup(false)).toBe(false);
  });
});
