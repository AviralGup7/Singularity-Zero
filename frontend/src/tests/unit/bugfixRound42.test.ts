import { describe, expect, it } from 'vitest';
import { clampIterationProgress } from '@/components/IterationProgressBar';
import { clampPluginPercent, finitePluginCount } from '@/components/PluginProgressGrid';
import { calculateBackoff } from '@/api/retry';
import { isCacheEntryStale } from '@/api/cache';

describe('iteration bar', () => {
  it('does not allocate thousands of ticks for a bogus max', () => {
    const next = clampIterationProgress(Number.NaN, 10_000, Number.NaN);
    expect(next.max).toBe(64);
    expect(next.current).toBe(0);
    expect(next.percent).toBe(0);
  });
});

describe('plugin counts', () => {
  it('ignores NaN processed/total', () => {
    expect(finitePluginCount(Number.NaN)).toBe(0);
    expect(finitePluginCount(4)).toBe(4);
  });
});

describe('plugin percent', () => {
  it('clamps overflow percents', () => {
    expect(clampPluginPercent(140)).toBe(100);
    expect(clampPluginPercent(Number.NaN)).toBe(0);
  });
});

describe('retry backoff', () => {
  it('treats a non-positive attempt as the first retry', () => {
    expect(calculateBackoff(0, () => 0)).toBe(1000);
    expect(calculateBackoff(3, () => 0)).toBe(4000);
  });
});

describe('cache freshness', () => {
  it('treats an expired TTL as stale even before get() marks it', () => {
    expect(isCacheEntryStale({ timestamp: 0, ttl: 10, stale: false }, 100)).toBe(true);
    expect(isCacheEntryStale({ timestamp: 90, ttl: 20, stale: false }, 100)).toBe(false);
  });
});
