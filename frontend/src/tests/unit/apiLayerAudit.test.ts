import { describe, expect, it } from 'vitest';
import { canonicalizeJobStatus, collectAllPages, mapFindingUpdate, parseRetryAfterMs, asRecord } from '@/api/contract';
import { isLoopbackHostname, measureResponseBytes, MAX_RESPONSE_SIZE_BYTES, validateRequestUrl } from '@/api/core';

describe('api layer audit', () => {
  it('measures payload size even without content-length', () => {
    expect(measureResponseBytes('abcd')).toBe(4);
    expect(measureResponseBytes({ a: 1 }, '12')).toBe(12);
    expect(measureResponseBytes({ hello: 'world' })).toBeGreaterThan(0);
    expect(measureResponseBytes('x'.repeat(MAX_RESPONSE_SIZE_BYTES + 1))).toBeGreaterThan(MAX_RESPONSE_SIZE_BYTES);
  });

  it('treats IPv6 loopback as loopback', () => {
    expect(isLoopbackHostname('::1')).toBe(true);
    expect(isLoopbackHostname('[::1]')).toBe(true);
    expect(isLoopbackHostname('127.0.0.1')).toBe(true);
    expect(isLoopbackHostname('example.com')).toBe(false);
    expect(validateRequestUrl('http://evil.example/api', 'https://console.example')).toBe(false);
  });

  it('does not coerce falsy job status through || queued', () => {
    expect(canonicalizeJobStatus('running')).toBe('running');
    expect(canonicalizeJobStatus('')).toBe('queued');
    expect(canonicalizeJobStatus(0)).toBe('queued');
    expect(canonicalizeJobStatus(false)).toBe('queued');
  });

  it('does not overwrite an explicit fp_status when marking false positive', () => {
    expect(mapFindingUpdate({ falsePositive: true, fpStatus: 'pending' })).toEqual({
      false_positive: true,
      fp_status: 'pending',
    });
    expect(mapFindingUpdate({ falsePositive: true })).toEqual({
      false_positive: true,
      fp_status: 'approved',
    });
  });

  it('ignores numeric junk as Retry-After HTTP-date', () => {
    expect(parseRetryAfterMs({ 'retry-after': '2' })).toBe(2000);
    expect(parseRetryAfterMs({ 'retry-after': '0' })).toBe(500);
    const past = parseRetryAfterMs({ 'retry-after': 'Thu, 01 Jan 1970 00:00:00 GMT' });
    expect(past).toBeGreaterThanOrEqual(500);
  });

  it('rejects class instances as records', () => {
    expect(asRecord({ id: '1' })).toEqual({ id: '1' });
    expect(asRecord(new Date())).toBeNull();
    expect(asRecord(['x'])).toBeNull();
  });

  it('fetches remaining pages in parallel when total is known', async () => {
    const seen: number[] = [];
    const items = await collectAllPages(
      async (query) => {
        seen.push(query.page);
        const start = (query.page - 1) * query.page_size;
        return {
          items: [start + 1, start + 2],
          total: 6,
          page: query.page,
          pageSize: 2,
          hasNext: query.page < 3,
          hasPrev: query.page > 1,
        };
      },
      { page_size: 2 },
    );
    expect(items).toEqual([1, 2, 3, 4, 5, 6]);
    expect(seen[0]).toBe(1);
    expect(seen.slice(1).sort()).toEqual([2, 3]);
  });
});
