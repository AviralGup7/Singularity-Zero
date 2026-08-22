import { describe, expect, it } from 'vitest';
import { asPlatformClients, pushFindingToPlatform } from '@/api/platforms';
import { sanitizeCacheKeyLimit, deleteCacheKeys } from '@/api/cacheMgmt';
import { isUsableReplayParams } from '@/api/replay';

describe('platform clients', () => {
  it('treats a missing clients array as empty', () => {
    expect(asPlatformClients({ clients: [] })).toEqual([]);
    expect(asPlatformClients([{ platform: 'hackerone', ready: true, configured: false }])).toHaveLength(1);
  });
});

describe('platform submit', () => {
  it('refuses a blank run or finding id', async () => {
    const res = await pushFindingToPlatform(' ', 'f1', 'hackerone');
    expect(res.submitted).toBe(false);
  });
});

describe('cache key limit', () => {
  it('replaces a non-positive limit with a safe default', () => {
    expect(sanitizeCacheKeyLimit(0)).toBe(100);
    expect(sanitizeCacheKeyLimit(5000)).toBe(1000);
  });
});

describe('cache delete', () => {
  it('refuses an empty delete pattern', async () => {
    await expect(deleteCacheKeys('  ')).rejects.toThrow(/required/i);
  });
});

describe('replay params', () => {
  it('requires target, run, and replay id', () => {
    expect(isUsableReplayParams({ target: '', run: 'r', replay_id: 'x' })).toBe(false);
    expect(isUsableReplayParams({ target: 'a', run: 'r', replay_id: 'x' })).toBe(true);
  });
});
