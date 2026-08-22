import { describe, expect, it } from 'vitest';
import { capMigrations } from '@/hooks/useCockpitData';
import { asSuggestionList } from '@/hooks/useJobTracePanel';

describe('cockpit migrations', () => {
  it('caps the in-memory migration list', () => {
    expect(capMigrations(Array.from({ length: 60 }, (_, i) => i), 50)).toHaveLength(50);
    expect(capMigrations([1, 2, 3], 50)).toEqual([1, 2, 3]);
  });
});

describe('remediation payload', () => {
  it('treats a non-array suggestions field as empty', () => {
    expect(asSuggestionList({ oops: true })).toEqual([]);
    expect(asSuggestionList([{ id: 'r1' }])).toHaveLength(1);
  });
});

describe('demo sign-in', () => {
  it('rejects a blank operator name', async () => {
    const { isUsableOperatorName } = await import('@/hooks/useConsoleBridge');
    expect(isUsableOperatorName('   ')).toBe(false);
    expect(isUsableOperatorName('Ada')).toBe(true);
  });
});

describe('start scan', () => {
  it('rejects a blank target url', async () => {
    const { isUsableScanUrl } = await import('@/hooks/useConsoleBridge');
    expect(isUsableScanUrl('')).toBe(false);
    expect(isUsableScanUrl('https://app.test')).toBe(true);
  });
});

describe('stream mount', () => {
  it('does not flip mountedRef on stream rebuild', async () => {
    const { shouldResetMountedOnStreamCleanup } = await import('@/hooks/useCockpitData');
    expect(shouldResetMountedOnStreamCleanup()).toBe(false);
  });
});
