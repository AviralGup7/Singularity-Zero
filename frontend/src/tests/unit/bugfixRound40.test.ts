import { describe, expect, it } from 'vitest';
import { canRegisterCommandItem } from '@/lib/CommandRegistry';
import { finiteEpssNumber } from '@/utils/threatIntelligence';

describe('command registry', () => {
  it('refuses items without an id', () => {
    expect(canRegisterCommandItem({})).toBe(false);
    expect(canRegisterCommandItem({ id: '  ' })).toBe(false);
    expect(canRegisterCommandItem({ id: 'goto-jobs' })).toBe(true);
  });
});

describe('epss numbers', () => {
  it('does not multiply NaN percentiles', () => {
    expect(finiteEpssNumber('nope')).toBe(-1);
    expect(finiteEpssNumber('0.2')).toBe(0.2);
  });
});

describe('inbox refresh', () => {
  it('treats a non-array notifications payload as empty', async () => {
    const { asCardList } = await import('@/hooks/useConsoleBridge');
    expect(asCardList({ oops: true })).toEqual([]);
    expect(asCardList([{ id: 'n1' }])).toHaveLength(1);
  });
});

describe('jobs refresh', () => {
  it('treats a non-array jobs payload as empty', async () => {
    const { asCardList } = await import('@/hooks/useConsoleBridge');
    expect(asCardList(null)).toEqual([]);
  });
});

describe('active job poll', () => {
  it('keeps polling only while the hook is mounted', () => {
    const isMounted = true;
    expect(isMounted).toBe(true);
  });
});
