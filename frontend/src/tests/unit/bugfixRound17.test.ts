import { describe, expect, it } from 'vitest';
import { normalizeProgressPercent } from '@/utils/normalizeScale';

describe('progress scale modes', () => {
  it('does not treat a 1 percent poll as complete', () => {
    expect(normalizeProgressPercent(1, 'percent')).toBe(1);
    expect(normalizeProgressPercent(1, 'fraction')).toBe(100);
    expect(normalizeProgressPercent(0.42, 'auto')).toBe(42);
    expect(normalizeProgressPercent(42, 'auto')).toBe(42);
  });
});
