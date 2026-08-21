import { describe, expect, it } from 'vitest';
import { moduleIntegrity } from '@/components/gap-analysis/gapIntegrity';

describe('gap integrity', () => {
  it('never reports a negative OK module count', () => {
    expect(moduleIntegrity(10, 12)).toEqual({ ok: 0, total: 10 });
    expect(moduleIntegrity(8, 2)).toEqual({ ok: 6, total: 8 });
    expect(moduleIntegrity(-1, 3)).toEqual({ ok: 0, total: 0 });
  });
});
