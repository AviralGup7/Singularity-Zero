import { describe, expect, it } from 'vitest';
import { pairFromSelection, pruneSelection } from '@/features/findings/selection';

describe('findings selection helpers', () => {
  it('orders a compare pair by id so column sides stay stable', () => {
    const items = [
      { id: 'bravo', title: 'B' },
      { id: 'alpha', title: 'A' },
    ];
    const forward = pairFromSelection(new Set(['bravo', 'alpha']), items);
    const reverse = pairFromSelection(['alpha', 'bravo'], items);
    expect(forward?.findingA.id).toBe('alpha');
    expect(forward?.findingB.id).toBe('bravo');
    expect(reverse).toEqual(forward);
  });

  it('drops ids that are no longer visible', () => {
    expect(pruneSelection(['a', 'gone'], ['a', 'b'])).toEqual(['a']);
  });
});
