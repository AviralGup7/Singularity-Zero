import { describe, expect, it } from 'vitest';
import { pruneSelection, shouldShowIterationBar } from '@/features/findings/selection';

describe('selection prune', () => {
  it('drops ids that are no longer visible', () => {
    expect(pruneSelection(['a', 'b', 'c'], ['a', 'c'])).toEqual(['a', 'c']);
  });
});

describe('iteration bar', () => {
  it('shows analysis iteration 0 instead of hiding it', () => {
    expect(shouldShowIterationBar('analysis', 0)).toBe(true);
    expect(shouldShowIterationBar('analysis', undefined)).toBe(false);
    expect(shouldShowIterationBar('recon', 1)).toBe(false);
  });
});
