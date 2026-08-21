import { describe, expect, it } from 'vitest';
import { shouldShowErrorStack } from '@/utils/errorOverlayPolicy';
import { acknowledgeNewFindings } from '@/features/findings/newFindingsFeed';

describe('error overlay stack', () => {
  it('hides stack traces outside development', () => {
    expect(shouldShowErrorStack(true, 'Error: boom')).toBe(true);
    expect(shouldShowErrorStack(false, 'Error: boom')).toBe(false);
    expect(shouldShowErrorStack(true, undefined)).toBe(false);
  });
});

describe('load feed acknowledgement', () => {
  it('merges newly loaded ids into the seen set', () => {
    expect(acknowledgeNewFindings(['a'], ['b', 'a'])).toEqual(['a', 'b']);
  });
});
