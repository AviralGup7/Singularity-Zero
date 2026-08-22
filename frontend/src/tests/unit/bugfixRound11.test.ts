import { describe, expect, it } from 'vitest';
import { canUnlockSession } from '@/hooks/sessionUnlock';
import { sanitizeSeverityFilters } from '@/features/findings/severityFilter';
import { detectFreshFindingIds } from '@/features/findings/newFindingsFeed';
import { unreadAfterDismiss } from '@/features/notifications/unread';
import { normalizeFindingsViewMode } from '@/features/findings/findingsViewMode';

describe('session unlock', () => {
  it('allows an explicit unlock while locked, but not idle activity', () => {
    expect(canUnlockSession(true, false)).toBe(false);
    expect(canUnlockSession(true, true)).toBe(true);
    expect(canUnlockSession(false, false)).toBe(true);
  });
});

describe('severity query sanitization', () => {
  it('drops unknown severity tokens from the URL', () => {
    expect(sanitizeSeverityFilters(['HIGH', 'nope', 'low', 'low'])).toEqual(['high', 'low']);
  });
});

describe('new finding detection', () => {
  it('does not treat already-pending ids as newly seen', () => {
    expect(detectFreshFindingIds(['a'], ['a', 'b', 'c'])).toEqual(['b', 'c']);
    expect(detectFreshFindingIds(['a', 'b'], ['a', 'b'])).toEqual([]);
  });
});

describe('dismiss unread', () => {
  it('decrements only when the dismissed item was unread', () => {
    expect(unreadAfterDismiss(true, 4)).toBe(3);
    expect(unreadAfterDismiss(false, 4)).toBe(4);
  });
});

describe('grid bulk bar view mode', () => {
  it('treats an invalid persisted mode as grid so the bulk bar can show', () => {
    expect(normalizeFindingsViewMode('cards')).toBe('grid');
  });
});
