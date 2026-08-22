import { describe, expect, it } from 'vitest';
import { withoutFindingParam } from '@/features/findings/newFindingsFeed';
import { applyDismiss, applyMarkRead, unreadAfterMarkRead } from '@/features/notifications/unread';
import { coalesceStoredValue } from '@/utils/storage';
import { nextOfflineRetryCount, offlineRetryDelayMs } from '@/utils/offlineQueuePolicy';
import { parseFindingTimestamp } from '@/utils/findingTime';
import { normalizeTimestamp } from '@/utils/time';

describe('finding deep-link close', () => {
  it('removes finding so the detail pane cannot reopen itself', () => {
    const params = new URLSearchParams('finding=abc&severity=high');
    const next = withoutFindingParam(params);
    expect(next.get('finding')).toBeNull();
    expect(next.get('severity')).toBe('high');
    expect(params.get('finding')).toBe('abc');
  });
});

describe('inbox mark-read', () => {
  it('does not decrement unread when the updater is applied twice', () => {
    const inbox = [
      { id: 'a', read: false },
      { id: 'b', read: true },
    ];
    const first = applyMarkRead(inbox, 'a');
    const second = applyMarkRead(first.items, 'a');
    expect(first.wasUnread).toBe(true);
    expect(second.wasUnread).toBe(false);
    expect(unreadAfterMarkRead(first.wasUnread, 2)).toBe(1);
    expect(unreadAfterMarkRead(second.wasUnread, 1)).toBe(1);
    expect(applyDismiss(inbox, 'a').wasUnread).toBe(true);
    expect(applyDismiss(inbox, 'b').wasUnread).toBe(false);
  });
});

describe('offline retry schedule', () => {
  it('keeps a failed mutation and waits before the next attempt', () => {
    expect(nextOfflineRetryCount(0)).toBe(1);
    expect(offlineRetryDelayMs(1)).toBeGreaterThan(0);
    expect(nextOfflineRetryCount(3)).toBeNull();
  });
});

describe('timestamp scale', () => {
  it('does not multiply millisecond epochs by 1000', () => {
    const ms = 1_700_000_000_000;
    expect(parseFindingTimestamp(ms)).toBe(ms);
    expect(normalizeTimestamp(ms)).toBe(ms);
    expect(normalizeTimestamp(1_700_000_000)).toBe(1_700_000_000_000);
  });
});

describe('storage memory fallback', () => {
  it('returns the in-memory value when durable storage missed the write', () => {
    expect(coalesceStoredValue(null, 'from-memory')).toBe('from-memory');
    expect(coalesceStoredValue('from-disk', 'from-memory')).toBe('from-disk');
    expect(coalesceStoredValue(null, undefined)).toBeNull();
  });
});
