import { describe, expect, it } from 'vitest';
import { shortcutEventMatches } from '@/hooks/useKeyboardShortcuts';
import { OfflineMutationQueue } from '@/utils/offlineQueue';
import { buildMarkdownReportBundle } from '@/utils/findingExport';
import type { Finding } from '@/types/api';

function keyEvent(partial: Partial<KeyboardEvent> & { key: string }): KeyboardEvent {
  return {
    key: partial.key,
    ctrlKey: Boolean(partial.ctrlKey),
    metaKey: Boolean(partial.metaKey),
    altKey: Boolean(partial.altKey),
    shiftKey: Boolean(partial.shiftKey),
  } as KeyboardEvent;
}

describe('shortcut matching', () => {
  it('does not fire a plain key while Ctrl/Meta is held', () => {
    expect(shortcutEventMatches('a', keyEvent({ key: 'a' }))).toBe(true);
    expect(shortcutEventMatches('a', keyEvent({ key: 'a', ctrlKey: true }))).toBe(false);
    expect(shortcutEventMatches('a', keyEvent({ key: 'a', metaKey: true }))).toBe(false);
  });

  it('treats ctrl+ and cmd+ as the same modifier family', () => {
    expect(shortcutEventMatches('ctrl+k', keyEvent({ key: 'k', ctrlKey: true }))).toBe(true);
    expect(shortcutEventMatches('cmd+k', keyEvent({ key: 'k', metaKey: true }))).toBe(true);
    expect(shortcutEventMatches('ctrl+k', keyEvent({ key: 'k' }))).toBe(false);
  });
});

describe('offline queue clear vs in-flight process', () => {
  it('does not reinsert a mutation after clear()', async () => {
    const queue = new OfflineMutationQueue();
    let release!: (value: unknown) => void;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    queue.enqueue({
      execute: async () => {
        await gate;
        throw new Error('network');
      },
      rollback: () => undefined,
      description: 'save finding',
    });
    queue.clear();
    release(undefined);
    await Promise.resolve();
    await Promise.resolve();
    expect(queue.length).toBe(0);
    expect(queue.getQueue()).toEqual([]);
  });
});

describe('report bundle cvss fallback', () => {
  it('prints N/A when both cvss fields are missing', () => {
    const finding = {
      id: 'f1',
      title: 'Open redirect',
      severity: 'high',
      type: 'redirect',
      target: 'https://example.test',
      confidence: 0.5,
    } as Finding;
    expect(buildMarkdownReportBundle([finding])).toContain('**CVSS:** N/A');
  });
});
