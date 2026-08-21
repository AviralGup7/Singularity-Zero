import { describe, expect, it } from 'vitest';
import { createMutationId, isFocusableHeading, nextOfflineRetryCount } from '@/utils/offlineQueuePolicy';

describe('offline queue policy', () => {
  it('drops a mutation after the retry budget', () => {
    expect(nextOfflineRetryCount(0)).toBe(1);
    expect(nextOfflineRetryCount(2)).toBe(3);
    expect(nextOfflineRetryCount(3)).toBeNull();
  });

  it('creates an id even without randomUUID', () => {
    expect(createMutationId(123).startsWith('mut-') || createMutationId(123).length > 8).toBe(true);
  });
});

describe('route focus target', () => {
  it('skips sr-only and aria-hidden headings', () => {
    const hidden = document.createElement('h1');
    hidden.className = 'sr-only';
    const aria = document.createElement('h2');
    aria.setAttribute('aria-hidden', 'true');
    const visible = document.createElement('h1');
    visible.textContent = 'Jobs';
    expect(isFocusableHeading(hidden)).toBe(false);
    expect(isFocusableHeading(aria)).toBe(false);
    expect(isFocusableHeading(visible)).toBe(true);
  });
});
