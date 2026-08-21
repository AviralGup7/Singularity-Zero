export const MAX_OFFLINE_RETRIES = 3;

export function nextOfflineRetryCount(current: number, max = MAX_OFFLINE_RETRIES): number | null {
  const next = current + 1;
  return next > max ? null : next;
}

export function createMutationId(now = Date.now()): string {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
  } catch {
    /* fall through */
  }
  return `mut-${now}-${Math.random().toString(36).slice(2, 10)}`;
}

export function isFocusableHeading(el: HTMLElement): boolean {
  if (el.hasAttribute('aria-hidden') && el.getAttribute('aria-hidden') !== 'false') return false;
  if (el.hidden || el.getAttribute('hidden') !== null) return false;
  const style = typeof window !== 'undefined' ? window.getComputedStyle(el) : null;
  if (style && (style.display === 'none' || style.visibility === 'hidden')) return false;
  if (el.classList.contains('sr-only')) return false;
  return true;
}
