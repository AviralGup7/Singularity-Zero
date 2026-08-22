export function canUnlockSession(isLocked: boolean, force: boolean): boolean {
  return force || !isLocked;
}

/** Same-tab storage events do not fire; also refresh on focus / visibility. */
export function subscribeStreamToken(onChange: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  const handler = () => onChange();
  window.addEventListener('storage', handler);
  window.addEventListener('focus', handler);
  document.addEventListener('visibilitychange', handler);
  return () => {
    window.removeEventListener('storage', handler);
    window.removeEventListener('focus', handler);
    document.removeEventListener('visibilitychange', handler);
  };
}

export function normalizeAutoLogoutMinutes(value: number | undefined | null): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return 0;
  return Math.min(480, Math.floor(value));
}

export function nextLockFlags(lockNow: boolean): { isLocked: boolean; showWarning: boolean; remainingMs: number } {
  return lockNow
    ? { isLocked: true, showWarning: false, remainingMs: 0 }
    : { isLocked: false, showWarning: false, remainingMs: 0 };
}
