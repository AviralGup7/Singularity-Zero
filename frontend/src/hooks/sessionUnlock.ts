export function canUnlockSession(isLocked: boolean, force: boolean): boolean {
  return force || !isLocked;
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
