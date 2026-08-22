export function canUnlockSession(isLocked: boolean, force: boolean): boolean {
  return force || !isLocked;
}

export function nextLockFlags(lockNow: boolean): { isLocked: boolean; showWarning: boolean; remainingMs: number } {
  return lockNow
    ? { isLocked: true, showWarning: false, remainingMs: 0 }
    : { isLocked: false, showWarning: false, remainingMs: 0 };
}
