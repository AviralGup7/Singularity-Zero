export function parseFindingTimestamp(value: number | string | undefined | null): number {
  if (value === undefined || value === null || value === '') return 0;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return 0;
    return value > 9_999_999_999 ? value : value * 1000;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export function clampPercent(value: number | undefined | null): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  return Math.min(100, Math.max(0, value));
}

export function isEditableShortcutTarget(target: EventTarget | null): boolean {
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement) {
    return true;
  }
  return Boolean(target instanceof HTMLElement && target.isContentEditable);
}

export function shouldIgnoreGlobalShortcut(target: EventTarget | null): boolean {
  if (isEditableShortcutTarget(target)) return true;
  if (typeof document !== 'undefined' && document.querySelector('[role="dialog"][aria-modal="true"]')) {
    return true;
  }
  return false;
}
