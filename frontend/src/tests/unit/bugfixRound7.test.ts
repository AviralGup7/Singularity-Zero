import { describe, expect, it } from 'vitest';
import { clampPercent, parseFindingTimestamp, shouldIgnoreGlobalShortcut } from '@/utils/findingTime';

describe('finding timestamps', () => {
  it('promotes unix seconds to ms and keeps ms as-is', () => {
    expect(parseFindingTimestamp(1_700_000_000)).toBe(1_700_000_000_000);
    expect(parseFindingTimestamp(1_700_000_000_000)).toBe(1_700_000_000_000);
    expect(parseFindingTimestamp('not-a-date')).toBe(0);
  });
});

describe('coverage clamp', () => {
  it('keeps the bar inside 0-100', () => {
    expect(clampPercent(140)).toBe(100);
    expect(clampPercent(-4)).toBe(0);
    expect(clampPercent(Number.NaN)).toBe(0);
  });
});

describe('global shortcuts', () => {
  it('ignores keys while a modal dialog is open', () => {
    const dialog = document.createElement('div');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    document.body.appendChild(dialog);
    expect(shouldIgnoreGlobalShortcut(document.body)).toBe(true);
    dialog.remove();
    expect(shouldIgnoreGlobalShortcut(document.body)).toBe(false);
  });
});
