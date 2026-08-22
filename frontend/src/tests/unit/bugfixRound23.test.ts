import { describe, expect, it } from 'vitest';
import { formatRelativeDistance } from '@/utils/time';
import { displayNumericOrNA } from '@/utils/displayValue';
import { formatBytes } from '@/lib/utils';
import { shouldCloseFindingDetail } from '@/features/findings/components/FindingDetailPanel/helpers';
import { tenantStorageAdapter } from '@/utils/tenantStorage';

describe('relative time', () => {
  it('does not print a negative "ago" for future timestamps', () => {
    expect(formatRelativeDistance(-30_000)).toBe('in a moment');
    expect(formatRelativeDistance(-1_000)).toBe('just now');
    expect(formatRelativeDistance(12_000)).toBe('12 sec ago');
  });
});

describe('numeric display', () => {
  it('treats whitespace-only values as missing', () => {
    expect(displayNumericOrNA('   ')).toBe('N/A');
    expect(displayNumericOrNA(0)).toBe('0');
  });
});

describe('byte formatting', () => {
  it('does not emit NaN units for invalid sizes', () => {
    expect(formatBytes(Number.NaN)).toBe('0 B');
    expect(formatBytes(-12)).toBe('0 B');
    expect(formatBytes(1024)).toBe('1 KB');
  });
});

describe('finding detail escape', () => {
  it('keeps the parent open while a nested submit dialog is up', () => {
    expect(shouldCloseFindingDetail('Escape', true)).toBe(false);
    expect(shouldCloseFindingDetail('Escape', false)).toBe(true);
    expect(shouldCloseFindingDetail('Enter', false)).toBe(false);
  });
});

describe('tenant storage adapter', () => {
  it('reads and writes without touching raw localStorage throws', () => {
    tenantStorageAdapter.setItem('round23-probe', '{"ok":true}');
    expect(tenantStorageAdapter.getItem('round23-probe')).toContain('ok');
    tenantStorageAdapter.removeItem('round23-probe');
    expect(tenantStorageAdapter.getItem('round23-probe')).toBeNull();
  });
});
