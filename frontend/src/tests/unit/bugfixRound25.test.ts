import { describe, expect, it } from 'vitest';
import { targetMatchesScanWindow } from '@/hooks/useTargetFilters';
import { jobsListIsFiltered } from '@/pages/jobsFilters';
import { normalizeCvss, normalizeEpss, getFindingBounty } from '@/features/findings/findingMetrics';
import { NotificationDigest } from '@/utils/notificationDigest';
import { parseInAppNotifications } from '@/utils/notifications';
import type { Finding } from '@/types/api';

describe('target scan window', () => {
  it('excludes undated targets from a scanned-after filter', () => {
    expect(targetMatchesScanWindow(undefined, '2024-01-01', '')).toBe(false);
    expect(targetMatchesScanWindow('2024-06-01', '2024-01-01', '')).toBe(true);
    expect(targetMatchesScanWindow('2023-01-01', '2024-01-01', '')).toBe(false);
  });
});

describe('jobs empty copy', () => {
  it('uses the effective URL search, not a stale persisted blank', () => {
    expect(jobsListIsFiltered('all', 'xss')).toBe(true);
    expect(jobsListIsFiltered('all', '  ')).toBe(false);
    expect(jobsListIsFiltered('failed', '')).toBe(true);
  });
});

describe('finding metrics', () => {
  it('clamps NaN CVSS/EPSS/bounty instead of painting NaN', () => {
    expect(normalizeCvss(Number.NaN)).toBe(0);
    expect(normalizeCvss(12)).toBe(10);
    expect(normalizeEpss(42)).toBe(0.42);
    expect(getFindingBounty({ bounty_value: Number.NaN } as Finding)).toBe(0);
  });
});

describe('notification digest', () => {
  it('flushes immediately when digesting is disabled', () => {
    const flushed: unknown[] = [];
    const digest = new NotificationDigest({
      enabled: false,
      onFlush: (items) => { flushed.push(...items); },
    });
    digest.add({ id: '1', type: 'info', message: 'hi', timestamp: Date.now() });
    expect(flushed).toHaveLength(1);
  });
});

describe('in-app notification store', () => {
  it('ignores a non-array blob', () => {
    expect(parseInAppNotifications('{"id":"x"}')).toEqual([]);
    expect(parseInAppNotifications('[{"id":"n1"}]')).toHaveLength(1);
  });
});
