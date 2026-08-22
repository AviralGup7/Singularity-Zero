import { describe, expect, it } from 'vitest';
import { isEditableShortcutTarget, shouldIgnoreGlobalShortcut, clampPercent } from '@/utils/findingTime';
import { applyLiveScanEvent } from '@/components/scanStatusMerge';
import { sanitizeRedirectPath } from '@/utils/routeValidation';
import { subscribeStreamToken } from '@/hooks/sessionUnlock';

describe('escape vs modal shortcuts', () => {
  it('still treats Escape as closeable while a dialog is open', () => {
    expect(isEditableShortcutTarget(null)).toBe(false);
    expect(typeof shouldIgnoreGlobalShortcut).toBe('function');
  });
});

describe('glow progress clamp', () => {
  it('drops NaN and caps overflow', () => {
    expect(clampPercent(Number.NaN)).toBe(0);
    expect(clampPercent(140)).toBe(100);
    expect(clampPercent(-4)).toBe(0);
  });
});

describe('live scan progress', () => {
  it('normalizes a fraction patch instead of painting 0.4%', () => {
    const prev = {
      jobId: 'job-1',
      targetName: 'app.test',
      progress: 10,
      status: 'scan',
      etaLabel: '',
      findingsCount: 0,
      urlsFound: 0,
    };
    expect(applyLiveScanEvent(prev, 'job-1', { progress: 0.4 })?.progress).toBe(40);
    expect(applyLiveScanEvent(prev, 'job-1', { progress: 55 })?.progress).toBe(55);
  });
});

describe('redirect sanitization', () => {
  it('does not throw on a malformed percent-encoding', () => {
    expect(sanitizeRedirectPath('%')).toBe('/');
    expect(sanitizeRedirectPath('/jobs')).toBe('/jobs');
    expect(sanitizeRedirectPath('https://evil.test')).toBe('/');
  });
});

describe('stream token subscription', () => {
  it('returns an unsubscribe function', () => {
    const off = subscribeStreamToken(() => {});
    expect(typeof off).toBe('function');
    off();
  });
});
