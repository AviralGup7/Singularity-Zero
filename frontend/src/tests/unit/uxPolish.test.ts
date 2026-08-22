import { describe, expect, it } from 'vitest';
import { isNavPathActive } from '@/utils/navActive';

describe('navigation active state', () => {
  it('treats dashboard as exact-only so it does not light up every page', () => {
    expect(isNavPathActive('/', '/')).toBe(true);
    expect(isNavPathActive('/jobs', '/')).toBe(false);
  });

  it('keeps nested job and finding routes marked active', () => {
    expect(isNavPathActive('/jobs/abc', '/jobs')).toBe(true);
    expect(isNavPathActive('/findings', '/findings')).toBe(true);
    expect(isNavPathActive('/risk/acceptance', '/risk')).toBe(true);
    expect(isNavPathActive('/risk-score', '/risk')).toBe(false);
  });
});
