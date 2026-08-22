import { describe, expect, it } from 'vitest';
import { normalizeJobStatusFilter } from '@/pages/jobsFilters';
import { normalizeAutoLogoutMinutes } from '@/hooks/sessionUnlock';

describe('job status filter', () => {
  it('accepts mixed-case status values', () => {
    expect(normalizeJobStatusFilter('FAILED')).toBe('failed');
    expect(normalizeJobStatusFilter(' Running ')).toBe('running');
    expect(normalizeJobStatusFilter('nope')).toBe('all');
  });
});

describe('auto logout minutes', () => {
  it('clamps invalid settings to a safe window', () => {
    expect(normalizeAutoLogoutMinutes(Number.NaN)).toBe(0);
    expect(normalizeAutoLogoutMinutes(-5)).toBe(0);
    expect(normalizeAutoLogoutMinutes(9999)).toBe(480);
    expect(normalizeAutoLogoutMinutes(15.9)).toBe(15);
  });
});
