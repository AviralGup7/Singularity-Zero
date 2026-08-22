import { describe, expect, it } from 'vitest';
import { asReportList, getCompliancePdfUrl } from '@/api/reports';
import { asRiskHistory } from '@/api/risk';
import { asSearchResults, sanitizeSearchQuery } from '@/api/search';

describe('report library', () => {
  it('treats a missing reports array as empty', () => {
    expect(asReportList({ reports: [] })).toEqual([]);
    expect(asReportList([{ target: 'a' }])).toHaveLength(1);
  });
});

describe('risk history', () => {
  it('treats a missing history array as empty', () => {
    expect(asRiskHistory(null)).toEqual([]);
    expect(asRiskHistory([{ target_id: 't' }])).toHaveLength(1);
  });
});

describe('search results', () => {
  it('ignores a non-array results payload', () => {
    expect(asSearchResults({ results: [] })).toEqual([]);
    expect(asSearchResults([{ id: '1', type: 'job', title: 'x' }])).toHaveLength(1);
  });
});

describe('search query', () => {
  it('does not call search with a blank query', () => {
    expect(sanitizeSearchQuery('   ')).toBe('');
    expect(sanitizeSearchQuery(' xss ')).toBe('xss');
  });
});

describe('compliance pdf', () => {
  it('does not emit a target-less PDF url', () => {
    expect(getCompliancePdfUrl('  ')).toBe('');
    expect(getCompliancePdfUrl('app.test')).toContain('target=app.test');
  });
});
