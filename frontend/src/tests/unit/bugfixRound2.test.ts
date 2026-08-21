import { describe, expect, it } from 'vitest';
import { nextExpandedSections } from '@/components/targets/reconSections';
import { normalizeJobStatusFilter } from '@/pages/jobsFilters';
import { getFindingBounty, getFindingCvss } from '@/features/findings/findingMetrics';
import { buildFailedBulkAction } from '@/features/findings/bulkRetry';
import { clampFindingsPage } from '@/features/findings/findingsViewMode';
import type { Finding } from '@/types/api';

function finding(partial: Partial<Finding>): Finding {
  return {
    id: 'f1',
    type: 'xss',
    title: 't',
    description: 'd',
    severity: 'info',
    confidence: 1,
    timestamp: 1,
    lifecycle_state: 'detected',
    ...partial,
  };
}

describe('recon section expand', () => {
  it('sets open/closed instead of flipping the current set', () => {
    const open = nextExpandedSections(['subdomains'], 'subdomains', true);
    expect([...open]).toEqual(['subdomains']);
    const closed = nextExpandedSections(open, 'subdomains', false);
    expect(closed.has('subdomains')).toBe(false);
    const urls = nextExpandedSections(closed, 'urls', true);
    expect(urls.has('urls')).toBe(true);
  });
});

describe('jobs filters and paging', () => {
  it('rejects unknown persisted status values', () => {
    expect(normalizeJobStatusFilter('running')).toBe('running');
    expect(normalizeJobStatusFilter('nope')).toBe('all');
  });

  it('clamps an oversized jobs page', () => {
    expect(clampFindingsPage(9, 2)).toBe(2);
  });
});

describe('finding metrics', () => {
  it('keeps a real CVSS 0 instead of treating it as missing', () => {
    expect(getFindingCvss(finding({ cvss_score: 0 }))).toBe(0);
    expect(getFindingCvss(finding({ cvss_v4_score: 9.1 }))).toBe(9.1);
    expect(getFindingBounty(finding({ bounty_value: 0 }))).toBe(0);
  });
});

describe('bulk retry payload', () => {
  it('preserves the original assign payload instead of rewriting to closed', () => {
    const failed = buildFailedBulkAction(['a'], { assignedTo: 'Analyst 1' }, 'assigned', 'Bulk assign');
    expect(failed.data).toEqual({ assignedTo: 'Analyst 1' });
    expect(failed.data.status).toBeUndefined();
  });
});
