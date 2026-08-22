import { describe, expect, it } from 'vitest';
import { collectFindingIds, normalizeScanDiffFilter } from '@/pages/scanDiffFilters';

describe('scan diff filters', () => {
  it('falls back to all for unknown filter tokens', () => {
    expect(normalizeScanDiffFilter('bounty_high')).toBe('bounty_high');
    expect(normalizeScanDiffFilter('wat')).toBe('all');
    expect(normalizeScanDiffFilter(null)).toBe('all');
  });

  it('refuses empty bulk id lists', () => {
    expect(collectFindingIds([{ id: '' }, { id: '  ' }, {}])).toEqual([]);
    expect(collectFindingIds([{ id: 'a' }, { id: 'b' }])).toEqual(['a', 'b']);
  });
});
