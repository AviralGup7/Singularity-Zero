import { describe, expect, it } from 'vitest';
import { deepMergeSettings, pickPreferredFilter } from '@/stores/settingsHydrate';
import { formatFindingDate } from '@/lib/utils';

describe('settings hydrate', () => {
  it('keeps default feature flags when a partial blob is imported', () => {
    const merged = deepMergeSettings(
      { features: { threatIntel: true, reconDetails: false }, language: 'en' },
      { features: { reconDetails: true } },
    );
    expect(merged.features.threatIntel).toBe(true);
    expect(merged.features.reconDetails).toBe(true);
    expect(merged.language).toBe('en');
  });

  it('lets a shared jobs URL win over a stale persisted filter', () => {
    expect(pickPreferredFilter('failed', 'running')).toBe('failed');
    expect(pickPreferredFilter(null, 'running')).toBe('running');
  });
});

describe('finding date format', () => {
  it('does not treat unix seconds as 1970', () => {
    const label = formatFindingDate(1_700_000_000);
    expect(label).not.toBe('—');
    expect(label.includes('1970')).toBe(false);
  });
});
