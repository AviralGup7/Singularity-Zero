import { describe, expect, it } from 'vitest';
import { getEPSSLabel, normalizeCweId, shouldCacheCveLookup } from '@/utils/threatIntelligence';
import { itemsKey } from '@/hooks/useCommandPaletteItems';
import { shouldRestartPausedPoll } from '@/utils/visibilityManager';

describe('cwe ids', () => {
  it('rejects unsanitized CWE tokens', () => {
    expect(normalizeCweId('CWE-79')).toBe('CWE-79');
    expect(normalizeCweId('CWE-79<script>')).toBeNull();
  });
});

describe('epss label', () => {
  it('treats NaN as unavailable', () => {
    expect(getEPSSLabel(Number.NaN)).toBe('N/A');
    expect(getEPSSLabel(0.6)).toBe('Very High');
  });
});

describe('cve cache', () => {
  it('does not persist a placeholder miss as a hit', () => {
    expect(shouldCacheCveLookup(false)).toBe(false);
    expect(shouldCacheCveLookup(true)).toBe(true);
  });
});

describe('command palette keys', () => {
  it('drops blank ids so cleanup cannot unregister everything', () => {
    expect(itemsKey([{ id: 'a' }, { id: '' }, { id: 'b' }])).toBe('a,b');
  });
});

describe('visibility polls', () => {
  it('restarts paused intervals instead of dropping them', () => {
    expect(shouldRestartPausedPoll(3000)).toBe(true);
    expect(shouldRestartPausedPoll(0)).toBe(false);
  });
});
