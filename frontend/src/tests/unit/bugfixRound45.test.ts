import { describe, expect, it } from 'vitest';
import { asFindingList, asTimelineEvents, getFindingById } from '@/api/findings';
import { normalizeLanguage } from '@/components/LanguageSelector';

describe('findings list', () => {
  it('treats a missing findings array as empty', () => {
    expect(asFindingList({ findings: [] })).toEqual([]);
    expect(asFindingList([{ id: 'f1' }])).toHaveLength(1);
  });
});

describe('timeline events', () => {
  it('ignores a non-array events payload', () => {
    expect(asTimelineEvents({ events: [] })).toEqual([]);
    expect(asTimelineEvents([{ id: 'e1' }])).toHaveLength(1);
  });
});

describe('language', () => {
  it('falls back when the stored locale is unknown', () => {
    expect(normalizeLanguage('en-US')).toBe('en');
    expect(normalizeLanguage('xx-pirate')).toBe('en');
  });
});

describe('bulk update', () => {
  it('treats a non-array bulk response as empty', () => {
    expect(asFindingList(null)).toEqual([]);
  });
});

describe('finding id', () => {
  it('refuses a blank finding lookup', async () => {
    await expect(getFindingById('   ')).rejects.toThrow(/required/i);
  });
});
