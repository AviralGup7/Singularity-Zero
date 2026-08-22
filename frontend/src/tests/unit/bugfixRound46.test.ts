import { describe, expect, it } from 'vitest';
import { normalizeNotes } from '@/api/notes';
import { asTargetList, compareTargets } from '@/api/targets';

describe('notes payload', () => {
  it('maps note_id and ignores a non-array blob', () => {
    expect(normalizeNotes({ notes: [] })).toEqual([]);
    expect(normalizeNotes([{ note_id: 12 }])[0]?.id).toBe('12');
  });
});

describe('targets list', () => {
  it('treats a missing targets array as empty', () => {
    expect(asTargetList({ targets: [] })).toEqual([]);
    expect(asTargetList([{ name: 'app.test' }])).toHaveLength(1);
  });
});

describe('target findings', () => {
  it('treats a missing findings array as empty', async () => {
    const { asTargetFindings } = await import('@/api/targets');
    expect(asTargetFindings(null)).toEqual([]);
  });
});

describe('note ids', () => {
  it('keeps a string id when already present', () => {
    expect(normalizeNotes([{ id: 'abc' }])[0]?.id).toBe('abc');
  });
});

describe('target compare', () => {
  it('refuses a blank pair', async () => {
    await expect(compareTargets(' ', 'b')).rejects.toThrow(/required/i);
  });
});
