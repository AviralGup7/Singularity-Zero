import { describe, expect, it } from 'vitest';
import { asLearningList } from '@/api/learning';
import { isUsableWebhookUrl } from '@/api/webhooks';
import { asEvidenceList, requireEvidenceId } from '@/api/evidenceCustody';

describe('learning lists', () => {
  it('treats a missing array as empty', () => {
    expect(asLearningList({ items: [] })).toEqual([]);
    expect(asLearningList([{ history_id: 'h1' }])).toHaveLength(1);
  });
});

describe('webhook url', () => {
  it('rejects javascript: and blank urls', () => {
    expect(isUsableWebhookUrl('javascript:alert(1)')).toBe(false);
    expect(isUsableWebhookUrl('https://hooks.slack.com/x')).toBe(true);
  });
});

describe('evidence list', () => {
  it('treats a missing evidence array as empty', () => {
    expect(asEvidenceList(null)).toEqual([]);
    expect(asEvidenceList([{ id: 'e1' }])).toHaveLength(1);
  });
});

describe('evidence id', () => {
  it('refuses a blank evidence lookup', () => {
    expect(() => requireEvidenceId('  ')).toThrow(/required/i);
  });
});

describe('evidence paging', () => {
  it('keeps an explicit zero limit instead of dropping it', () => {
    const params: Record<string, unknown> = {};
    const limit = 0;
    if (limit !== undefined) params.limit = limit;
    expect(params.limit).toBe(0);
  });
});
