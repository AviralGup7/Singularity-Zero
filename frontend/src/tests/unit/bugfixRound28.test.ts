import { describe, expect, it } from 'vitest';
import { bountyDelta, nextScanDiffSearch } from '@/pages/scanDiffModel';
import { parseRetryAfter } from '@/features/bridge/retry';
import { validateUrl } from '@/lib/utils';
import { csvEscape } from '@/utils/exporters';
import type { Finding } from '@/types/api';

describe('scan diff query', () => {
  it('drops unknown filter tokens instead of writing them to the URL', () => {
    const next = nextScanDiffSearch(new URLSearchParams('foo=1'), 'wat', 'a', 'b');
    const params = new URLSearchParams(next);
    expect(params.get('filter')).toBeNull();
    expect(params.get('runA')).toBe('a');
  });
});

describe('bounty delta', () => {
  it('ignores NaN bounty values', () => {
    const delta = bountyDelta([{ bounty_value: Number.NaN } as Finding, { bounty_value: 200 } as Finding]);
    expect(delta.count).toBe(1);
    expect(delta.max).toBe(200);
  });
});

describe('retry-after', () => {
  it('parses HTTP-date headers into a capped wait', () => {
    const now = Date.parse('Wed, 21 Oct 2015 07:28:00 GMT');
    const header = 'Wed, 21 Oct 2015 07:28:30 GMT';
    expect(parseRetryAfter(header, now)).toBe(30);
    expect(parseRetryAfter('12')).toBe(12);
  });
});

describe('url validation', () => {
  it('does not throw on an unparseable host', () => {
    expect(validateUrl('https://exa mple.com').valid).toBe(false);
  });
});

describe('csv formula injection', () => {
  it('neutralizes formula-prefixed cells', () => {
    expect(csvEscape('=cmd|calc')).toBe("'=cmd|calc");
    expect(csvEscape('plain')).toBe('plain');
  });
});
