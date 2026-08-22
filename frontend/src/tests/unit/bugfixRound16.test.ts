import { describe, expect, it } from 'vitest';
import { keyForFinding } from '@/pages/scanDiffModel';
import { pickPreferredFilter } from '@/stores/settingsHydrate';
import type { Finding } from '@/types/api';

function finding(partial: Partial<Finding>): Finding {
  return {
    id: '',
    type: 'xss',
    title: 't',
    description: 'd',
    severity: 'high',
    confidence: 1,
    timestamp: 1,
    lifecycle_state: 'detected',
    target: 'app.test',
    ...partial,
  };
}

describe('anonymous diff keys', () => {
  it('does not collapse two id-less findings with different titles', () => {
    const a = keyForFinding(finding({ title: 'one' }));
    const b = keyForFinding(finding({ title: 'two' }));
    expect(a).not.toBe(b);
  });
});

describe('url vs stored filters', () => {
  it('treats an explicit empty query as a clear, not a miss', () => {
    expect(pickPreferredFilter('', 'old')).toBe('');
    expect(pickPreferredFilter(null, 'old')).toBe('old');
    expect(pickPreferredFilter('xss', 'old')).toBe('xss');
  });
});
