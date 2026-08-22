import { describe, expect, it } from 'vitest';
import { computeDuplicateKey, dedupeFindings } from '@/features/findings/hooks/useFindingsTable';
import { shortcutGlyph, userInitials } from '@/utils/userChrome';
import type { Finding } from '@/types/api';

function finding(partial: Partial<Finding> & Pick<Finding, 'id'>): Finding {
  return {
    type: 'xss',
    title: 't',
    description: 'd',
    severity: 'high',
    confidence: 1,
    timestamp: 1,
    lifecycle_state: 'detected',
    target: 'https://app.test',
    ...partial,
  };
}

describe('dedupe without evidence', () => {
  it('does not collapse distinct findings that share type and target', () => {
    const a = finding({ id: 'a' });
    const b = finding({ id: 'b' });
    expect(computeDuplicateKey(a)).not.toBe(computeDuplicateKey(b));
    expect(dedupeFindings([a, b])).toHaveLength(2);
  });
});

describe('user chrome', () => {
  it('builds initials and a non-Mac shortcut label', () => {
    expect(userInitials('  ')).toBe('A');
    expect(userInitials('Ada Lovelace')).toBe('AL');
    expect(shortcutGlyph('Win32')).toBe('Ctrl+K');
    expect(shortcutGlyph('MacIntel')).toBe('⌘ K');
  });
});
