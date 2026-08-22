import { describe, expect, it } from 'vitest';
import { notificationDelivery } from '@/utils/notifications';
import { confidencePercent } from '@/utils/normalizeScale';
import { normalizePresetName, parseSavedFilterPresets } from '@/hooks/useSavedFilterPresets';
import { asSanitizableHtml } from '@/utils/sanitizeContent';

describe('in-app notification fanout', () => {
  it('still delivers in-app when OS push permission is granted', () => {
    expect(notificationDelivery('granted')).toEqual({ inApp: true, push: true });
    expect(notificationDelivery('denied')).toEqual({ inApp: true, push: false });
  });
});

describe('export confidence', () => {
  it('does not turn an already-percent score into 8500%', () => {
    expect(confidencePercent(85)).toBe(85);
    expect(confidencePercent(0.85)).toBe(85);
  });
});

describe('saved filter presets', () => {
  it('ignores a corrupt non-array payload', () => {
    expect(parseSavedFilterPresets('{"id":"x"}')).toEqual([]);
    expect(parseSavedFilterPresets('[{"id":"p1","name":"XSS","filters":{},"createdAt":"t"}]')).toHaveLength(1);
  });

  it('refuses blank preset names', () => {
    expect(normalizePresetName('   ')).toBeNull();
    expect(normalizePresetName('  XSS  ')).toBe('XSS');
  });
});

describe('html sanitizer input', () => {
  it('treats non-strings as empty instead of throwing', () => {
    expect(asSanitizableHtml(undefined)).toBe('');
    expect(asSanitizableHtml(null)).toBe('');
    expect(asSanitizableHtml('<b>ok</b>')).toBe('<b>ok</b>');
  });
});
