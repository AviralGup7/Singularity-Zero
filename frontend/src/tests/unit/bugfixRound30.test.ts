import { describe, expect, it } from 'vitest';
import { classifyAgainstScope, parseScopeText, scopeHost } from '@/utils/scopeParser';
import { deepMergeSettings } from '@/stores/settingsHydrate';
import { formatErrorDetail } from '@/utils/extractErrorMessage';
import { validateEvidenceId } from '@/utils/routeValidation';

describe('scope host matching', () => {
  it('matches a URL-shaped scope entry against a hostname', () => {
    expect(scopeHost('https://admin.example.com/path')).toBe('admin.example.com');
    const scope = parseScopeText('https://example.com/admin');
    expect(classifyAgainstScope('example.com', scope).status).toBe('in_scope');
  });
});

describe('settings merge', () => {
  it('ignores prototype-polluting keys', () => {
    const merged = deepMergeSettings({ theme: 'dark' }, { __proto__: { hacked: true }, theme: 'light' } as never);
    expect(merged.theme).toBe('light');
    expect(Object.prototype.hasOwnProperty.call(merged, 'hacked')).toBe(false);
  });
});

describe('nested validation errors', () => {
  it('reads FastAPI detail arrays from axios-shaped errors', async () => {
    const { extractErrorMessage } = await import('@/utils/extractErrorMessage');
    expect(extractErrorMessage({
      response: { data: { detail: [{ msg: 'target is required' }] } },
    })).toBe('target is required');
  });
});

describe('error detail arrays', () => {
  it('joins FastAPI validation details', () => {
    expect(formatErrorDetail([{ msg: 'field required' }, { msg: 'invalid url' }])).toBe('field required; invalid url');
  });
});

describe('evidence ids', () => {
  it('accepts numeric evidence ids', () => {
    expect(validateEvidenceId('42')).toBe('42');
    expect(validateEvidenceId('../x')).toBeNull();
  });
});
