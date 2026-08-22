import { describe, expect, it } from 'vitest';
import { settingsScopeKey } from '@/stores/settingsStore';
import { parseWorkflowMode } from '@/stores/displayStore';
import { capTail, jobBufferCaps } from '@/stores/jobStore';
import { emitNotification } from '@/lib/events';

describe('store audit leftovers', () => {
  it('treats missing user and missing tenant as distinct settings scopes', () => {
    expect(settingsScopeKey(undefined)).toBe('anon');
    expect(settingsScopeKey({})).toBe('session');
    expect(settingsScopeKey({ tenantId: 'acme' })).toBe('acme');
  });

  it('reads both raw and JSON workflow mode values', () => {
    expect(parseWorkflowMode('pentest')).toBe('pentest');
    expect(parseWorkflowMode('"appsec"')).toBe('appsec');
    expect(parseWorkflowMode('nope')).toBeNull();
  });

  it('caps findings/log tails without throwing on missing arrays', () => {
    expect(capTail(undefined, 3)).toEqual([]);
    expect(capTail([1, 2, 3, 4], 2)).toEqual([3, 4]);
    expect(jobBufferCaps(true).maxFindings).toBe(2500);
  });

  it('normalizes spoofed notification payloads', () => {
    let seen: { message: string; type: string } | null = null;
    const handler = (e: Event) => {
      seen = (e as CustomEvent<{ message: string; type: string }>).detail;
    };
    window.addEventListener('notification:add', handler);
    emitNotification({ message: 'ok', type: 'info' });
    window.removeEventListener('notification:add', handler);
    expect(seen).toEqual({ message: 'ok', type: 'info' });
  });
});
