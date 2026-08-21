import { describe, expect, it } from 'vitest';
import { shouldEnableSse, shouldEnableWs } from '@/hooks/realtimeTransport';
import { unreadAfterMarkRead, visibleFindingIds } from '@/features/notifications/unread';
import { keyForFinding } from '@/pages/scanDiffModel';

describe('auto transport', () => {
  it('keeps websocket closed while SSE is healthy', () => {
    expect(shouldEnableSse('auto')).toBe(true);
    expect(shouldEnableWs('auto', 'connected')).toBe(false);
    expect(shouldEnableWs('auto', 'failed')).toBe(true);
    expect(shouldEnableWs('ws', 'connected')).toBe(true);
  });
});

describe('notification unread', () => {
  it('does not decrement when marking an already-read item', () => {
    expect(unreadAfterMarkRead(false, 3)).toBe(3);
    expect(unreadAfterMarkRead(true, 3)).toBe(2);
  });
});

describe('new findings holdback', () => {
  it('hides pending ids until the operator loads them', () => {
    expect(visibleFindingIds(['a', 'b', 'c'], ['b'])).toEqual(['a', 'c']);
    expect(visibleFindingIds(['a', 'b'], [])).toEqual(['a', 'b']);
  });
});

describe('run diff key', () => {
  it('includes id so two XSS findings do not collapse', () => {
    const a = keyForFinding({ id: '1', type: 'xss', target: 't', severity: 'high' } as never);
    const b = keyForFinding({ id: '2', type: 'xss', target: 't', severity: 'high' } as never);
    expect(a).not.toBe(b);
  });
});
