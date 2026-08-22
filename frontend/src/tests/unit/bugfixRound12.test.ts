import { describe, expect, it } from 'vitest';
import { resolveEffectiveTransport, sanitizeLiveStatus, shouldEnableWs } from '@/hooks/realtimeTransport';
import { applyFilterPreset } from '@/features/findings/filterPreset';
import { parsePersistedValue } from '@/hooks/persistedValue';

describe('auto websocket fallback', () => {
  it('does not open websocket while SSE is merely closed/idle', () => {
    expect(shouldEnableWs('auto', 'closed')).toBe(false);
    expect(shouldEnableWs('auto', 'failed')).toBe(true);
    expect(resolveEffectiveTransport('auto', 'failed')).toBe('ws');
  });
});

describe('live scan status', () => {
  it('ignores transport event names as operator labels', () => {
    expect(sanitizeLiveStatus('progress_update')).toBeUndefined();
    expect(sanitizeLiveStatus('analysis')).toBe('analysis');
  });
});

describe('filter presets', () => {
  it('clears search when the preset explicitly sets an empty search', () => {
    const next = applyFilterPreset({ search: 'xss', severity: ['high'] }, { search: '', severity: 'critical' });
    expect(next.search).toBe('');
    expect(next.severity).toEqual(['critical']);
  });
});

describe('persisted values', () => {
  it('keeps a legacy raw string instead of wiping it', () => {
    expect(parsePersistedValue('running', 'all')).toBe('running');
    expect(parsePersistedValue('"kanban"', 'grid')).toBe('kanban');
  });
});
