import { describe, expect, it } from 'vitest';
import { sessionHasBearerToken } from '@/features/auth/session';
import { shouldEnableSessionLock } from '@/components/SessionGuard';
import { computeDuplicateKey, dedupeFindings } from '@/features/findings/hooks/useFindingsTable';
import { bucketKanbanFindings, resolveKanbanColumn } from '@/features/findings/components/FindingsKanbanView';
import { showErrorOverlay } from '@/utils/errorOverlay';
import { AppSettingsSchema } from '@/api/schemas';
import type { Finding } from '@/types/api';

function finding(partial: Partial<Finding> & Pick<Finding, 'id'>): Finding {
  return {
    type: 'xss',
    title: `Finding ${partial.id}`,
    description: 'desc',
    severity: 'high',
    confidence: 0.8,
    timestamp: 1_700_000_000,
    lifecycle_state: 'detected',
    target: 'https://app.test',
    status: 'open',
    ...partial,
  };
}

describe('session lock token gate', () => {
  it('never treats demo or guest as bearer sessions', () => {
    expect(sessionHasBearerToken('demo', 'token')).toBe(false);
    expect(sessionHasBearerToken('guest', 'token')).toBe(false);
    expect(sessionHasBearerToken('jwt', 'token')).toBe(true);
    expect(sessionHasBearerToken('jwt', '')).toBe(false);
  });

  it('enables lock only for token-backed users with auto-logout', () => {
    expect(shouldEnableSessionLock(true, 'jwt-token', 15)).toBe(true);
    expect(shouldEnableSessionLock(true, null, 15)).toBe(false);
    expect(shouldEnableSessionLock(true, 'jwt-token', 0)).toBe(false);
    expect(shouldEnableSessionLock(false, 'jwt-token', 15)).toBe(false);
  });
});

describe('findings dedupe', () => {
  it('collapses matching type, target, and evidence into a primary with duplicates', () => {
    const primary = finding({ id: 'a', evidence: { match: 'same' } });
    const duplicate = finding({ id: 'b', evidence: { match: 'same' } });
    const unique = finding({ id: 'c', type: 'sqli', evidence: { match: 'other' } });
    const result = dedupeFindings([primary, duplicate, unique]);
    expect(result).toHaveLength(2);
    expect(result[0].duplicates).toEqual(['b']);
    expect(result[1].id).toBe('c');
    expect(computeDuplicateKey(primary)).toBe(computeDuplicateKey(duplicate));
  });
});

describe('kanban column map', () => {
  it('maps explicit status first and falls back from finding fields', () => {
    expect(resolveKanbanColumn(finding({ id: '1', kanbanStatus: 'submitted' }))).toBe('submitted');
    expect(resolveKanbanColumn(finding({ id: '2', falsePositive: true }))).toBe('not_interested');
    expect(resolveKanbanColumn(finding({ id: '3', status: 'closed' }))).toBe('resolved');
    expect(resolveKanbanColumn(finding({ id: '4', already_reported: true }))).toBe('submitted');
    expect(resolveKanbanColumn(finding({ id: '5', lifecycle_state: 'reportable' }))).toBe('report_ready');
    expect(resolveKanbanColumn(finding({ id: '6', status: 'accepted' }))).toBe('in-progress');
    expect(resolveKanbanColumn(finding({ id: '7', fpStatus: 'pending' }))).toBe('needs_validation');
    expect(resolveKanbanColumn(finding({ id: '8' }))).toBe('new');
  });

  it('buckets findings into all seven columns', () => {
    const buckets = bucketKanbanFindings([
      finding({ id: 'n' }),
      finding({ id: 'v', fpStatus: 'pending' }),
      finding({ id: 'p', status: 'accepted' }),
      finding({ id: 'r', lifecycle_state: 'reportable' }),
      finding({ id: 's', already_reported: true }),
      finding({ id: 'd', status: 'closed' }),
      finding({ id: 'x', falsePositive: true }),
    ]);
    expect(Object.keys(buckets)).toEqual([
      'new',
      'needs_validation',
      'in-progress',
      'report_ready',
      'submitted',
      'resolved',
      'not_interested',
    ]);
    expect(buckets.new.map((item) => item.id)).toEqual(['n']);
    expect(buckets.needs_validation.map((item) => item.id)).toEqual(['v']);
    expect(buckets['in-progress'].map((item) => item.id)).toEqual(['p']);
    expect(buckets.report_ready.map((item) => item.id)).toEqual(['r']);
    expect(buckets.submitted.map((item) => item.id)).toEqual(['s']);
    expect(buckets.resolved.map((item) => item.id)).toEqual(['d']);
    expect(buckets.not_interested.map((item) => item.id)).toEqual(['x']);
  });
});

describe('error overlay export', () => {
  it('exports a callable overlay entry point', () => {
    expect(typeof showErrorOverlay).toBe('function');
  });
});

describe('optional features schema', () => {
  it('defaults client performance and recon details off', () => {
    const settings = AppSettingsSchema.parse({});
    expect(settings.features.clientPerformance).toBe(false);
    expect(settings.features.reconDetails).toBe(false);
    expect(settings.features.livePipelineStatus).toBe(false);
  });
});
