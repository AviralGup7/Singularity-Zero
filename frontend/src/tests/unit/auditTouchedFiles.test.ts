import { describe, expect, it } from 'vitest';
import { canonicalizeFindingStatus, mapFindingUpdate } from '@/api/contract';
import { FindingSchema, FindingsListSchema, JobSchema } from '@/api/schemas';
import { userInitials } from '@/utils/userChrome';

describe('touched-file audit leftovers', () => {
  it('maps bulk delete and keeps unknown finding status visible', () => {
    expect(mapFindingUpdate({ _deleted: true, assignedTo: 'ada' })).toEqual({
      _deleted: true,
      assignee: 'ada',
    });
    expect(canonicalizeFindingStatus('needs-review')).toBe('needs-review');
    expect(canonicalizeFindingStatus('active')).toBe('open');
    expect(canonicalizeFindingStatus('')).toBe('open');
  });

  it('keeps FindingSchema and JobSchema as soft validators', () => {
    expect(FindingSchema.safeParse({ id: 'f1', severity: 'high' }).success).toBe(true);
    expect(FindingsListSchema.safeParse([{ id: 'f1', severity: 'low' }]).success).toBe(true);
    expect(JobSchema.safeParse({ id: 'j1', status: 'running' }).success).toBe(true);
  });

  it('falls back to a letter when the user name is empty', () => {
    expect(userInitials(undefined)).toBe('A');
    expect(userInitials('')).toBe('A');
  });
});
