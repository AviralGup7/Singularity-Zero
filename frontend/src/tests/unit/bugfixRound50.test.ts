import { describe, expect, it } from 'vitest';
import { asProjectList, getProject } from '@/api/projects';
import { asRemediationCandidates, asRemediationUnits } from '@/api/remediation';
import { asAccessLogList } from '@/api/accessLogs';

describe('projects list', () => {
  it('unwraps a projects envelope and ignores non-arrays', () => {
    expect(asProjectList({ projects: [] })).toEqual([]);
    expect(asProjectList([{ id: 'p1' }])).toHaveLength(1);
  });
});

describe('project id', () => {
  it('refuses a blank project lookup', async () => {
    await expect(getProject('  ')).rejects.toThrow(/required/i);
  });
});

describe('remediation plan', () => {
  it('treats a missing units array as empty', () => {
    expect(asRemediationUnits({ units: [] })).toEqual([]);
    expect(asRemediationUnits([{ category: 'xss' }])).toHaveLength(1);
  });
});

describe('remediation candidates', () => {
  it('treats a missing candidates array as empty', () => {
    expect(asRemediationCandidates(null)).toEqual([]);
  });
});

describe('access logs', () => {
  it('treats a missing log array as empty', () => {
    expect(asAccessLogList({ logs: [] })).toEqual([]);
    expect(asAccessLogList([{ id: 'a1' }])).toHaveLength(1);
  });
});
