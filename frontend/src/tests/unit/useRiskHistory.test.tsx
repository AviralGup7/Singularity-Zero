import { renderHook } from '@testing-library/react';
import { describe, expect, it, vi, afterEach } from 'vitest';
import { buildRiskDateColumns, useRiskHistory } from '@/hooks/useRiskHistory';
import type { RiskHistoryEntry } from '@/types/extended';

const mocks = vi.hoisted(() => ({
  useApi: vi.fn(),
}));

vi.mock('@/hooks/useApi', () => ({
  useApi: mocks.useApi,
}));

const entries: RiskHistoryEntry[] = [
  {
    target_id: 'api.example.com',
    target: 'api.example.com',
    csi_value: 7.2,
    timestamp: '2026-05-01T12:00:00Z',
    severity_breakdown: { critical: 1, high: 2, medium: 3, low: 0, info: 0 },
    factors: { cvss: 8, confidence: 7, exploitability: 7.5, mesh_consensus: 6 },
    top_findings: [],
  },
  {
    target_id: 'portal.example.com',
    target: 'portal.example.com',
    csi_value: 4.1,
    timestamp: '2026-05-02T12:00:00Z',
    severity_breakdown: { critical: 0, high: 1, medium: 2, low: 4, info: 1 },
    factors: { cvss: 5, confidence: 6, exploitability: 4, mesh_consensus: 4 },
    top_findings: [],
  },
];

describe('useRiskHistory', () => {
  afterEach(() => {
    mocks.useApi.mockReset();
  });

  it('filters history by selected targets and date range', () => {
    mocks.useApi.mockImplementation((url: string) => ({
      data: url === '/api/risk/history' ? entries : { weights: {}, factors: [] },
      loading: false,
      error: null,
      refetch: vi.fn(),
      isStale: false,
    }));

    const { result } = renderHook(() => useRiskHistory({
      days: 30,
   
      targetIds: ['portal.example.com'],
      startDate: '2026-05-02',
      endDate: '2026-05-03',
    }));

    expect(result.current.history).toHaveLength(1);
   
    expect(result.current.history[0].target_id).toBe('portal.example.com');
  });

  it('builds sorted date columns from history entries', () => {
   
    expect(buildRiskDateColumns(entries)).toEqual(['2026-05-01', '2026-05-02']);
  });
});
