import { renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useFindingsTimeline } from '@/hooks/useFindingsTimeline';

const mocks = vi.hoisted(() => ({
  useApi: vi.fn(),
}));

vi.mock('@/hooks/useApi', () => ({
  useApi: mocks.useApi,
}));

describe('useFindingsTimeline', () => {
  afterEach(() => {
    mocks.useApi.mockReset();
  });

  it('passes timeline filters as API query parameters', () => {
    mocks.useApi.mockReturnValue({
   
      data: [{ id: 'one' }, { id: 'two' }],
      loading: false,
      error: null,
      refetch: vi.fn(),
      isStale: false,
    });

    const { result } = renderHook(() => useFindingsTimeline({
      jobId: 'job-1',
      severity: 'high',
      target: 'api.example.com',
      startDate: '2026-05-01',
      endDate: '2026-05-10',
      limit: 2,
      offset: 4,
    }));

    expect(mocks.useApi).toHaveBeenCalledWith('/api/findings/timeline', {
      params: {
        job_id: 'job-1',
        severity: 'high',
        target: 'api.example.com',
        start_date: '2026-05-01',
        end_date: '2026-05-10',
        limit: 2,
        offset: 4,
      },
      bypassCache: true,
    });
    expect(result.current.events).toHaveLength(2);
    expect(result.current.hasMore).toBe(true);
  });
});
