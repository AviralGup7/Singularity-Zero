import { useApi } from './useApi';
import type { FindingTimelineEvent } from '@/types/extended';

export interface FindingsTimelineFilters {
  jobId?: string;
  severity?: string;
  target?: string;
  startDate?: string;
  endDate?: string;
  limit: number;
  offset: number;
}

export function useFindingsTimeline(filters: FindingsTimelineFilters) {
  const params = {
    job_id: filters.jobId || undefined,
    severity: filters.severity || undefined,
    target: filters.target || undefined,
    start_date: filters.startDate || undefined,
    end_date: filters.endDate || undefined,
    limit: filters.limit,
    offset: filters.offset,
  };

  const result = useApi<FindingTimelineEvent[]>('/api/findings/timeline', {
    params,
    bypassCache: true,
  });

  return {
    ...result,
    events: result.data ?? [],
    hasMore: (result.data?.length ?? 0) >= filters.limit,
  };
}
