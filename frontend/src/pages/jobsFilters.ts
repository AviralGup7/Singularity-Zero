export const JOB_STATUS_FILTERS = ['all', 'running', 'completed', 'failed', 'stopped'] as const;
export type JobStatusFilter = (typeof JOB_STATUS_FILTERS)[number];

export function normalizeJobStatusFilter(value: unknown): JobStatusFilter {
  const normalized = String(value ?? '').trim().toLowerCase();
  return JOB_STATUS_FILTERS.includes(normalized as JobStatusFilter) ? (normalized as JobStatusFilter) : 'all';
}

export function jobsListIsFiltered(status: string, query: string): boolean {
  return status !== 'all' || query.trim().length > 0;
}
