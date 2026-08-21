export const JOB_STATUS_FILTERS = ['all', 'running', 'completed', 'failed', 'stopped'] as const;
export type JobStatusFilter = (typeof JOB_STATUS_FILTERS)[number];

export function normalizeJobStatusFilter(value: unknown): JobStatusFilter {
  return JOB_STATUS_FILTERS.includes(value as JobStatusFilter) ? (value as JobStatusFilter) : 'all';
}
