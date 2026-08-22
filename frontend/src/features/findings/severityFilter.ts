export const FINDING_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export function sanitizeSeverityFilters(values: Iterable<string>): FindingSeverity[] {
  const allowed = new Set<string>(FINDING_SEVERITIES);
  const next: FindingSeverity[] = [];
  for (const value of values) {
    const normalized = value.trim().toLowerCase();
    if (allowed.has(normalized) && !next.includes(normalized as FindingSeverity)) {
      next.push(normalized as FindingSeverity);
    }
  }
  return next;
}
