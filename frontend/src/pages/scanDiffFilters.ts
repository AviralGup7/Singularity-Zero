export const SCAN_DIFF_FILTERS = ['all', 'new', 'removed', 'changed', 'bounty_high'] as const;
export type ScanDiffFilter = (typeof SCAN_DIFF_FILTERS)[number];

export function normalizeScanDiffFilter(value: string | null | undefined): ScanDiffFilter {
  return SCAN_DIFF_FILTERS.includes(value as ScanDiffFilter) ? (value as ScanDiffFilter) : 'all';
}

export function collectFindingIds(items: Array<{ id?: string }>): string[] {
  return items.map((item) => item.id).filter((id): id is string => Boolean(id && id.trim()));
}
