export const FINDINGS_VIEW_MODES = ['grid', 'table', 'kanban'] as const;
export type FindingsViewMode = (typeof FINDINGS_VIEW_MODES)[number];

export function normalizeFindingsViewMode(value: unknown): FindingsViewMode {
  return FINDINGS_VIEW_MODES.includes(value as FindingsViewMode) ? (value as FindingsViewMode) : 'grid';
}

export function clampFindingsPage(page: number, totalPages: number): number {
  const safeTotal = Math.max(1, totalPages);
  if (!Number.isFinite(page)) return 1;
  return Math.min(Math.max(1, Math.trunc(page)), safeTotal);
}
