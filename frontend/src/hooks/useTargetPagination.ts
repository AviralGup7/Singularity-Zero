import { useState, useMemo } from 'react';
import { clampFindingsPage } from '@/features/findings/findingsViewMode';

export const PAGE_SIZE = 10;

export function resolveTargetPageCount(total: number, pageSize = PAGE_SIZE): number {
  const size = Number.isFinite(pageSize) && pageSize > 0 ? pageSize : PAGE_SIZE;
  const count = Number.isFinite(total) ? Math.max(0, total) : 0;
  return Math.max(1, Math.ceil(count / size));
}

export function useTargetPagination(total: number, pageSize = PAGE_SIZE) {
  const [currentPage, setCurrentPage] = useState(1);
  const totalPages = resolveTargetPageCount(total, pageSize);
  const safePage = clampFindingsPage(currentPage, totalPages);

  const paginated = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return { start, end: start + pageSize };
  }, [safePage, pageSize]);

  return { currentPage: safePage, setCurrentPage, totalPages, paginated };
}
