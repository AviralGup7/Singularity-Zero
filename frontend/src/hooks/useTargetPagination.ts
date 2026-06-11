import { useState, useMemo } from 'react';

export const PAGE_SIZE = 10;

export function useTargetPagination(total: number, pageSize = PAGE_SIZE) {
  const [currentPage, setCurrentPage] = useState(1);
  const totalPages = Math.ceil(total / pageSize);

  const paginated = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return { start, end: start + pageSize };
  }, [currentPage, pageSize]);

  return { currentPage, setCurrentPage, totalPages, paginated };
}
