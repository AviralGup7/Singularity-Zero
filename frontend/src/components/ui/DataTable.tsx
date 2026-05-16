import { useState, useCallback, useMemo } from 'react';
import { cn } from '@/lib/utils';
import { Skeleton } from './Skeleton';

export interface Column<T> {
  key: keyof T & string;
  header: string;
  render?: (item: T) => React.ReactNode;
  sortable?: boolean;
  className?: string;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  pageSize?: number;
  emptyMessage?: string;
  className?: string;
  getRowKey: (item: T) => string;
  onRowClick?: (item: T) => void;
}

type SortDirection = 'asc' | 'desc' | null;

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  loading = false,
  pageSize = 10,
  emptyMessage = 'No data available',
  className,
  getRowKey,
  onRowClick,
}: DataTableProps<T>) {
   
  const [sortKey, setSortKey] = useState<string | null>(null);
   
  const [sortDirection, setSortDirection] = useState<SortDirection>(null);
   
  const [currentPage, setCurrentPage] = useState(1);

  const handleSort = useCallback(
    (key: string) => {
      if (sortKey === key) {
        setSortDirection((prev) => (prev === 'asc' ? 'desc' : prev === 'desc' ? null : 'asc'));
        if (sortDirection === 'desc') setSortKey(null);
      } else {
        setSortKey(key);
        setSortDirection('asc');
      }
      setCurrentPage(1);
    },
   
    [sortKey, sortDirection]
  );

  const sortedData = useMemo(() => {
    if (!sortKey || !sortDirection) return data;

    const col = columns.find((c) => c.key === sortKey);
    if (!col) return data;

   
    return [...data].sort((a, b) => {
   
      const aVal = a[sortKey as keyof T];
   
      const bVal = b[sortKey as keyof T];

      if (aVal == null && bVal == null) return 0;
      if (aVal == null) return sortDirection === 'asc' ? -1 : 1;
      if (bVal == null) return sortDirection === 'asc' ? 1 : -1;

      const comparison =
        typeof aVal === 'string'
          ? aVal.localeCompare(bVal as string)
          : (aVal as number) - (bVal as number);

      return sortDirection === 'asc' ? comparison : -comparison;
    });
   
  }, [data, sortKey, sortDirection, columns]);

  const totalPages = Math.max(1, Math.ceil(sortedData.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const paginatedData = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return sortedData.slice(start, start + pageSize);
   
  }, [sortedData, safePage, pageSize]);

  if (loading) {
    return (
      <div className={cn('w-full', className)} role="status" aria-live="polite" aria-label="Loading table data">
        <Skeleton variant="table" lines={5} />
      </div>
    );
  }

  if (sortedData.length === 0) {
    return (
      <div
        className={cn(
   
          'w-full border border-[var(--line)] bg-[var(--panel)] p-8 text-center text-[var(--muted)] font-mono',
          className
        )}
        role="status"
      >
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className={cn('w-full', className)}>
      <div className="overflow-x-auto border border-[var(--line)] bg-[var(--panel)]">
        <table className="w-full text-[length:var(--text-sm)] font-mono">
          <thead className="bg-[var(--table-header-bg)] border-b border-[var(--line)]">
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={cn(
   
                    'px-3 py-2 text-left text-[var(--muted)] uppercase tracking-wider',
   
                    col.sortable && 'cursor-pointer select-none hover:text-[var(--accent)]',
                    col.className
                  )}
                  onClick={col.sortable ? () => handleSort(col.key) : undefined}
                  aria-sort={
                    sortKey === col.key
                      ? sortDirection === 'asc'
                        ? 'ascending'
                        : sortDirection === 'desc'
                          ? 'descending'
                          : 'none'
                      : undefined
                  }
                >
                  <span className="inline-flex items-center gap-1">
                    {col.header}
                    {col.sortable && sortKey === col.key && (
                      <span aria-hidden="true">{sortDirection === 'asc' ? '↑' : sortDirection === 'desc' ? '↓' : '↕'}</span>
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paginatedData.map((item) => {
              const key = getRowKey(item);
              return (
                <tr
                  key={key}
                  className={cn(
   
                    'border-b border-[var(--line)] transition-colors hover:bg-[var(--table-row-hover)]',
                    onRowClick && 'cursor-pointer'
                  )}
                  onClick={onRowClick ? () => onRowClick(item) : undefined}
                >
                  {columns.map((col) => (
   
                    <td key={col.key} className={cn('px-3 py-2 text-[var(--text)]', col.className)}>
                      {col.render ? col.render(item) : (item[col.key as keyof T] as React.ReactNode)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
   
        <div className="flex items-center justify-between px-2 py-2 text-[length:var(--text-xs)] font-mono text-[var(--muted)]">
          <span>Page {safePage} of {totalPages}</span>
          <span>({sortedData.length} items)</span>
          <div className="flex items-center gap-1">
            <button
   
              className="px-2 py-1 border border-[var(--line)] bg-transparent text-[var(--text)] hover:bg-[var(--hover-bg)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={safePage <= 1}
              aria-label="Previous page"
            >
              ←
            </button>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
              <button
                key={page}
                className={cn(
   
                  'px-2 py-1 border border-[var(--line)] transition-colors',
                  page === safePage
   
                    ? 'bg-[var(--accent)] text-[var(--bg)] border-[var(--accent)]'
   
                    : 'bg-transparent text-[var(--text)] hover:bg-[var(--hover-bg)]'
                )}
                onClick={() => setCurrentPage(page)}
                aria-label={`Page ${page}`}
                aria-current={page === safePage ? 'page' : undefined}
              >
                {page}
              </button>
            ))}
            <button
   
              className="px-2 py-1 border border-[var(--line)] bg-transparent text-[var(--text)] hover:bg-[var(--hover-bg)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={safePage >= totalPages}
              aria-label="Next page"
            >
              →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
