import { memo, useEffect, useState } from 'react';
import { VirtuosoGrid } from 'react-virtuoso';
import type { Job } from '../../types/api';

interface VirtualizedJobGridProps {
  jobs: Job[];
  renderItem: (job: Job) => React.ReactNode;
  itemHeight?: number;
}

const DEFAULT_ROW_HEIGHT = 280;
const MD_BREAKPOINT = '(min-width: 768px)';

function useJobGridColumns(): number {
  const [columns, setColumns] = useState(() =>
    typeof window !== 'undefined' && window.matchMedia(MD_BREAKPOINT).matches ? 2 : 1,
  );

  useEffect(() => {
    const media = window.matchMedia(MD_BREAKPOINT);
    const sync = () => setColumns(media.matches ? 2 : 1);
    sync();
    media.addEventListener('change', sync);
    return () => media.removeEventListener('change', sync);
  }, []);

  return columns;
}

const gridComponents = {
  List: memo(function GridList({ children, ...props }: React.HTMLProps<HTMLDivElement>) {
    return (
      <div {...props} className="grid grid-cols-1 md:grid-cols-2 gap-4" role="grid" aria-label="Jobs grid">
        {children}
      </div>
    );
  }),
  Item: memo(function GridItem({ children, ...props }: React.HTMLProps<HTMLDivElement>) {
    return (
      <div {...props} role="row">
        <div role="gridcell">{children}</div>
      </div>
    );
  }),
};

const VirtualizedJobGrid = memo(function VirtualizedJobGrid({
  jobs,
  renderItem,
  itemHeight = DEFAULT_ROW_HEIGHT,
}: VirtualizedJobGridProps) {
  const columns = useJobGridColumns();
  const rowHeight = itemHeight > 0 ? itemHeight : DEFAULT_ROW_HEIGHT;

  if (jobs.length === 0) return null;

  return (
    <VirtuosoGrid
      totalCount={jobs.length}
      overscan={200}
      className="scrollbar-cyber"
      components={gridComponents}
      itemContent={(index) => renderItem(jobs[index])}
      style={{ height: Math.min(800, Math.ceil(jobs.length / columns) * (rowHeight + 16)) }}
    />
  );
});

export default VirtualizedJobGrid;
