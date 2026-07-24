import { memo } from 'react';
import { VirtuosoGrid } from 'react-virtuoso';
import type { Job } from '../../types/api';

interface VirtualizedJobGridProps {
  jobs: Job[];
  renderItem: (job: Job) => React.ReactNode;
  itemHeight?: number;
}

const ROW_HEIGHT = 280;

const gridComponents = {
  List: memo(function GridList({ children, ...props }: React.HTMLProps<HTMLDivElement>) {
    return (
      <div {...props} className="grid grid-cols-1 md:grid-cols-2 gap-4" role="grid" aria-label="Jobs grid">
        {children}
      </div>
    );
  }),
  Item: memo(function GridItem({ children, ...props }: React.HTMLProps<HTMLDivElement>) {
    return <div {...props} role="gridcell">{children}</div>;
  }),
};

const VirtualizedJobGrid = memo(function VirtualizedJobGrid({
  jobs,
  renderItem,
}: VirtualizedJobGridProps) {
  if (jobs.length === 0) return null;

  return (
    <VirtuosoGrid
      totalCount={jobs.length}
      overscan={200}
      className="scrollbar-cyber"
      components={gridComponents}
      itemContent={(index) => renderItem(jobs[index])}
      style={{ height: Math.min(800, Math.ceil(jobs.length / 2) * (ROW_HEIGHT + 16)) }}
    />
  );
});

export default VirtualizedJobGrid;
