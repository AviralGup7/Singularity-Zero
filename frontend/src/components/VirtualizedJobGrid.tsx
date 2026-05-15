import { memo } from 'react';
import { List, useListRef, type RowComponentProps } from 'react-window';
import type { Job } from '../types/api';

interface VirtualizedJobGridProps {
  jobs: Job[];
  renderItem: (job: Job) => React.ReactNode;
  itemHeight?: number;
  itemsPerRow?: number;
  gap?: number;
}

const ROW_HEIGHT = 280;
const ITEMS_PER_ROW = 2;

interface RowData {
  jobs: Job[];
  renderItem: (job: Job) => React.ReactNode;
  itemsPerRow: number;
  itemHeight: number;
  gap: number;
}

function GridRow(props: RowComponentProps<RowData>) {
  const { index, style, jobs, renderItem, itemsPerRow, itemHeight, gap } = props;
  const startIdx = index * itemsPerRow;
  const rowItems = jobs.slice(startIdx, startIdx + itemsPerRow);

  return (
    <div
      style={{
        ...style,
        display: 'grid',
        gridTemplateColumns: `repeat(${itemsPerRow}, 1fr)`,
        gap: `${gap}px`,
        paddingRight: '8px',
      }}
    >
      {rowItems.map((job) => (
        <div key={job.id} style={{ minHeight: itemHeight }}>
          {renderItem(job)}
        </div>
      ))}
    </div>
  );
}

const VirtualizedJobGrid = memo(function VirtualizedJobGrid({
  jobs,
  renderItem,
  itemHeight = ROW_HEIGHT,
  itemsPerRow = ITEMS_PER_ROW,
  gap = 16,
}: VirtualizedJobGridProps) {
  const listRef = useListRef(null);
  const rowCount = jobs.length > 0 ? Math.ceil(jobs.length / itemsPerRow) : 0;
  const listHeight = Math.min(800, rowCount * (itemHeight + gap));

  if (jobs.length === 0) return null;

  const rowData: RowData = { jobs, renderItem, itemsPerRow, itemHeight, gap };

  return (
    <div style={{ height: listHeight, width: '100%' }}>
      <List<RowData>
        listRef={listRef}
        rowCount={rowCount}
        rowHeight={itemHeight + gap}
        defaultHeight={listHeight}
        rowProps={rowData}
        rowComponent={GridRow}
      />
    </div>
  );
});

export default VirtualizedJobGrid;
