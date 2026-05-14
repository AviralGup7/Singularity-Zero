import type { Finding } from '../../../types/api';

interface FindingsBulkActionBarProps {
  selectedIds: Set<string>;
  bulkActionMode: string | null;
  bulkAssignee: string;
  allOnPageSelected: boolean;
  filteredCount: number;
  paginated: Finding[];
  setBulkActionMode: (mode: string | null) => void;
  setBulkAssignee: (name: string) => void;
  togglePage: () => void;
  selectAll: () => void;
  clearSelection: () => void;
  handleBulkStatus: (status: 'open' | 'closed' | 'accepted') => void;
  handleBulkFalsePositive: () => void;
  handleBulkAssign: () => void;
  handleBulkDelete: () => void;
}

export function FindingsBulkActionBar({
  selectedIds,
  bulkActionMode,
  bulkAssignee,
  allOnPageSelected,
  filteredCount,
  setBulkActionMode,
  setBulkAssignee,
  togglePage,
  selectAll,
  clearSelection,
  handleBulkStatus,
  handleBulkFalsePositive,
  handleBulkAssign,
  handleBulkDelete,
}: FindingsBulkActionBarProps) {
  if (selectedIds.size === 0) return null;

  return (
    <div className="bulk-action-bar">
      <div className="bulk-action-info">
        <input
          type="checkbox"
          checked={allOnPageSelected}
          onChange={togglePage}
          aria-label="Select all on page"
        />
        <span>{selectedIds.size} selected</span>
        {selectedIds.size < filteredCount && (
          <button className="bulk-select-all-btn" onClick={selectAll}>
            Select all {filteredCount}
          </button>
        )}
        <button className="bulk-clear-btn" onClick={clearSelection}>
          Clear selection
        </button>
      </div>
      <div className="bulk-actions">
        {bulkActionMode === 'status' ? (
          <div className="bulk-action-group">
            <button className="bulk-btn" onClick={() => handleBulkStatus('open')}>New</button>
            <button className="bulk-btn" onClick={() => handleBulkStatus('accepted')}>In Progress</button>
            <button className="bulk-btn" onClick={() => handleBulkStatus('closed')}>Resolved</button>
            <button className="bulk-btn bulk-cancel" onClick={() => setBulkActionMode(null)}>Cancel</button>
          </div>
        ) : bulkActionMode === 'assign' ? (
          <div className="bulk-action-group bulk-assign-group">
            <input
              type="text"
              placeholder="Enter assignee name..."
              value={bulkAssignee}
              onChange={e => setBulkAssignee(e.target.value)}
              className="bulk-assign-input"
            />
            <button
              className="bulk-btn"
              disabled={!bulkAssignee.trim()}
              onClick={handleBulkAssign}
            >
              Assign
            </button>
            <button className="bulk-btn bulk-cancel" onClick={() => { setBulkActionMode(null); setBulkAssignee(''); }}>Cancel</button>
          </div>
        ) : (
          <>
            <div className="bulk-action-group">
              <span className="bulk-action-label">Status:</span>
              <button className="bulk-btn" onClick={() => setBulkActionMode('status')}>Change Status</button>
            </div>
            <div className="bulk-action-group">
              <button className="bulk-btn bulk-btn-warning" onClick={handleBulkFalsePositive}>
                Mark as False Positive
              </button>
            </div>
            <div className="bulk-action-group">
              <button className="bulk-btn" onClick={() => setBulkActionMode('assign')}>
                Assign to...
              </button>
            </div>
            <div className="bulk-action-group">
              <button className="bulk-btn bulk-btn-danger" onClick={handleBulkDelete}>
                Delete
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
