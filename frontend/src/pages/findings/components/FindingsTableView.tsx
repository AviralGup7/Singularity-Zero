import type { Finding } from '@/types/api';
import { Pagination } from '@/components/ui/Pagination';
import { CopyButton } from '@/components/CopyButton';
import { formatFindingDate } from '@/lib/utils';

type SortKey = 'severity' | 'type' | 'target' | 'status' | 'date';
type SortDir = 'asc' | 'desc';

interface FindingsTableViewProps {
  paginated: Finding[];
  filtered: Finding[];
  page: number;
  pageSize: number;
  sortKey: SortKey;
  sortDir: SortDir;
  selectedIds: Set<string>;
  expandedDuplicates: Set<string>;
  allOnPageSelected: boolean;
  uniqueAssignees: string[];
  handleSort: (key: SortKey) => void;
  toggleRow: (id: string) => void;
  togglePage: () => void;
  selectAll: () => void;
  clearSelection: () => void;
  onPageChange: (p: number) => void;
  toggleDuplicateExpand: (id: string) => void;
  getDuplicateById: (id: string) => Finding | undefined;
  handleAssign: (findingId: string, assignee: string) => void;
  setFpDialogFinding: (finding: Finding | null) => void;
  setFpReviewDialog: (finding: Finding | null) => void;
  handleOpenDetail: (finding: Finding) => void;
  hashToColor: (str: string) => string;
  getInitials: (name: string) => string;
}

export function FindingsTableView({
  paginated,
  filtered,
  page,
  pageSize,
  sortKey,
  sortDir,
  selectedIds,
  expandedDuplicates,
  allOnPageSelected,
  uniqueAssignees,
  handleSort,
  toggleRow,
  togglePage,
  selectAll,
  clearSelection,
  onPageChange,
  toggleDuplicateExpand,
  getDuplicateById,
  handleAssign,
  setFpDialogFinding,
  setFpReviewDialog,
  handleOpenDetail,
  hashToColor,
  getInitials,
}: FindingsTableViewProps) {
  return (
    <>
      {selectedIds.size > 0 && (
        <div className="bulk-action-bar">
          <div className="bulk-action-info">
            <input
              type="checkbox"
              checked={allOnPageSelected}
              onChange={togglePage}
              aria-label="Select all on page"
            />
            <span>{selectedIds.size} selected</span>
            {selectedIds.size < filtered.length && (
              <button className="bulk-select-all-btn" onClick={selectAll}>
                Select all {filtered.length}
              </button>
            )}
            <button className="bulk-clear-btn" onClick={clearSelection}>
              Clear selection
            </button>
          </div>
          <div className="bulk-actions">
          {/* Bulk action buttons removed — handlers not yet implemented */}
          <span className="bulk-actions-placeholder">Bulk actions coming soon</span>
        </div>
        </div>
      )}

      <div className="table-container table-responsive" role="region" aria-label="Findings table">
        <table className="findings-table" role="table">
          <thead>
            <tr>
              <th scope="col" className="bulk-select-col">
                <input
                  type="checkbox"
                  checked={allOnPageSelected}
                  onChange={togglePage}
                  aria-label="Select all on page"
                />
              </th>
              <th scope="col" className="col-id">ID</th>
              <th scope="col">
                <button className="sort-btn" onClick={() => handleSort('severity')} aria-label={`Sort by severity, currently ${sortDir}`}>
                  Severity
                  {sortKey === 'severity' && <span className="sort-indicator">{sortDir === 'asc' ? '↑' : '↓'}</span>}
                </button>
              </th>
              <th scope="col">
                <button className="sort-btn" onClick={() => handleSort('type')} aria-label={`Sort by type, currently ${sortDir}`}>
                  Type
                  {sortKey === 'type' && <span className="sort-indicator">{sortDir === 'asc' ? '↑' : '↓'}</span>}
                </button>
              </th>
              <th scope="col">
                <button className="sort-btn" onClick={() => handleSort('target')} aria-label={`Sort by target, currently ${sortDir}`}>
                  Target
                  {sortKey === 'target' && <span className="sort-indicator">{sortDir === 'asc' ? '↑' : '↓'}</span>}
                </button>
              </th>
              <th scope="col">
                <button className="sort-btn" onClick={() => handleSort('status')} aria-label={`Sort by status, currently ${sortDir}`}>
                  Status
                  {sortKey === 'status' && <span className="sort-indicator">{sortDir === 'asc' ? '↑' : '↓'}</span>}
                </button>
              </th>
              <th scope="col">Lifecycle</th>
              <th scope="col">
                <button className="sort-btn" onClick={() => handleSort('date')} aria-label={`Sort by date, currently ${sortDir}`}>
                  Date
                  {sortKey === 'date' && <span className="sort-indicator">{sortDir === 'asc' ? '↑' : '↓'}</span>}
                </button>
              </th>
              <th scope="col">Assignee</th>
              <th scope="col">FP Status</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginated.map((finding, idx) => {
              const dupCount = (finding.duplicates || []).length;
              const isFP = finding.falsePositive;
              return (
                <tr
                  key={finding.id || idx}
                  className={`finding-row-clickable ${isFP ? 'row-false-positive' : ''} ${selectedIds.has(finding.id) ? 'row-selected' : ''}`}
                  onClick={() => handleOpenDetail(finding)}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleOpenDetail(finding); } }}
                  tabIndex={0}
                  role="link"
                  aria-label={`View details for ${finding.title}`}
                >
                  <td className="bulk-select-col" onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(finding.id)}
                      onChange={() => toggleRow(finding.id)}
                      aria-label={`Select ${finding.type || 'finding'}`}
                    />
                  </td>
                  <td className="finding-id-cell">
                    <span className="finding-id-text" title={finding.id}>{finding.id}</span>
                    <CopyButton text={finding.id} />
                  </td>
                  <td>
                    <span className={`severity-badge sev-${finding.severity}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="finding-type">
                    {isFP ? <s>{finding.type || '—'}</s> : (finding.type || '—')}
                    {dupCount > 0 && (
                      <button
                        className="dup-badge"
                        onClick={e => { e.stopPropagation(); toggleDuplicateExpand(finding.id); }}
                      >
                        {dupCount} dup{dupCount > 1 ? 's' : ''}
                      </button>
                    )}
                  </td>
                  <td className="finding-target" title={finding.target}>
                    <span className="target-text">{isFP ? <s>{finding.target || '—'}</s> : (finding.target || '—')}</span>
                    <CopyButton text={finding.target || ''} />
                  </td>
                  <td>
                    <span className={`status-badge status-${finding.status}`}>
                      {finding.status}
                    </span>
                  </td>
                  <td>
                    <span className="lifecycle-badge">
                      {finding.lifecycle_state || 'detected'}
                    </span>
                  </td>
                  <td className="finding-date">{formatFindingDate(finding.timestamp)}</td>
                  <td className="finding-assignee">
                    {finding.assignedTo ? (
                      <span className="assignee-cell">
                        <span
                          className="assignee-avatar assignee-avatar-small"
                          style={{ backgroundColor: hashToColor(finding.assignedTo) }}
                        >
                          {getInitials(finding.assignedTo)}
                        </span>
                        {finding.assignedTo}
                      </span>
                    ) : (
                      <span className="unassigned">Unassigned</span>
                    )}
                  </td>
                  <td className="finding-fp-status">
                    {finding.fpStatus && finding.fpStatus !== 'none' ? (
                      <span className={`fp-status-badge fp-${finding.fpStatus}`}>
                        {finding.fpStatus}
                      </span>
                    ) : isFP ? (
                      <span className="fp-status-badge fp-marked">FP</span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="finding-actions" onClick={e => e.stopPropagation()}>
                    <select
                      className="assign-select-small"
                      value={finding.assignedTo || ''}
                      onChange={e => handleAssign(finding.id, e.target.value)}
                    >
                      <option value="">Assign...</option>
                      {uniqueAssignees.map(a => <option key={a} value={a}>{a}</option>)}
                      {!uniqueAssignees.includes('Analyst 1') && <option value="Analyst 1">Analyst 1</option>}
                      {!uniqueAssignees.includes('Analyst 2') && <option value="Analyst 2">Analyst 2</option>}
                      {!uniqueAssignees.includes('Reviewer') && <option value="Reviewer">Reviewer</option>}
                    </select>
                    {!isFP && (
                      <button
                        className="fp-mark-btn-small"
                        onClick={() => setFpDialogFinding(finding)}
                      >
                        Mark FP
                      </button>
                    )}
                    {finding.fpStatus === 'pending' && (
                      <button
                        className="fp-review-btn-small"
                        onClick={() => setFpReviewDialog(finding)}
                      >
                        Review
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {paginated.some(f => (f.duplicates || []).length > 0) && (
        <div className="expanded-duplicates-section">
          {paginated.filter(f => (f.duplicates || []).length > 0 && expandedDuplicates.has(f.id)).map(finding => (
            <div key={finding.id} className="dup-group">
              <div className="dup-group-header">
                <strong>{finding.type}</strong> on <strong>{finding.target}</strong>
                <span className="dup-group-count">{(finding.duplicates || []).length} duplicates</span>
              </div>
              <div className="dup-group-list">
                {(finding.duplicates || []).map(did => {
                  const dup = getDuplicateById(did);
                  return dup ? (
                    <div key={dup.id} className="dup-row">
                      <span className={`severity-badge sev-${dup.severity}`}>{dup.severity}</span>
                      <span className="dup-type">{dup.type}</span>
                      <span className="dup-target">{dup.target}</span>
                      <span className="dup-date">{formatFindingDate(dup.timestamp)}</span>
                    </div>
                  ) : null;
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      <Pagination
        page={page}
        total={filtered.length}
        pageSize={pageSize}
        onPageChange={onPageChange}
      />
    </>
  );
}
