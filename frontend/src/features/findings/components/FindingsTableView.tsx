import type { Finding } from '@/types/api';
import { Pagination } from '@/components/ui/Pagination';
import { CopyButton } from '@/components/ui/CopyButton';
import { formatFindingDate } from '@/lib/utils';
import { FindingsBulkActionBar } from './FindingsBulkActionBar';

type SortKey = 'severity' | 'type' | 'target' | 'status' | 'date' | 'bounty_value';
type SortDir = 'asc' | 'desc';

const USD_FORMAT = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });

function SortHeader({
  label,
  column,
  sortKey,
  sortDir,
  onSort,
}: {
  label: string;
  column: SortKey;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (key: SortKey) => void;
}) {
  const active = sortKey === column;
  return (
    <th
      scope="col"
      className="sortable"
      aria-sort={active ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button type="button" onClick={() => onSort(column)}>
        {label} {active && <span>{sortDir === 'asc' ? '↑' : '↓'}</span>}
      </button>
    </th>
  );
}

function signalQualityFor(finding: Finding) {
  const quality =
    finding.signal_quality?.quality_score ??
    finding.signal_quality_score ??
    (typeof finding.true_positive_probability === 'number'
      ? finding.true_positive_probability * 100
      : finding.confidence * 100);
  const fpProbability =
    finding.signal_quality?.false_positive_probability ??
    finding.false_positive_probability ??
    Math.max(0, 1 - finding.confidence);
  const action = finding.signal_quality?.action || (fpProbability >= 0.5 ? 'review' : 'keep');
  const tier = fpProbability >= 0.7 ? 'noisy' : fpProbability >= 0.4 ? 'review' : 'clean';
  return {
    action,
    fpProbability,
    quality,
    tier,
  };
}

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
  bulkActionMode: string | null;
  bulkAssignee: string;
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
  setBulkActionMode: (mode: string | null) => void;
  setBulkAssignee: (name: string) => void;
  handleBulkStatus: (status: 'open' | 'closed' | 'accepted') => void;
  handleBulkFalsePositive: () => void;
  handleBulkAssign: () => void;
  handleBulkDelete: () => void;
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
  bulkActionMode,
  bulkAssignee,
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
  setBulkActionMode,
  setBulkAssignee,
  handleBulkStatus,
  handleBulkFalsePositive,
  handleBulkAssign,
  handleBulkDelete,
}: FindingsTableViewProps) {
  return (
    <>
      <FindingsBulkActionBar
        selectedIds={selectedIds}
        bulkActionMode={bulkActionMode}
        bulkAssignee={bulkAssignee}
        allOnPageSelected={allOnPageSelected}
        filteredCount={filtered.length}
        paginated={paginated}
        setBulkActionMode={setBulkActionMode}
        setBulkAssignee={setBulkAssignee}
        togglePage={togglePage}
        selectAll={selectAll}
        clearSelection={clearSelection}
        handleBulkStatus={handleBulkStatus}
        handleBulkFalsePositive={handleBulkFalsePositive}
        handleBulkAssign={handleBulkAssign}
        handleBulkDelete={handleBulkDelete}
      />
      <div className="findings-table-wrapper">
        <table className="findings-table">
          <caption className="sr-only">Findings list</caption>
          <thead>
            <tr>
              <th scope="col" className="col-checkbox">
                <input
                  type="checkbox"
                  checked={allOnPageSelected}
                  onChange={togglePage}
                  aria-label="Select all on page"
                />
              </th>
              <SortHeader label="Severity" column="severity" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <SortHeader label="Bounty" column="bounty_value" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <SortHeader label="Type" column="type" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <SortHeader label="Target" column="target" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <SortHeader label="Status" column="status" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <th scope="col">Lifecycle</th>
              <th scope="col">Signal</th>
              <SortHeader label="Date" column="date" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
              <th scope="col">Assignee</th>
              <th scope="col">FP</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginated.map(finding => {
              const signal = signalQualityFor(finding);
              const isFP = finding.falsePositive;
              const dupCount = (finding.duplicates || []).length;
              return (
                <tr
                  key={finding.id}
                  className={`finding-row ${isFP ? 'finding-row-fp' : ''}`}
                  onClick={() => handleOpenDetail(finding)}
                  tabIndex={0}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      handleOpenDetail(finding);
                    }
                  }}
                >
                  <td className="col-checkbox" onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(finding.id)}
                      onChange={() => toggleRow(finding.id)}
                      aria-label={`Select finding ${finding.id}`}
                    />
                  </td>
                  <td>
                    <span className={`severity-badge sev-${finding.severity}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="finding-bounty">
                    {typeof finding.bounty_value === 'number' && finding.bounty_value > 0 ? (
                      <span className="bounty-value">
                        {USD_FORMAT.format(finding.bounty_value)}
                        {finding.bounty_currency && finding.bounty_currency !== 'USD' && (
                          <span className="bounty-currency"> {finding.bounty_currency}</span>
                        )}
                      </span>
                    ) : (
                      <span className="bounty-empty" aria-label="No bounty estimate">—</span>
                    )}
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
                    <span className="target-text">
                      {isFP ? <s>{finding.target || '—'}</s> : (finding.target || '—')}
                    </span>
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
                  <td className="finding-signal-quality">
                    <span
                      className={`signal-quality-badge signal-${signal.tier}`}
                      title={`FP probability ${Math.round(signal.fpProbability * 100)}%`}
                    >
                      {Math.round(signal.quality)}%
                    </span>
                    <span className="signal-action">{signal.action.replace(/_/g, ' ')}</span>
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
                      aria-label={`Assign ${finding.id}`}
                    >
                      <option value="">Assign...</option>
                      {uniqueAssignees.map(a => <option key={a} value={a}>{a}</option>)}
                      {!uniqueAssignees.includes('Analyst 1') && <option value="Analyst 1">Analyst 1</option>}
                      {!uniqueAssignees.includes('Analyst 2') && <option value="Analyst 2">Analyst 2</option>}
                      {!uniqueAssignees.includes('Reviewer') && <option value="Reviewer">Reviewer</option>}
                    </select>
                    {!isFP && (
                      <button
                        type="button"
                        className="fp-mark-btn-small"
                        onClick={e => { e.stopPropagation(); setFpDialogFinding(finding); }}
                      >
                        Mark FP
                      </button>
                    )}
                    {finding.fpStatus === 'pending' && (
                      <button
                        type="button"
                        className="fp-review-btn-small"
                        onClick={e => { e.stopPropagation(); setFpReviewDialog(finding); }}
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
