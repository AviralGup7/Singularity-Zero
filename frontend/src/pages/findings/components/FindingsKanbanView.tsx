import type { Finding } from '../../../types/api';
import { formatFindingDate } from '../../../lib/utils';

type KanbanColumn = 'new' | 'in-progress' | 'resolved';

interface FindingsKanbanViewProps {
  kanbanFindings: Record<KanbanColumn, Finding[]>;
  uniqueAssignees: string[];
  handleDragStart: (finding: Finding) => void;
  handleDragOver: (e: React.DragEvent) => void;
  handleDrop: (column: KanbanColumn) => void;
  handleAssign: (findingId: string, assignee: string) => void;
  toggleDuplicateExpand: (id: string) => void;
  getDuplicateById: (id: string) => Finding | undefined;
  expandedDuplicates: Set<string>;
  setFpDialogFinding: (finding: Finding | null) => void;
  setFpReviewDialog: (finding: Finding | null) => void;
  hashToColor: (str: string) => string;
  getInitials: (name: string) => string;
}

const KANBAN_COLUMNS: { key: KanbanColumn; label: string }[] = [
  { key: 'new', label: 'New' },
  { key: 'in-progress', label: 'In Progress' },
  { key: 'resolved', label: 'Resolved' },
];

export function FindingsKanbanView({
  kanbanFindings,
  uniqueAssignees,
  handleDragStart,
  handleDragOver,
  handleDrop,
  handleAssign,
  toggleDuplicateExpand,
  getDuplicateById,
  expandedDuplicates,
  setFpDialogFinding,
  setFpReviewDialog,
  hashToColor,
  getInitials,
}: FindingsKanbanViewProps) {
  return (
    <div className="kanban-board">
      {KANBAN_COLUMNS.map(col => (
        <div
          key={col.key}
          className="kanban-column"
          onDragOver={handleDragOver}
          onDrop={() => handleDrop(col.key)}
        >
          <div className="kanban-column-header">
            <span className="kanban-column-title">{col.label}</span>
  // eslint-disable-next-line security/detect-object-injection
            <span className="kanban-column-count">{kanbanFindings[col.key].length}</span>
          </div>
          <div className="kanban-cards">
  // eslint-disable-next-line security/detect-object-injection
            {kanbanFindings[col.key].map(finding => {
              const dupCount = (finding.duplicates || []).length;
              const isFP = finding.falsePositive;
              const fpStatusBadge = finding.fpStatus && finding.fpStatus !== 'none'
                ? <span className={`fp-status-badge fp-${finding.fpStatus}`}>{finding.fpStatus}</span>
                : null;
              return (
                <div
                  key={finding.id}
                  className={`kanban-card ${isFP ? 'kanban-card-fp' : ''}`}
                  draggable
                  onDragStart={() => handleDragStart(finding)}
                >
                  <div className="kanban-card-header">
                    <span className={`severity-badge sev-${finding.severity}`}>
                      {finding.severity}
                    </span>
                    {fpStatusBadge}
                  </div>
                  <div className="kanban-card-type">{finding.type || '—'}</div>
                  <div className="kanban-card-target" title={finding.target}>{finding.target || '—'}</div>
                  <div className="kanban-card-date">{formatFindingDate(finding.timestamp)}</div>
                  {finding.assignedTo && (
                    <div className="kanban-card-assignee" title={finding.assignedTo}>
                      <span
                        className="assignee-avatar"
                        style={{ backgroundColor: hashToColor(finding.assignedTo) }}
                      >
                        {getInitials(finding.assignedTo)}
                      </span>
                    </div>
                  )}
                  {dupCount > 0 && (
                    <button
                      className="dup-badge-btn"
                      onClick={() => toggleDuplicateExpand(finding.id)}
                    >
                      {dupCount} duplicate{dupCount > 1 ? 's' : ''}
                    </button>
                  )}
                  {expandedDuplicates.has(finding.id) && finding.duplicates && finding.duplicates.length > 0 && (
                    <div className="dup-list">
                      {finding.duplicates.map(did => {
                        const dup = getDuplicateById(did);
                        return dup ? (
                          <div key={did} className="dup-item">
                            <span className={`severity-badge sev-${dup.severity}`}>{dup.severity}</span>
                            <span className="dup-id">{dup.id}</span>
                          </div>
                        ) : null;
                      })}
                    </div>
                  )}
                  <div className="kanban-card-actions">
                    <select
                      className="assign-select"
                      value={finding.assignedTo || ''}
                      onChange={e => handleAssign(finding.id, e.target.value)}
                    >
                      <option value="">Assign to...</option>
                      {uniqueAssignees.map(a => <option key={a} value={a}>{a}</option>)}
                      {!uniqueAssignees.includes('Analyst 1') && <option value="Analyst 1">Analyst 1</option>}
                      {!uniqueAssignees.includes('Analyst 2') && <option value="Analyst 2">Analyst 2</option>}
                      {!uniqueAssignees.includes('Reviewer') && <option value="Reviewer">Reviewer</option>}
                    </select>
                    {!isFP && (
                      <button
                        className="fp-mark-btn"
                        onClick={() => setFpDialogFinding(finding)}
                      >
                        Mark FP
                      </button>
                    )}
                    {finding.fpStatus === 'pending' && (
                      <button
                        className="fp-review-btn"
                        onClick={() => setFpReviewDialog(finding)}
                      >
                        Review FP
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
