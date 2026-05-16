import { useState } from 'react';
import { getAuditLog, clearAuditLog, type AuditEntry } from '@/utils/auditLogger';

interface AuditLogViewerProps {
  className?: string;
}

export function AuditLogViewer({ className }: AuditLogViewerProps) {
  // FIX: Use lazy initializer to avoid ambiguity
   
  const [entries, setEntries] = useState<AuditEntry[]>(() => getAuditLog());
   
  const [filter, setFilter] = useState('');
   
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = entries.filter((e) => {
    if (!filter) return true;
    const f = filter.toLowerCase();
    return (
      e.action.toLowerCase().includes(f) ||
      e.user.toLowerCase().includes(f) ||
      e.page?.toLowerCase().includes(f)
    );
  });

  const handleClear = () => {
    clearAuditLog();
    setEntries([]);
    setExpandedId(null);
  };

  return (
    <div className={`audit-log-viewer ${className || ''}`}>
      <div className="audit-log-header">
        <h3>Audit Log ({entries.length} entries)</h3>
        <div className="audit-log-actions">
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter..."
            className="audit-log-filter"
          />
          <button onClick={handleClear} className="btn btn-sm btn-danger">Clear</button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="audit-log-empty">
          {entries.length === 0 ? 'No audit log entries.' : 'No entries match filter.'}
        </div>
      ) : (
        <div className="audit-log-list">
          {filtered.map(entry => (
            <button
              key={entry.id}
              className={`audit-log-entry w-full text-left focus:outline-none focus:bg-white/5 ${expandedId === entry.id ? 'expanded' : ''}`}
              onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
              aria-expanded={expandedId === entry.id}
            >
              <div className="audit-log-entry-header">
                <span className="audit-log-action">{entry.action}</span>
                <span className="audit-log-user">{entry.user}</span>
                <span className="audit-log-time">{new Date(entry.timestamp).toLocaleString()}</span>
              </div>
              {expandedId === entry.id && (
                <div className="audit-log-entry-details">
                  {entry.page && <div className="audit-log-detail"><strong>Page:</strong> {entry.page}</div>}
                  {entry.details && <div className="audit-log-detail"><strong>Details:</strong> {JSON.stringify(entry.details)}</div>}
                </div>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
