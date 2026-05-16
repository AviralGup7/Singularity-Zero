import { getCustodyChain } from '@/utils/evidenceChain';

export function EvidenceCustodyViewer({ evidenceId }: { evidenceId: string }) {
  const chain = getCustodyChain(evidenceId);

  const actionIcons: Record<string, string> = {
    created: '📝',
    accessed: '👁️',
    modified: '✏️',
    exported: '📤',
    deleted: '🗑️',
  };

  return (
    <div className="evidence-custody-viewer">
      <h5>Chain of Custody</h5>
      <div className="custody-chain">
  // eslint-disable-next-line security/detect-object-injection
        {chain.length === 0 && <p className="text-[var(--muted)]">No custody records</p>}
        {chain.map(entry => (
          <div key={entry.id} className="custody-entry">
            <span className="custody-action-icon">
  // eslint-disable-next-line security/detect-object-injection
              {actionIcons[entry.action] || '📋'}
            </span>
            <div className="custody-details">
              <div className="custody-header">
                <span className="custody-action">{entry.action}</span>
                <span className="custody-user">by {entry.user}</span>
              </div>
              <div className="custody-time">
                {new Date(entry.timestamp).toLocaleString()}
              </div>
              {entry.details && <div className="custody-note">{entry.details}</div>}
              {entry.hashBefore && (
                <div className="custody-hash">
                  <span>Before: </span>
                  <code>{entry.hashBefore.slice(0, 16)}...</code>
                </div>
              )}
              {entry.hashAfter && (
                <div className="custody-hash">
                  <span>After: </span>
                  <code>{entry.hashAfter.slice(0, 16)}...</code>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
