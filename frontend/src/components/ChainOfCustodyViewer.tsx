import { useState, useEffect } from 'react';
import { getCustodyChain } from '@/utils/chainOfCustody';

interface ChainOfCustodyViewerProps {
  evidenceId: string;
}

export function ChainOfCustodyViewer({ evidenceId }: ChainOfCustodyViewerProps) {
  const [chain, setChain] = useState(getCustodyChain(evidenceId));

  useEffect(() => {
    setChain(getCustodyChain(evidenceId));
  }, [evidenceId]);

  if (chain.length === 0) return null;

  const actionClass = (action: string) => {
    switch (action) {
      case 'created': return 'custody-action-created';
      case 'accessed': return 'custody-action-accessed';
      case 'modified': return 'custody-action-modified';
      case 'transferred': return 'custody-action-transferred';
      case 'deleted': return 'custody-action-deleted';
      default: return '';
    }
  };

  return (
    <div className="custody-chain">
      <h4 className="custody-chain-title">Chain of Custody ({chain.length} entries)</h4>
      {chain.map((entry) => (
        <div key={entry.id} className="custody-entry">
          <span className={`custody-action ${actionClass(entry.action)}`}>
            {entry.action}
          </span>
          <div className="flex-1">
            <span className="custody-user">{entry.user}</span>
            {entry.previousHash && (
              <div className="custody-hash">
                Prev: {entry.previousHash.slice(0, 16)}... → {entry.hash.slice(0, 16)}...
              </div>
            )}
          </div>
          <span className="custody-time">
            {new Date(entry.timestamp).toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}
