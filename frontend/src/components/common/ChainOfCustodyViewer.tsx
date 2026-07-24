import { useMemo } from 'react';
import { CheckCircle2, Clock3, Fingerprint, GitCommitHorizontal } from 'lucide-react';
import { getCustodyChain as getChainFromChainOfCustody } from '@/utils/chainOfCustody';
import type { CustodyEntry as ChainCustodyEntry } from '@/utils/chainOfCustody';
import { getCustodyChain as getChainFromEvidenceChain } from '@/utils/evidenceChain';
import type { CustodyEntry as EvidenceCustodyEntry } from '@/utils/evidenceChain';

interface ChainOfCustodyViewerProps {
  evidenceId: string;
  compact?: boolean;
  source?: 'chainOfCustody' | 'evidenceChain';
}

type NormalizedEntry = {
  id: string;
  action: string;
  user: string;
  timestamp: string;
  hash: string;
  previousHash?: string;
};

const ACTION_CLASS: Record<string, string> = {
  created: 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200',
  accessed: 'border-sky-400/40 bg-sky-400/10 text-sky-200',
  modified: 'border-amber-400/40 bg-amber-400/10 text-amber-200',
  transferred: 'border-violet-400/40 bg-violet-400/10 text-violet-200',
  exported: 'border-violet-400/40 bg-violet-400/10 text-violet-200',
  deleted: 'border-red-400/40 bg-red-400/10 text-red-200',
};

function normalizeEntry(entry: ChainCustodyEntry | EvidenceCustodyEntry, source: 'chainOfCustody' | 'evidenceChain'): NormalizedEntry {
  if (source === 'evidenceChain') {
    const e = entry as EvidenceCustodyEntry;
    return {
      id: e.id,
      action: e.action,
      user: e.user,
      timestamp: e.timestamp,
      hash: e.hashAfter || e.hashBefore || '',
      previousHash: e.hashBefore,
    };
  }
  const e = entry as ChainCustodyEntry;
  return {
    id: e.id,
    action: e.action,
    user: e.user,
    timestamp: e.timestamp,
    hash: e.hash,
    previousHash: e.previousHash,
  };
}

export function ChainOfCustodyViewer({ evidenceId, compact = false, source = 'chainOfCustody' }: ChainOfCustodyViewerProps) {
  const rawChain = useMemo(() => {
    if (source === 'evidenceChain') {
      return getChainFromEvidenceChain(evidenceId) as unknown[];
    }
    return getChainFromChainOfCustody(evidenceId) as unknown[];
  }, [evidenceId, source]);

  const chain = useMemo(() => {
    return (rawChain as (ChainCustodyEntry | EvidenceCustodyEntry)[]).map(e => normalizeEntry(e, source));
  }, [rawChain, source]);

  const verified = chain.length > 0 && chain.every((entry, index) => {
    if (index === 0) return true;
    return !entry.previousHash || entry.previousHash === chain[index - 1]?.hash;
  });

  if (chain.length === 0) return null;

  return (
    <section className="rounded border border-line bg-surface-2" aria-label={`Chain of custody for ${evidenceId}`}>
      <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="flex items-center gap-2">
          <Fingerprint size={15} className="text-cyan-200" aria-hidden="true" />
          <h4 className="text-[10px] font-black uppercase tracking-[0.22em] text-text-secondary">Chain Of Custody</h4>
        </div>
        <div
          className={`flex items-center gap-1 text-[9px] font-black uppercase tracking-widest ${verified ? 'text-emerald-300' : 'text-amber-300'}`}
          role="status"
          aria-label={verified ? 'Chain verified' : 'Chain partially verified'}
        >
          <CheckCircle2 size={12} aria-hidden="true" />
          {verified ? 'Verified' : 'Partial'}
        </div>
      </div>

      <div className={compact ? 'max-h-56 overflow-y-auto' : ''} role="list" aria-label="Custody chain entries">
        {chain.map((entry, index) => (
          <div key={entry.id} className="grid grid-cols-[24px_1fr] gap-3 border-b border-line px-4 py-3 last:border-b-0" role="listitem">
            <div className="flex flex-col items-center">
              <div className="flex h-5 w-5 items-center justify-center rounded-full border border-cyan-300/30 bg-cyan-300/10" aria-hidden="true">
                <GitCommitHorizontal size={12} className="text-cyan-200" />
              </div>
              {index < chain.length - 1 && <div className="mt-1 h-full min-h-8 w-px bg-surface-2" aria-hidden="true" />}
            </div>
            <div className="min-w-0">
              <div className="mb-2 flex items-center justify-between gap-3">
                <span className={`rounded border px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${ACTION_CLASS[entry.action] || 'border-line bg-surface-hover text-text-secondary'}`}>
                  {entry.action}
                </span>
                <span className="flex items-center gap-1 text-[9px] font-mono text-muted" title={entry.timestamp}>
                  <Clock3 size={11} aria-hidden="true" />
                  <time dateTime={entry.timestamp}>{new Date(entry.timestamp).toLocaleString()}</time>
                </span>
              </div>
              <div className="text-xs font-bold text-text">{entry.user}</div>
              <div className="mt-1 truncate font-mono text-[10px] text-white/45" title={entry.previousHash ? `${entry.previousHash} → ${entry.hash}` : entry.hash}>
                {entry.previousHash ? `${entry.previousHash.slice(0, 16)} → ${entry.hash.slice(0, 16)}` : entry.hash.slice(0, 24)}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
