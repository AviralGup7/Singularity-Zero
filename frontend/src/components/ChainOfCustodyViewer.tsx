import { useMemo } from 'react';
import { CheckCircle2, Clock3, Fingerprint, GitCommitHorizontal } from 'lucide-react';
import { getCustodyChain } from '@/utils/chainOfCustody';

interface ChainOfCustodyViewerProps {
  evidenceId: string;
  compact?: boolean;
}

const ACTION_CLASS: Record<string, string> = {
  created: 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200',
  accessed: 'border-sky-400/40 bg-sky-400/10 text-sky-200',
  modified: 'border-amber-400/40 bg-amber-400/10 text-amber-200',
  transferred: 'border-violet-400/40 bg-violet-400/10 text-violet-200',
  deleted: 'border-red-400/40 bg-red-400/10 text-red-200',
};

export function ChainOfCustodyViewer({ evidenceId, compact = false }: ChainOfCustodyViewerProps) {
  const chain = useMemo(() => getCustodyChain(evidenceId), [evidenceId]);
  const verified = chain.length > 0 && chain.every((entry, index) => {
    if (index === 0) return true;
    return !entry.previousHash || entry.previousHash === chain[index - 1]?.hash;
  });

  if (chain.length === 0) return null;

  return (
    <section className="rounded border border-white/10 bg-black/35">
      <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
        <div className="flex items-center gap-2">
          <Fingerprint size={15} className="text-cyan-200" />
          <h4 className="text-[10px] font-black uppercase tracking-[0.22em] text-white/70">Chain Of Custody</h4>
        </div>
        <div className={`flex items-center gap-1 text-[9px] font-black uppercase tracking-widest ${verified ? 'text-emerald-300' : 'text-amber-300'}`}>
          <CheckCircle2 size={12} />
          {verified ? 'Verified' : 'Partial'}
        </div>
      </div>

      <div className={compact ? 'max-h-56 overflow-y-auto' : ''}>
        {chain.map((entry, index) => (
          <div key={entry.id} className="grid grid-cols-[24px_1fr] gap-3 border-b border-white/5 px-4 py-3 last:border-b-0">
            <div className="flex flex-col items-center">
              <div className="flex h-5 w-5 items-center justify-center rounded-full border border-cyan-300/30 bg-cyan-300/10">
                <GitCommitHorizontal size={12} className="text-cyan-200" />
              </div>
              {index < chain.length - 1 && <div className="mt-1 h-full min-h-8 w-px bg-white/10" />}
            </div>
            <div className="min-w-0">
              <div className="mb-2 flex items-center justify-between gap-3">
                <span className={`rounded border px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${ACTION_CLASS[entry.action] || 'border-white/15 bg-white/5 text-white/70'}`}>
                  {entry.action}
                </span>
                <span className="flex items-center gap-1 text-[9px] font-mono text-muted">
                  <Clock3 size={11} />
                  {new Date(entry.timestamp).toLocaleString()}
                </span>
              </div>
              <div className="text-xs font-bold text-text">{entry.user}</div>
              <div className="mt-1 truncate font-mono text-[10px] text-white/45">
                {entry.previousHash ? `${entry.previousHash.slice(0, 16)} -> ${entry.hash.slice(0, 16)}` : entry.hash.slice(0, 24)}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
