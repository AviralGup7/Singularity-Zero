import { Crosshair } from 'lucide-react';
import type { LowHangingFruitSummary } from '@/api/evasion';

interface LhfColumnCardProps {
  lhf: LowHangingFruitSummary | null;
}

export function LhfColumnCard({ lhf }: LhfColumnCardProps) {
  const findings = lhf?.findings ?? [];
  const total = lhf?.total ?? findings.length;

  return (
    <div className="glass-panel p-6 rounded-2xl border border-ok/20 cyber-glow-card">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Crosshair size={16} className="text-ok" />
          <h2 className="text-xs font-black uppercase tracking-widest text-text">Low-Hanging-Fruit</h2>
        </div>
        <span className="text-[10px] font-mono text-muted uppercase tracking-widest">{total} LHF</span>
      </div>
      {lhf?.criteria && (
        <div className="flex flex-wrap items-center gap-2 mb-4 text-[9px] text-muted/80 font-mono uppercase tracking-widest">
          {lhf.criteria.min_severity ? <span>SEV ≥ {lhf.criteria.min_severity}</span> : null}
          {typeof lhf.criteria.min_confidence === 'number' ? (
            <span>· CONF ≥ {(lhf.criteria.min_confidence * 100).toFixed(0)}%</span>
          ) : null}
          {lhf.criteria.max_findings ? <span>· MAX {lhf.criteria.max_findings}</span> : null}
        </div>
      )}
      {findings.length === 0 ? (
        <div className="py-10 text-center text-muted/60 italic text-[11px] uppercase tracking-widest">
          No low-hanging-fruit candidates yet.
        </div>
      ) : (
        <ul className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
          {findings.map((f) => (
            <li
              key={f.id}
              className="p-3 rounded-xl border border-white/5 bg-black/30 hover:bg-black/40 transition-colors flex items-center justify-between gap-3"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span
                    className={`text-[9px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border ${
                      f.severity === 'critical' || f.severity === 'high'
                        ? 'bg-bad/10 text-bad border-bad/20'
                        : f.severity === 'medium'
                        ? 'bg-warn/10 text-warn border-warn/20'
                        : 'bg-ok/10 text-ok border-ok/20'
                    }`}
                  >
                    {f.severity}
                  </span>
                  <span className="text-[9px] font-mono text-muted/80 uppercase tracking-widest">{f.category}</span>
                  {f.is_high_value ? (
                    <span className="text-[9px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border bg-accent/10 text-accent border-accent/20">
                      HIGH-VALUE
                    </span>
                  ) : null}
                  {f.bounty_source ? (
                    <span className="text-[9px] font-mono text-muted/70 uppercase tracking-widest">
                      {f.bounty_source}
                    </span>
                  ) : null}
                </div>
                <div className="text-[11px] font-bold text-text truncate">{f.title}</div>
                <div className="text-[9px] text-muted/80 font-mono truncate">{f.url}</div>
              </div>
              <div className="flex flex-col items-end gap-1 shrink-0">
                <span className="text-[10px] font-mono font-black text-ok">
                  {(f.confidence * 100).toFixed(0)}%
                </span>
                <a
                  href={`/cockpit?focus=${encodeURIComponent(f.id)}`}
                  className="text-[9px] font-black uppercase tracking-widest text-accent hover:underline"
                >
                  Inspect →
                </a>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
