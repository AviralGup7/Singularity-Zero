import { Hourglass, Flag, Clock } from 'lucide-react';
import type { EvasionMetricsResponse } from '@/api/evasion';

interface HuntBudgetCardProps {
  huntBudget: NonNullable<EvasionMetricsResponse['hunt_budget']>;
}

interface BudgetBarProps {
  label: string;
  value: string;
  sub: string;
  percent: number;
  accent: string;
}

function BudgetBar({ label, value, sub, percent, accent }: BudgetBarProps) {
  return (
    <div className="p-3 rounded-xl border border-white/5 bg-black/30 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-[9px] font-black uppercase tracking-widest text-muted">{label}</span>
        <span className={`text-[10px] font-mono font-black ${accent}`}>{value}</span>
      </div>
      <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
        <div
          className={`h-full ${accent.replace('text-', 'bg-')} transition-all duration-700`}
          style={{ width: `${Math.max(0, Math.min(100, percent))}%` }}
        />
      </div>
      <span className="text-[9px] font-mono text-muted/70 uppercase tracking-widest">{sub}</span>
    </div>
  );
}

export function HuntBudgetCard({ huntBudget }: HuntBudgetCardProps) {
  const max = huntBudget.max_duration_seconds ?? 0;
  const elapsed = huntBudget.elapsed_seconds ?? 0;
  const remaining = max > 0 ? Math.max(0, max - elapsed) : null;
  const progress = max > 0 ? Math.min(100, (elapsed / max) * 100) : 0;
  const findings = huntBudget.findings_count ?? 0;
  const highConf = huntBudget.high_confidence_count ?? 0;
  const stopFindings = huntBudget.stop_when_total_findings ?? 0;
  const stopHighConf = huntBudget.stop_when_high_confidence_count ?? 0;
  const findingsPct = stopFindings > 0 ? Math.min(100, (findings / stopFindings) * 100) : 0;
  const highConfPct = stopHighConf > 0 ? Math.min(100, (highConf / stopHighConf) * 100) : 0;

  return (
    <div className="glass-panel p-6 rounded-2xl border border-accent/20 cyber-glow-card">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Hourglass size={16} className="text-accent" />
          <h2 className="text-xs font-black uppercase tracking-widest text-text">
            Hunt Budget
            {huntBudget.label ? (
              <span className="ml-2 text-muted/60 normal-case tracking-wider text-[9px]">{huntBudget.label}</span>
            ) : null}
          </h2>
        </div>
        {huntBudget.exhausted ? (
          <span className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded border bg-bad/10 text-bad border-bad/20">
            <Flag size={9} className="inline -mt-0.5 mr-1" /> Exhausted
          </span>
        ) : (
          <span className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded border bg-ok/10 text-ok border-ok/20">
            <Clock size={9} className="inline -mt-0.5 mr-1" /> Active
          </span>
        )}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <BudgetBar
          label="Time"
          value={`${Math.round(elapsed)}s`}
          sub={remaining !== null ? `${Math.round(remaining)}s remaining` : 'unbounded'}
          percent={progress}
          accent="text-accent"
        />
        <BudgetBar
          label="Total Findings"
          value={`${findings} / ${stopFindings}`}
          sub={`Stops at ${stopFindings}`}
          percent={findingsPct}
          accent="text-ok"
        />
        <BudgetBar
          label="High-Confidence"
          value={`${highConf} / ${stopHighConf}`}
          sub={`Stops at ${stopHighConf}`}
          percent={highConfPct}
          accent="text-warn"
        />
      </div>
    </div>
  );
}
