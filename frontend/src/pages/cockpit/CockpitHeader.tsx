import { memo } from 'react';
import { Icon } from '@/components/ui/Icon';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-critical border-critical/30 bg-critical/5',
  high: 'text-high border-high/30 bg-high/5',
  medium: 'text-medium border-medium/30 bg-medium/5',
  low: 'text-low border-low/30 bg-low/5',
  info: 'text-info border-info/30 bg-info/5',
};

interface CockpitHeaderProps {
  target: string;
  activeJob: { status?: string; stage_label?: string; progress_percent?: number } | null;
  stats: Record<string, number>;
}

function CockpitHeaderBase({ target, activeJob, stats }: CockpitHeaderProps) {
  return (
    <div className="flex-shrink-0 z-20 flex flex-col md:flex-row items-stretch md:items-center justify-between border-b border-line-strong bg-surface/80 backdrop-blur-md px-6 py-4 gap-4" role="banner" aria-label="Cockpit header">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/20 bg-accent/5" aria-hidden="true">
          <Icon name="shield" size={18} className="text-accent" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-extrabold uppercase tracking-tight text-text-primary">Steering Cockpit</h2>
            <span className="font-mono text-[9px] rounded-full border border-info/20 bg-info/10 px-2 py-0.5 text-info" role="status">
              {activeJob?.status || 'Active telemetry'}
            </span>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[10px] text-text-secondary" title={target}>
            <span className="pulse-dot" aria-hidden="true" /> {target}
          </div>
        </div>
      </div>

      {activeJob && (
        <div className="flex-1 max-w-sm mx-4 space-y-1">
          <div className="flex items-center justify-between font-mono text-[9px]">
            <span className="uppercase text-text-secondary truncate max-w-[150px]" title={activeJob.stage_label || 'Scanning'}>{activeJob.stage_label || 'Scanning'}</span>
            <span className="font-bold text-accent tabular-nums">{Math.round(activeJob.progress_percent || 0)}%</span>
          </div>
          <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-valuenow={Math.round(activeJob.progress_percent || 0)} aria-valuemin={0} aria-valuemax={100} aria-label={`Scan progress: ${Math.round(activeJob.progress_percent || 0)}%`}>
            <div
              className="h-full rounded-full bg-gradient-to-r from-accent via-info to-ok transition-all duration-300"
              style={{ width: `${activeJob.progress_percent || 0}%` }}
            />
          </div>
        </div>
      )}

      <div className="flex items-center gap-2.5" role="group" aria-label="Finding severity counts">
        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
          <div
            key={sev}
            className={`rounded-lg border px-3 py-1 text-center min-w-16 transition-all ${SEVERITY_COLORS[sev]}`}
            role="status"
            aria-label={`${stats[sev]} ${sev} findings`}
          >
            <div className="font-mono text-xs font-black tabular-nums">{stats[sev]}</div>
            <div className="text-[8px] font-black uppercase tracking-wider opacity-60">{sev}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export const CockpitHeader = memo(CockpitHeaderBase);
