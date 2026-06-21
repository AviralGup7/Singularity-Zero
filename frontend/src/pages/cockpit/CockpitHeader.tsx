import { memo } from 'react';
import { Icon } from '@/components/ui/Icon';
import type { Job } from '@/types/api';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500 border-red-500/30 bg-red-500/5',
  high: 'text-orange-500 border-orange-500/30 bg-orange-500/5',
  medium: 'text-amber-500 border-amber-500/30 bg-amber-500/5',
  low: 'text-blue-500 border-blue-500/30 bg-blue-500/5',
  info: 'text-slate-400 border-slate-400/30 bg-slate-400/5',
};

interface CockpitHeaderProps {
  target: string;
  activeJob: Job | null;
  stats: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

function CockpitHeaderBase({ target, activeJob, stats }: CockpitHeaderProps) {
  return (
    <div className="flex-shrink-0 z-20 flex flex-col md:flex-row items-stretch md:items-center justify-between border-b border-white/10 bg-[#080b11]/80 backdrop-blur-md px-6 py-4 gap-4">
      {/* Left Telemetry Title */}
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/20 bg-accent/5">
          <Icon name="shield" size={18} className="text-accent" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-extrabold uppercase tracking-tight text-white">Steering Cockpit</h2>
            <span className="font-mono text-[9px] rounded-full border border-cyan-500/20 bg-cyan-950/20 px-2 py-0.5 text-cyan-400">
              {activeJob?.status || 'Active telemetry'}
            </span>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[10px] text-muted">
            <span className="pulse-dot" /> {target}
          </div>
        </div>
      </div>

      {/* Global Progress telemetry */}
      {activeJob && (
        <div className="flex-1 max-w-sm mx-4 space-y-1">
          <div className="flex items-center justify-between font-mono text-[9px]">
            <span className="uppercase text-muted truncate max-w-[150px]">{activeJob.stage_label || 'Scanning'}</span>
            <span className="font-bold text-accent">{Math.round(activeJob.progress_percent || 0)}%</span>
          </div>
          <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-white/5">
            <div
              className="h-full rounded-full bg-gradient-to-r from-accent via-cyan-400 to-emerald-400 transition-all duration-300"
              style={{ width: `${activeJob.progress_percent || 0}%` }}
            />
          </div>
        </div>
      )}

      {/* Right HUD metrics */}
      <div className="flex items-center gap-2.5">
        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
          <div
            key={sev}
            className={`rounded-lg border px-3 py-1 text-center min-w-16 transition-all ${SEVERITY_COLORS[sev]}`}
          >
            <div className="font-mono text-xs font-black">{stats[sev]}</div>
            <div className="text-[8px] font-black uppercase tracking-wider opacity-60">{sev}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export const CockpitHeader = memo(CockpitHeaderBase);
