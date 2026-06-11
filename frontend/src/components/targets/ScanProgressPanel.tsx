import { GlowProgress } from '@/components/ui/GlowProgress';

export type ScanProgress = {
  targetName: string;
  jobId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
};

const getGlowProgressVariant = (status: string) => {
  switch (status) {
    case 'completed':
      return 'success';
    case 'failed':
      return 'danger';
    case 'running':
      return 'cyber';
    default:
      return 'default';
  }
};

interface ScanProgressPanelProps {
  scanProgress: ScanProgress[];
}

export function ScanProgressPanel({ scanProgress }: ScanProgressPanelProps) {
  if (scanProgress.length === 0) return null;

  return (
    <div className="scan-progress-panel space-y-3">
      <h4 className="scan-progress-title">Scan Progress</h4>
      {scanProgress.map((p) => (
        <div
          key={p.targetName}
          className="scan-progress-item flex items-center gap-4 p-2 rounded-lg bg-[var(--surface)] border border-[var(--border)]"
        >
          <span className="scan-progress-target font-medium w-36 truncate">{p.targetName}</span>
          <div className="flex-1">
            <GlowProgress
              value={p.progress}
              variant={getGlowProgressVariant(p.status)}
              animated={p.status === 'running'}
              size="sm"
              showLabel
            />
          </div>
          <span
            className={`scan-progress-status text-xs font-semibold px-2 py-0.5 rounded-full capitalize ${
              p.status === 'completed'
                ? 'bg-emerald-500/10 text-emerald-400'
                : p.status === 'failed'
                ? 'bg-rose-500/10 text-rose-400'
                : p.status === 'running'
                ? 'bg-cyan-500/10 text-cyan-400 animate-pulse'
                : 'bg-gray-500/10 text-gray-400'
            }`}
          >
            {p.status}
          </span>
          {p.jobId && <span className="scan-progress-job text-xs text-[var(--text-tertiary)] tabular-nums">{p.jobId}</span>}
        </div>
      ))}
    </div>
  );
}
