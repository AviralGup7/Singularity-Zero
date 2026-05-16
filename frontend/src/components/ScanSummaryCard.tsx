import { cn } from '@/lib/utils';
import type { Job } from '../types/api';

export interface ScanSummaryCardProps {
  job: Job;
  historicalComparison?: { mean_seconds: number };
}

export function ScanSummaryCard({ job, historicalComparison }: ScanSummaryCardProps) {
  const durationSeconds = computeDurationSeconds(job);
  const durationLabel = formatDuration(durationSeconds);

  const severityTotals = extractSeverityTotals(job);
  const totalFindings = Object.values(severityTotals).reduce((a, b) => a + b, 0);

  const comparison = historicalComparison
    ? computeComparison(durationSeconds, historicalComparison.mean_seconds)
    : null;

  return (
    <div
      className={cn(
        'card',
   
        'relative bg-[var(--panel)] border border-[var(--accent)]/60 p-4 transition-all duration-200',
   
        '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
      )}
      style={{ boxShadow: '0 0 12px color-mix(in srgb, var(--accent) 20%, transparent)' }}
      role="region"
      aria-label="Scan summary"
    >
      <h3 className="border-b border-[var(--line)] pb-2 mb-3 font-mono text-[length:var(--text-lg)] font-bold text-[var(--accent)] uppercase tracking-wider">
        ✅ Scan Complete
      </h3>

      <div className="summary-grid mb-4">
        <div className="summary-item">
          <span className="summary-label">Duration</span>
          <span className="summary-value font-mono text-[var(--accent)]">{durationLabel}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Target</span>
          <span className="summary-value">{job.hostname || job.base_url}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Started</span>
          <span className="summary-value">{job.started_at_ist || job.started_at}</span>
        </div>
        {job.completed_at && (
          <div className="summary-item">
            <span className="summary-label">Completed</span>
            <span className="summary-value">{job.completed_at}</span>
          </div>
        )}
        <div className="summary-item">
          <span className="summary-label">Final Stage</span>
          <span className="summary-value">{job.stage_label}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Modules Used</span>
          <span className="summary-value">{job.enabled_modules?.join(', ') || 'None'}</span>
        </div>
      </div>

      {totalFindings > 0 && (
        <div className="mb-4">
          <h4 className="font-mono text-[length:var(--text-sm)] font-bold text-[var(--text)] uppercase tracking-wider mb-2">
            Findings by Severity
          </h4>
          <div className="flex flex-wrap gap-2">
            {SEVERITY_ORDER.map((sev) => {
              const count = severityTotals[sev] ?? 0;
              if (count === 0) return null;
              return (
                <span
                  key={sev}
                  className={cn(
   
                    'inline-flex items-center gap-1 px-2 py-1 text-[length:var(--text-xs)] font-mono font-bold uppercase tracking-wider border rounded-sm',
                    severityColorClass(sev)
                  )}
                  role="status"
                  aria-label={`${count} ${sev} findings`}
                >
                  {sev}: {count}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {comparison && (
        <div
          className={cn(
   
            'p-3 rounded-sm font-mono text-[length:var(--text-sm)] border',
            comparison.faster
   
              ? 'bg-[var(--ok)]/10 border-[var(--ok)]/30 text-[var(--ok)]'
   
              : 'bg-[var(--warn)]/10 border-[var(--warn)]/30 text-[var(--warn)]'
          )}
          role="status"
          aria-live="polite"
        >
          {comparison.faster ? '⚡' : '🐢'}{' '}
          This scan was{' '}
          <strong>{comparison.diffLabel}</strong>{' '}
          {comparison.faster ? 'faster' : 'slower'} than usual
          {comparison.percentLabel && (
            <span className="opacity-70"> ({comparison.percentLabel})</span>
          )}
        </div>
      )}
    </div>
  );
}

   
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

function severityColorClass(sev: string): string {
  const map: Record<string, string> = {
   
    critical: 'bg-[var(--severity-critical)]/20 text-[var(--severity-critical)] border-[var(--severity-critical)]/40',
   
    high: 'bg-[var(--severity-high)]/20 text-[var(--severity-high)] border-[var(--severity-high)]/40',
   
    medium: 'bg-[var(--severity-medium)]/20 text-[var(--severity-medium)] border-[var(--severity-medium)]/40',
   
    low: 'bg-[var(--severity-low)]/20 text-[var(--severity-low)] border-[var(--severity-low)]/40',
   
    info: 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/40',
  };
  return map[sev] ?? map.info;
}

function computeDurationSeconds(job: Job): number {
  if (job.completed_at && job.started_at) {
    const start = new Date(job.started_at).getTime();
    const end = new Date(job.completed_at).getTime();
    if (!isNaN(start) && !isNaN(end)) {
      return Math.max(0, Math.round((end - start) / 1000));
    }
  }
  return 0;
}

function formatDuration(totalSeconds: number): string {
  if (totalSeconds === 0) return '—';
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
   
  const parts: string[] = [];
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  if (s > 0 || parts.length === 0) parts.push(`${s}s`);
  return parts.join(' ');
}

function extractSeverityTotals(job: Job): Record<string, number> {
  const totals: Record<string, number> = {};
  if (job.latest_logs) {
    for (const line of job.latest_logs) {
   
      const match = line.match(/severity[_\s]*(critical|high|medium|low|info)[=:\s]+(\d+)/i);
      if (match) {
   
        totals[match[1].toLowerCase()] = parseInt(match[2], 10);
      }
    }
  }
  return totals;
}

function computeComparison(
  actualSeconds: number,
  meanSeconds: number
): { faster: boolean; diffSeconds: number; diffLabel: string; percentLabel: string } | null {
  if (actualSeconds === 0 || meanSeconds === 0) return null;
  const diff = meanSeconds - actualSeconds;
  const faster = diff > 0;
  const absDiff = Math.abs(diff);
  const percent = Math.round((absDiff / meanSeconds) * 100);
  return {
    faster,
    diffSeconds: absDiff,
    diffLabel: formatDuration(absDiff),
    percentLabel: `${percent}%`,
  };
}
