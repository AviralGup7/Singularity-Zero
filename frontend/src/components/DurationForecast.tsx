import { memo } from 'react';
import { cn } from '@/lib/utils';

export interface DurationForecastProps {
  durations: {
    per_stage: Record<string, { mean: number; p50: number; p90: number; p99: number; count: number }>;
    total_mean_seconds: number;
  } | null;
  loading: boolean;
}

export const DurationForecast = memo(function DurationForecast({ durations, loading }: DurationForecastProps) {
  if (loading) {
    return (
      <div
        className={cn(
   
          'relative bg-panel border border-line p-4 transition-all duration-200 animate-pulse',
   
          '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
        )}
        role="status"
        aria-label="Loading duration forecast"
      >
        <div className="h-4 bg-muted/20 rounded-sm w-48 mb-3" />
        <div className="h-3 bg-muted/20 rounded-sm w-32 mb-2" />
        <div className="h-3 bg-muted/20 rounded-sm w-64" />
      </div>
    );
  }

  if (!durations) {
    return (
      <div
        className={cn(
   
          'relative bg-panel border border-line p-4 transition-all duration-200',
   
          '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
        )}
        role="status"
        aria-label="No duration forecast available"
      >
        <p className="text-muted text-[length:var(--text-sm)] font-mono">
          No historical duration data available. Duration estimates will appear after more scans complete.
        </p>
      </div>
    );
  }

  const totalMean = durations.total_mean_seconds;
  const p50 = computeTotalP50(durations.per_stage);
  const p90 = computeTotalP90(durations.per_stage);
  const p99 = computeTotalP99(durations.per_stage);

  const stageEntries = Object.entries(durations.per_stage);
   
  const maxMean = Math.max(...stageEntries.map(([, v]) => v.mean), 1);

  return (
    <div
      className={cn(
   
        'relative bg-panel border border-line p-4 transition-all duration-200',
   
        '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
      )}
      style={{ boxShadow: 'var(--shadow)' }}
      role="region"
      aria-label="Duration forecast"
    >
      <h3 className="border-b border-line pb-2 mb-3 font-mono text-[length:var(--text-lg)] font-bold text-accent uppercase tracking-wider">
        ⏱️ Duration Forecast
      </h3>

      <p className="text-muted text-[length:var(--text-sm)] font-mono mb-4">
        This scan typically takes{' '}
        <span className="text-accent">{formatDuration(p50)}</span>
        {' – '}
        <span className="text-warn">{formatDuration(p90)}</span>
        {' '}based on historical data
      </p>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <ForecastStat label="Mean" value={totalMean} />
        <ForecastStat label="P50" value={p50} />
        <ForecastStat label="P90" value={p90} />
        <ForecastStat label="P99" value={p99} />
      </div>

      {stageEntries.length > 0 && (
        <div>
          <h4 className="font-mono text-[length:var(--text-sm)] font-bold text-text uppercase tracking-wider mb-2">
            Per-Stage Breakdown
          </h4>
          <div className="space-y-2">
            {stageEntries.map(([stage, stats]) => (
              <div key={stage} className="group flex items-center gap-3">
                <span className="font-mono text-[length:var(--text-xs)] text-text w-24 truncate" title={stage}>
                  {stage}
                </span>
                <div className="flex-1 h-3 bg-muted/10 rounded-sm overflow-hidden relative">
                  <div
                    className="absolute h-full bg-accent/20 rounded-sm"
                    style={{
                      left: `${Math.min(100, (stats.p50 / maxMean) * 100)}%`,
                      width: `${Math.min(100, ((stats.p90 - stats.p50) / maxMean) * 100)}%`,
                    }}
                    title={`P50–P90 range: ${formatDuration(stats.p50)} – ${formatDuration(stats.p90)}`}
                  />
                  <div
                    className="h-full bg-accent/60 rounded-sm transition-all duration-300 group-hover:bg-accent/80"
                    style={{ width: `${Math.min(100, (stats.mean / maxMean) * 100)}%` }}
                    role="progressbar"
                    aria-valuenow={stats.mean}
                    aria-valuemin={0}
                    aria-valuemax={maxMean}
                    aria-label={`${stage}: ${formatDuration(stats.mean)} average (P50: ${formatDuration(stats.p50)}, P90: ${formatDuration(stats.p90)})`}
                  />
                </div>
                <span className="font-mono text-[length:var(--text-xs)] text-muted w-16 text-right">
                  {formatDuration(stats.mean)}
                </span>
                <span className="font-mono text-[length:var(--text-xs)] text-muted w-12 text-right opacity-60">
                  n={stats.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
});

function ForecastStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="text-center p-2 bg-muted/5 border border-line rounded-sm hover:border-accent/30 transition-colors duration-150">
      <div className="font-mono text-[length:var(--text-xs)] text-muted uppercase mb-1">
        {label}
      </div>
      <div className="font-mono text-[length:var(--text-sm)] font-bold text-accent">
        {formatDuration(value)}
      </div>
    </div>
  );
}

function computeTotalP50(perStage: Record<string, { mean: number; p50: number; p90: number; p99: number; count: number }>): number {
  return Object.values(perStage).reduce((sum, s) => sum + s.p50, 0);
}

function computeTotalP90(perStage: Record<string, { mean: number; p50: number; p90: number; p99: number; count: number }>): number {
  return Object.values(perStage).reduce((sum, s) => sum + s.p90, 0);
}

function computeTotalP99(perStage: Record<string, { mean: number; p50: number; p90: number; p99: number; count: number }>): number {
  return Object.values(perStage).reduce((sum, s) => sum + s.p99, 0);
}

function formatDuration(totalSeconds: number): string {
  if (totalSeconds <= 0) return '0s';
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = Math.round(totalSeconds % 60);
   
  const parts: string[] = [];
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  if (s > 0 || parts.length === 0) parts.push(`${s}s`);
  return parts.join(' ');
}
