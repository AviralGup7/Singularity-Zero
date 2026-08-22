import { memo } from 'react';
import { cn } from '@/lib/utils';

export interface IterationProgressBarProps {
  currentIteration: number;
  maxIterations: number;
  stagePercent: number;
  previousFindings?: number;
}

export function clampIterationProgress(current: number, max: number, percent: number): { current: number; max: number; percent: number } {
  const safeMax = Number.isFinite(max) && max > 0 ? Math.min(Math.floor(max), 64) : 1;
  const safeCurrent = Number.isFinite(current) ? Math.min(Math.max(0, Math.floor(current)), safeMax) : 0;
  const safePercent = Number.isFinite(percent) ? Math.min(100, Math.max(0, percent)) : 0;
  return { current: safeCurrent, max: safeMax, percent: safePercent };
}

export const IterationProgressBar = memo(function IterationProgressBar({
  currentIteration,
  maxIterations,
  stagePercent,
  previousFindings,
}: IterationProgressBarProps) {
  const { current, max, percent: clampedPercent } = clampIterationProgress(currentIteration, maxIterations, stagePercent);
  const isComplete = current >= max;

  return (
    <div
      className={cn(
   
        'relative bg-panel border border-line p-4 transition-all duration-200',
   
        '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
      )}
      style={{ boxShadow: 'var(--shadow)' }}
      role="region"
      aria-label={`Passive analysis iteration ${current} of ${max}`}
      aria-live="polite"
    >
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-mono text-[length:var(--text-lg)] font-bold text-accent uppercase tracking-wider">
          🔄 Passive Analysis
        </h3>
        <span
          className={cn(
   
            'inline-flex items-center px-2 py-0.5 text-[length:var(--text-xs)] font-mono font-bold uppercase tracking-wider border rounded-sm',
            isComplete
   
              ? 'bg-ok/20 text-ok border-ok/40'
   
              : 'bg-accent/20 text-accent border-accent/40'
          )}
          role="status"
          aria-label={`Iteration ${current} of ${max}`}
        >
          Iteration {current}/{max}
        </span>
      </div>

      <div className="mb-2">
        <div
          className="progress-bar h-2.5 bg-muted/20 rounded-full overflow-hidden"
          role="progressbar"
          aria-valuenow={clampedPercent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Iteration ${current} progress: ${Math.round(clampedPercent)}%`}
        >
          <div
            className={cn(
              'h-full rounded-full transition-all duration-500 ease-out',
              isComplete ? 'bg-ok' : 'bg-accent'
            )}
            style={{ width: `${clampedPercent}%` }}
          />
        </div>
        <div className="flex items-center justify-between mt-1 text-[length:var(--text-xs)] font-mono text-muted">
          <span className="tabular-nums">{Math.round(clampedPercent)}% complete</span>
          {previousFindings !== undefined && previousFindings > 0 && (
            <span aria-label={`${previousFindings} findings in previous iteration`}>
              Previous: {previousFindings} finding{previousFindings !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {max > 1 && (
        <div className="flex gap-1 mt-3" aria-label="Iteration progress indicators">
          {Array.from({ length: max }, (_, i) => {
            const iteration = i + 1;
            const isPast = iteration < current;
            const isCurrent = iteration === current;
            return (
              <div
                key={iteration}
                className={cn(
                  'flex-1 h-1.5 rounded-sm transition-all duration-300',
   
                  isPast && 'bg-ok/60',
   
                  isCurrent && 'bg-accent animate-pulse',
   
                  !isPast && !isCurrent && 'bg-muted/20'
                )}
                role="img"
                aria-label={
                  isPast
                    ? `Iteration ${iteration} complete`
                    : isCurrent
                    ? `Iteration ${iteration} in progress`
                    : `Iteration ${iteration} pending`
                }
              />
            );
          })}
        </div>
      )}
    </div>
  );
});
