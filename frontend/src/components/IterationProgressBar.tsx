import { memo } from 'react';
import { cn } from '@/lib/utils';

export interface IterationProgressBarProps {
  currentIteration: number;
  maxIterations: number;
  stagePercent: number;
  previousFindings?: number;
}

export const IterationProgressBar = memo(function IterationProgressBar({
  currentIteration,
  maxIterations,
  stagePercent,
  previousFindings,
}: IterationProgressBarProps) {
  const isComplete = currentIteration >= maxIterations;
  const clampedPercent = Math.min(100, Math.max(0, stagePercent));

  return (
    <div
      className={cn(
   
        'relative bg-[var(--panel)] border border-[var(--line)] p-4 transition-all duration-200',
   
        '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
      )}
      style={{ boxShadow: 'var(--shadow)' }}
      role="region"
      aria-label={`Passive analysis iteration ${currentIteration} of ${maxIterations}`}
      aria-live="polite"
    >
      <div className="flex items-center justify-between mb-3">
  // eslint-disable-next-line security/detect-object-injection
        <h3 className="font-mono text-[length:var(--text-lg)] font-bold text-[var(--accent)] uppercase tracking-wider">
          🔄 Passive Analysis
        </h3>
        <span
          className={cn(
   
            'inline-flex items-center px-2 py-0.5 text-[length:var(--text-xs)] font-mono font-bold uppercase tracking-wider border rounded-sm',
            isComplete
   
              ? 'bg-[var(--ok)]/20 text-[var(--ok)] border-[var(--ok)]/40'
   
              : 'bg-[var(--accent)]/20 text-[var(--accent)] border-[var(--accent)]/40'
          )}
          role="status"
          aria-label={`Iteration ${currentIteration} of ${maxIterations}`}
        >
          Iteration {currentIteration}/{maxIterations}
        </span>
      </div>

      <div className="mb-2">
        <div
          className="progress-bar"
          role="progressbar"
          aria-valuenow={clampedPercent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Iteration ${currentIteration} progress: ${Math.round(clampedPercent)}%`}
        >
          <div
            className={cn(
              'progress-fill',
              isComplete ? 'complete' : 'running'
            )}
            style={{ width: `${clampedPercent}%` }}
          />
        </div>
  // eslint-disable-next-line security/detect-object-injection
        <div className="flex items-center justify-between mt-1 text-[length:var(--text-xs)] font-mono text-[var(--muted)]">
          <span>{Math.round(clampedPercent)}% complete</span>
          {previousFindings !== undefined && previousFindings > 0 && (
            <span aria-label={`${previousFindings} findings in previous iteration`}>
              Previous: {previousFindings} finding{previousFindings !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {maxIterations > 1 && (
        <div className="flex gap-1 mt-3" aria-label="Iteration progress indicators">
          {Array.from({ length: maxIterations }, (_, i) => {
            const iteration = i + 1;
            const isPast = iteration < currentIteration;
            const isCurrent = iteration === currentIteration;
            return (
              <div
                key={iteration}
                className={cn(
                  'flex-1 h-1.5 rounded-sm transition-all duration-300',
   
                  isPast && 'bg-[var(--ok)]/60',
   
                  isCurrent && 'bg-[var(--accent)] animate-pulse',
   
                  !isPast && !isCurrent && 'bg-[var(--muted)]/20'
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
