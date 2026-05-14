import { cn } from '@/lib/utils';
import type { StalledContext } from '@/types/api';

export interface StalledExplainerPanelProps {
  stalled: boolean;
  stage: string;
  stageLabel: string;
  secondsSinceUpdate: number;
  elapsedLabel: string;
  stalledContext?: StalledContext | null;
}

export function StalledExplainerPanel({
  stalled,
  stage,
  stageLabel,
  secondsSinceUpdate,
  elapsedLabel,
  stalledContext,
}: StalledExplainerPanelProps) {
  if (!stalled) return null;

  const formatSeconds = (s: number): string => {
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const rem = s % 60;
    return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
  };

  const probableCause = stalledContext?.probable_cause ?? 'Waiting for external responses or cooldown periods';
  const expectedDuration = stalledContext?.expected_duration_seconds
    ? formatSeconds(Math.round(stalledContext.expected_duration_seconds))
    : null;
  const suggestedActions = stalledContext?.suggested_actions ?? [];

  return (
    <div
      role="alert"
      aria-live="polite"
      className={cn(
        'relative bg-[var(--warn)]/10 border border-[var(--warn)]/40 p-4 transition-all duration-200',
        '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
      )}
      style={{ boxShadow: '0 0 8px color-mix(in srgb, var(--warn) 30%, transparent)' }}
    >
      <div className="flex items-start gap-3">
        <span className="text-xl animate-pulse flex-shrink-0" aria-hidden="true">⏳</span>
        <div className="flex-1 min-w-0">
          <p className="font-mono text-[length:var(--text-sm)] font-bold text-[var(--warn)] uppercase tracking-wider mb-1">
            Scan is still running — no action needed
          </p>
          <p className="text-[var(--text)] text-[length:var(--text-sm)] opacity-80 mb-2">
            {probableCause}
          </p>
          <div className="flex flex-wrap gap-3 text-[length:var(--text-xs)] font-mono text-[var(--muted)] mb-2">
            <span>
              Stage:{' '}
              <span className="text-[var(--warn)]">{stageLabel || stage}</span>
            </span>
            <span>
              Last update:{' '}
              <span className="text-[var(--warn)]">{formatSeconds(secondsSinceUpdate)} ago</span>
            </span>
            {elapsedLabel && (
              <span>
                Elapsed:{' '}
                <span className="text-[var(--warn)]">{elapsedLabel}</span>
              </span>
            )}
            {expectedDuration && (
              <span>
                Expected:{' '}
                <span className="text-[var(--warn)]">{expectedDuration}</span>
              </span>
            )}
          </div>
          {suggestedActions.length > 0 && (
            <div className="mt-2">
              <p className="text-[length:var(--text-xs)] font-mono text-[var(--warn)] mb-1">Suggested actions:</p>
              <ul className="list-disc list-inside text-[length:var(--text-xs)] font-mono text-[var(--muted)] space-y-0.5">
                {suggestedActions.map((action, i) => (
                  <li key={i}>{action}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
