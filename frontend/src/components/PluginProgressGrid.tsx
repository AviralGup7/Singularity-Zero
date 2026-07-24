import { useState, useCallback, useMemo } from 'react';
import { cn } from '@/lib/utils';

export interface PluginProgressEntry {
  group: string;
  label: string;
  processed: number;
  total: number;
  percent: number;
  current_plugin?: string;
  status: 'pending' | 'running' | 'completed' | 'error';
  error_message?: string;
}

interface PluginProgressGridProps {
  plugins: PluginProgressEntry[];
  loading?: boolean;
  collapsedGroups?: string[];
  onToggleGroup?: (group: string) => void;
}

export function PluginProgressGrid({
  plugins,
  loading = false,
  collapsedGroups: externalCollapsed,
  onToggleGroup,
}: PluginProgressGridProps) {
   
  const [internalCollapsed, setInternalCollapsed] = useState<Set<string>>(new Set());

  const isControlled = externalCollapsed !== undefined && onToggleGroup !== undefined;
  const collapsed = isControlled ? new Set(externalCollapsed) : internalCollapsed;

  const handleToggle = useCallback(
    (group: string) => {
      if (isControlled) {
        onToggleGroup(group);
      } else {
        setInternalCollapsed((prev) => {
          const next = new Set(prev);
          if (next.has(group)) next.delete(group);
          else next.add(group);
          return next;
        });
      }
    },
   
    [isControlled, onToggleGroup]
  );

  const grouped = useMemo(() => {
    const map = new Map<string, PluginProgressEntry[]>();
    for (const p of plugins) {
      if (!map.has(p.group)) map.set(p.group, []);
      map.get(p.group)!.push(p);
    }
    return Array.from(map.entries());
   
  }, [plugins]);

  const overallProgress = useMemo(() => {
    const totalProcessed = plugins.reduce((s, p) => s + p.processed, 0);
    const totalAll = plugins.reduce((s, p) => s + p.total, 0);
    return totalAll > 0 ? Math.round((totalProcessed / totalAll) * 100) : 0;
   
  }, [plugins]);

  const completedCount = plugins.filter((p) => p.status === 'completed').length;
  const runningCount = plugins.filter((p) => p.status === 'running').length;
  const errorCount = plugins.filter((p) => p.status === 'error').length;

  if (loading) {
    return (
      <div
        className={cn(
   
          'relative bg-panel border border-line p-4 transition-all duration-200 animate-pulse',
   
          '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
        )}
        role="status"
        aria-label="Loading plugin progress"
      >
        <div className="h-4 bg-muted/20 rounded-sm w-48 mb-3" />
        {Array.from({ length: 3 }).map((_, i) => (
   
          <div key={i} className="h-3 bg-muted/20 rounded-sm w-full mb-2" />
        ))}
      </div>
    );
  }

  if (plugins.length === 0) {
    return (
      <div
        className={cn(
   
          'relative bg-panel border border-line p-4 transition-all duration-200',
   
          '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
        )}
        role="status"
        aria-label="No plugin progress data"
      >
        <p className="text-muted text-[length:var(--text-sm)] font-mono">
          Plugin progress tracking is enabled. Progress will appear here once the analysis stage begins.
        </p>
      </div>
    );
  }

  return (
    <div
      className={cn(
   
        'relative bg-panel border border-line p-4 transition-all duration-200',
   
        '[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]'
      )}
      style={{ boxShadow: 'var(--shadow)' }}
      role="region"
      aria-label="Plugin progress grid"
      aria-live="polite"
    >
      <div className="flex items-center justify-between border-b border-line pb-2 mb-3">
        <h3 className="font-mono text-[length:var(--text-lg)] font-bold text-accent uppercase tracking-wider">
          Plugin Progress
        </h3>
        <div className="flex items-center gap-4 text-[length:var(--text-xs)] font-mono">
          <span className="text-muted">
            {completedCount}/{plugins.length} complete
          </span>
          {runningCount > 0 && (
   
            <span className="text-accent">● {runningCount} running</span>
          )}
          {errorCount > 0 && (
   
            <span className="text-warn">● {errorCount} errors</span>
          )}
          <span className="text-text">
            {overallProgress}% overall
          </span>
        </div>
      </div>

      <div className="mb-3">
        <div className="h-2 bg-muted/10 rounded-sm overflow-hidden">
          <div
            className={cn(
              'h-full rounded-sm transition-all duration-300',
   
              errorCount > 0 ? 'bg-warn/70' : 'bg-accent/60'
            )}
            style={{ width: `${overallProgress}%` }}
            role="progressbar"
            aria-valuenow={overallProgress}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`Overall plugin progress: ${overallProgress}%`}
          />
        </div>
      </div>

      <div className="space-y-3" role="list" aria-label="Plugin groups">
        {grouped.map(([group, entries]) => {
          const isCollapsed = collapsed.has(group);
          const groupProcessed = entries.reduce((s, e) => s + e.processed, 0);
          const groupTotal = entries.reduce((s, e) => s + e.total, 0);
          const groupPercent = groupTotal > 0 ? Math.round((groupProcessed / groupTotal) * 100) : 0;
          const runningEntry = entries.find((e) => e.status === 'running');
          const errorEntry = entries.find((e) => e.status === 'error');

          return (
            <div key={group} role="listitem" aria-label={`${group} plugin group`}>
              <button
                className={cn(
                  'w-full flex items-center justify-between px-3 py-2 rounded-sm transition-colors',
   
                  'bg-muted/5 hover:bg-muted/10',
   
                  'text-left font-mono text-[length:var(--text-sm)]'
                )}
                onClick={() => handleToggle(group)}
                aria-expanded={!isCollapsed}
                aria-controls={`plugin-group-${group}`}
              >
                <div className="flex items-center gap-2">
                  <span className="text-muted">
                    {isCollapsed ? '▶' : '▼'}
                  </span>
                  <span className="text-text font-bold">{group}</span>
                  {runningEntry && (
   
                    <span className="text-accent text-[length:var(--text-xs)]">
                      ● {runningEntry.current_plugin || 'Running...'}
                    </span>
                  )}
                  {errorEntry && (
   
                    <span className="text-warn text-[length:var(--text-xs)]">
                      ⚠ Error
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-muted text-[length:var(--text-xs)]">
                    {groupProcessed}/{groupTotal}
                  </span>
                  <span className="text-text text-[length:var(--text-xs)] font-bold">
                    {groupPercent}%
                  </span>
                </div>
              </button>

              <div className="h-1.5 bg-muted/10 rounded-sm overflow-hidden mt-1">
                <div
   
                  className="h-full bg-accent/40 rounded-sm transition-all duration-300"
                  style={{ width: `${groupPercent}%` }}
                />
              </div>

              {!isCollapsed && (
                <div
                  id={`plugin-group-${group}`}
                  className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 mt-2 pl-5"
                  role="list"
                  aria-label={`${group} plugins`}
                >
                  {entries.map((entry) => (
                    <PluginProgressItem key={entry.label || entry.group} entry={entry} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PluginProgressItem({ entry }: { entry: PluginProgressEntry }) {
  const statusColor =
    entry.status === 'completed'
      ? 'border-accent/40 bg-accent/5'
      : entry.status === 'running'
      ? 'border-accent/60 bg-accent/10 motion-safe:animate-pulse'
      : entry.status === 'error'
      ? 'border-warn/60 bg-warn/10'
      : 'border-line bg-muted/5';

  const progressColor =
    entry.status === 'completed'
      ? 'bg-accent'
      : entry.status === 'running'
      ? 'bg-accent/70'
      : entry.status === 'error'
      ? 'bg-warn'
      : 'bg-muted/30';

  return (
    <div
      className={cn(
        'border rounded-sm p-2 transition-all duration-200 hover:shadow-sm',
        statusColor
      )}
      role="listitem"
      aria-label={`${entry.label}: ${entry.percent}% ${entry.status}`}
    >
      <div className="flex items-center justify-between mb-1">
        <span
          className="font-mono text-[length:var(--text-xs)] text-text truncate"
          title={entry.label}
        >
          {entry.label}
        </span>
        <span className="font-mono text-[length:var(--text-xs)] text-muted tabular-nums">
          {entry.percent}%
        </span>
      </div>
      <div className="h-1 bg-muted/20 rounded-sm overflow-hidden">
        <div
          className={cn('h-full rounded-sm transition-all duration-300', progressColor)}
          style={{ width: `${entry.percent}%` }}
          role="progressbar"
          aria-valuenow={entry.percent}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
      {entry.current_plugin && entry.status === 'running' && (
        <div className="text-[length:var(--text-xs)] text-accent mt-1 truncate" title={entry.current_plugin}>
          {entry.current_plugin}
        </div>
      )}
      {entry.error_message && entry.status === 'error' && (
        <div className="text-[length:var(--text-xs)] text-warn mt-1 truncate" title={entry.error_message}>
          {entry.error_message}
        </div>
      )}
    </div>
  );
}
