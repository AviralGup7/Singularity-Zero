import { useRef, useEffect, type ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { StatusBadge } from './StatusBadge';

export interface LogEntry {
  timestamp?: string;
  level?: string;
  message: string;
  source?: string;
}

export interface LogViewerProps {
  entries: LogEntry[];
  maxHeight?: string;
  showLevel?: boolean;
  showTimestamp?: boolean;
  showSource?: boolean;
  className?: string;
  autoScroll?: boolean;
  emptyMessage?: string;
  renderEntry?: (entry: LogEntry, index: number) => ReactNode;
}

const levelColors: Record<string, string> = {
  error: 'text-rose-400',
  warn: 'text-amber-400',
  warning: 'text-amber-400',
  info: 'text-blue-400',
  debug: 'text-muted-foreground',
  trace: 'text-muted-foreground/60',
};

export function LogViewer({
  entries,
  maxHeight = '400px',
  showLevel = true,
  showTimestamp = true,
  showSource = false,
  className,
  autoScroll = true,
  emptyMessage = 'No log entries',
  renderEntry,
}: LogViewerProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [entries, autoScroll]);

  if (entries.length === 0) {
    return (
      <div className={cn("flex items-center justify-center h-32 text-muted-foreground text-sm", className)}>
        {emptyMessage}
      </div>
    );
  }

  return (
    <div
      className={cn("overflow-y-auto font-mono text-xs space-y-0.5 p-3 bg-black/40 rounded-lg border", className)}
      style={{ maxHeight }}
    >
      {entries.map((entry, i) => {
        if (renderEntry) return <div key={`${entry.timestamp}-${entry.message}-${i}`}>{renderEntry(entry, i)}</div>;

        return (
          <div key={`${entry.timestamp}-${entry.message}-${i}`} className="flex items-start gap-2 py-0.5 hover:bg-white/5 rounded px-1 transition-colors">
            {showTimestamp && entry.timestamp && (
              <span className="shrink-0 text-muted-foreground/60 w-16">{entry.timestamp}</span>
            )}
            {showLevel && entry.level && (
              <span className={cn("shrink-0 uppercase w-12", levelColors[entry.level.toLowerCase()] ?? 'text-muted-foreground')}>
                {entry.level}
              </span>
            )}
            {showSource && entry.source && (
              <StatusBadge status="neutral" label={entry.source} showDot={false} className="shrink-0" />
            )}
            <span className="break-all text-foreground/90">{entry.message}</span>
          </div>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}
