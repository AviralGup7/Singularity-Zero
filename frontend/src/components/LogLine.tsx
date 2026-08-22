import { memo, useMemo } from 'react';
import { cn } from '@/lib/utils';

export interface LogLineProps {
  line: string;
  index?: number;
  style?: React.CSSProperties;
}

export const LogLine = memo(function LogLine({ line, index, style }: LogLineProps) {
  const cssClass = useMemo(() => classifyInlineLogLine(line), [line]);

  return (
    <div
      className={cn(
        "px-2 py-0.5 font-mono text-xs leading-relaxed",
        "hover:bg-muted/30 transition-colors duration-100",
        cssClass
      )}
      style={style}
      data-line-index={index}
      role="log"
      aria-label={`Log line ${index ?? ''}: ${line}`}
    >
      {line}
    </div>
  );
});

export function classifyInlineLogLine(line: string): string {
  if (typeof line !== 'string') return 'text-text';
  const lower = line.toLowerCase();
  const looksLikeUrl = /https?:\/\//i.test(line);
  if (
    !looksLikeUrl && (
    lower.includes('error') ||
    lower.includes('exception') ||
    lower.includes('fatal') ||
    lower.includes('traceback')
    )
  ) {
    return 'text-rose-400 bg-rose-500/5';
  }
  if (lower.includes('warn')) {
    return 'text-amber-400 bg-amber-500/5';
  }
  if (
    lower.includes('success') ||
    lower.includes('complete') ||
    lower.includes('done')
  ) {
    return 'text-emerald-400 bg-emerald-500/5';
  }
  if (
    lower.includes('info') ||
    lower.includes('starting') ||
    lower.includes('loading')
  ) {
    return 'text-sky-400 bg-sky-500/5';
  }
  return 'text-text';
}
