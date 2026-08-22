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
      className={cn('log-line', cssClass)}
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
    return 'log-line-error';
  }
  if (lower.includes('warn')) {
    return 'log-line-warn';
  }
  if (
    lower.includes('success') ||
    lower.includes('complete') ||
    lower.includes('done')
  ) {
    return 'log-line-success';
  }
  if (
    lower.includes('info') ||
    lower.includes('starting') ||
    lower.includes('loading')
  ) {
    return 'log-line-info';
  }
  return '';
}
