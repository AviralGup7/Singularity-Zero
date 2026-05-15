import { memo } from 'react';

export interface LogLineProps {
  line: string;
  index?: number;
  style?: React.CSSProperties;
}

export const LogLine = memo(function LogLine({ line, index, style }: LogLineProps) {
  const cssClass = classifyLogLine(line);

  return (
    <div
      className={cssClass}
      style={style}
      data-line-index={index}
    >
      {line}
    </div>
  );
});

function classifyLogLine(line: string): string {
  const lower = line.toLowerCase();
  if (
    lower.includes('error') ||
    lower.includes('exception') ||
    lower.includes('fatal') ||
    lower.includes('traceback')
  ) {
    return 'log-line log-line-error';
  }
  if (lower.includes('warn')) {
    return 'log-line log-line-warn';
  }
  if (
    lower.includes('success') ||
    lower.includes('complete') ||
    lower.includes('done')
  ) {
    return 'log-line log-line-success';
  }
  if (
    lower.includes('info') ||
    lower.includes('starting') ||
    lower.includes('loading')
  ) {
    return 'log-line log-line-info';
  }
  return 'log-line';
}
