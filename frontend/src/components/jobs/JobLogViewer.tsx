import { useRef, memo } from 'react';
import { Virtuoso } from 'react-virtuoso';
import { LogLine } from '../LogLine';

const LOG_LINE_HEIGHT = 20;

const LogRowRenderer = memo(function LogRowRenderer({ line, index }: { line: string; index: number }) {
  return <LogLine line={line} index={index} />;
});

interface JobLogViewerProps {
  displayLines: string[];
  wsFailed: boolean;
  jobStatus: string;
}

export function JobLogViewer({ displayLines, wsFailed, jobStatus }: JobLogViewerProps) {
  const logsContainerRef = useRef<HTMLDivElement>(null);

  if (displayLines.length > 50) {
    return (
      <div className="card logs-card">
        <h3>
          📜 Logs ({displayLines.length} lines)
          {wsFailed && jobStatus === 'running' && (
            <span className="ws-status ws-disconnected">Falling back to polling</span>
          )}
        </h3>
        <div className="logs-container" ref={logsContainerRef}>
          <div className="logs-virtualized" style={{ height: 400 }}>
            <Virtuoso
              totalCount={displayLines.length}
              itemContent={(index) => <LogRowRenderer line={displayLines[index]} index={index} />}
              className="scrollbar-cyber"
              overscan={200}
              style={{ height: '100%' }}
            />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card logs-card">
      <h3>
        📜 Logs ({displayLines.length} lines)
        {wsFailed && jobStatus === 'running' && (
          <span className="ws-status ws-disconnected">Falling back to polling</span>
        )}
      </h3>
      <div className="logs-container" ref={logsContainerRef}>
        {displayLines.map((line, i) => (
          <LogLine key={`${line}-${i}`} line={line} index={i} />
        ))}
        {displayLines.length === 0 && (
          <div className="log-line log-line-info">Waiting for output...</div>
        )}
      </div>
    </div>
  );
}
