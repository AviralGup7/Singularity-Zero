import { useCallback, useRef } from 'react';
import { LogLine } from '../LogLine';
import { List as VirtualList, type RowComponentProps } from 'react-window';

const LOG_LINE_HEIGHT = 20;

interface LogRowData {
  lines: string[];
}

function LogRowRenderer(props: RowComponentProps<LogRowData>) {
  const { index, style, lines } = props;
  // eslint-disable-next-line security/detect-object-injection
  return <LogLine line={lines[index]} index={index} style={style} />;
}

interface JobLogViewerProps {
  displayLines: string[];
  wsFailed: boolean;
  jobStatus: string;
}

export function JobLogViewer({ displayLines, wsFailed, jobStatus }: JobLogViewerProps) {
  const logsContainerRef = useRef<HTMLDivElement>(null);

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    const threshold = 60;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < threshold;
    (el as HTMLDivElement).dataset.autoScroll = String(atBottom);
  }, []);

  if (displayLines.length > 50) {
    return (
      <div className="card logs-card">
        <h3>
          📜 Logs ({displayLines.length} lines)
          {wsFailed && jobStatus === 'running' && (
            <span className="ws-status ws-disconnected">Falling back to polling</span>
          )}
        </h3>
        <div
          className="logs-container"
          ref={logsContainerRef}
          onScroll={handleScroll}
        >
          <div className="logs-virtualized" style={{ height: 400 }}>
            <VirtualList<LogRowData>
              key={displayLines.length}
              rowCount={displayLines.length}
              rowHeight={LOG_LINE_HEIGHT}
              defaultHeight={400}
              rowProps={{ lines: displayLines }}
              rowComponent={LogRowRenderer}
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
      <div
        className="logs-container"
        ref={logsContainerRef}
        onScroll={handleScroll}
      >
        {displayLines.map((line, i) => (
          <LogLine key={i} line={line} index={i} />
        ))}
        {displayLines.length === 0 && (
          <div className="log-line log-line-info">Waiting for output...</div>
        )}
      </div>
    </div>
  );
}
