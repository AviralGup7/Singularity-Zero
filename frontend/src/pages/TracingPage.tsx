import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ExternalLink, RefreshCw, Zap } from 'lucide-react';
import { getTrace, getTraces, getTracingConfig, type TraceDetail, type TraceSpan, type TraceSummary, type TracingConfig } from '@/api/tracing';

const TIME_RANGES = [
  { label: '15m', value: 15 * 60 * 1000 },
  { label: '1h', value: 60 * 60 * 1000 },
  { label: '6h', value: 6 * 60 * 60 * 1000 },
  { label: '24h', value: 24 * 60 * 60 * 1000 },
];

function formatTime(ns: number): string {
  return new Date(Math.floor(ns / 1_000_000)).toLocaleTimeString();
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function shortTrace(id: string): string {
  return id ? `${id.slice(0, 8)}...${id.slice(-6)}` : '';
}

function buildDepths(spans: TraceSpan[]): Map<string, number> {
   
  const byId = new Map(spans.map(span => [span.span_id, span]));
  const depths = new Map<string, number>();
  const visit = (span: TraceSpan): number => {
    if (depths.has(span.span_id)) return depths.get(span.span_id) ?? 0;
    if (!span.parent_span_id || !byId.has(span.parent_span_id)) {
      depths.set(span.span_id, 0);
      return 0;
    }
    const parent = byId.get(span.parent_span_id);
    const depth = parent ? visit(parent) + 1 : 0;
    depths.set(span.span_id, depth);
    return depth;
  };
  spans.forEach(visit);
  return depths;
}

function TraceWaterfall({ trace }: { trace: TraceDetail | null }) {
   
  const spans = useMemo(() => trace?.spans ?? [], [trace]);
  const bounds = useMemo(() => {
    const start = Math.min(...spans.map(span => span.start_time_unix_nano), Number.MAX_SAFE_INTEGER);
    const end = Math.max(...spans.map(span => span.end_time_unix_nano), 0);
    return { start, end, duration: Math.max(1, end - start) };
   
  }, [spans]);
   
  const depths = useMemo(() => buildDepths(spans), [spans]);

  if (!trace || spans.length === 0) {
    return (
      <div className="trace-empty">
        Select a trace to inspect the stage waterfall.
      </div>
    );
  }

  const width = 980;
  const labelWidth = 260;
  const rowHeight = 34;
  const height = Math.max(120, spans.length * rowHeight + 42);
  const timelineWidth = width - labelWidth - 24;

  return (
    <div className="trace-waterfall-shell">
      <div className="trace-waterfall-head">
        <strong>{shortTrace(trace.trace_id)}</strong>
        <span>{spans.length} spans</span>
      </div>
      <div className="trace-waterfall-scroll">
        <svg className="trace-waterfall" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Trace waterfall">
          <line x1={labelWidth} y1={18} x2={width - 12} y2={18} className="trace-axis" />
          {[0, 0.25, 0.5, 0.75, 1].map(tick => (
            <g key={tick}>
              <line x1={labelWidth + tick * timelineWidth} y1={14} x2={labelWidth + tick * timelineWidth} y2={height - 8} className="trace-grid" />
              <text x={labelWidth + tick * timelineWidth + 4} y={12} className="trace-tick">
                {formatDuration((bounds.duration / 1_000_000) * tick)}
              </text>
            </g>
          ))}
          {spans.map((span, index) => {
            const y = 34 + index * rowHeight;
            const depth = depths.get(span.span_id) ?? 0;
            const x = labelWidth + ((span.start_time_unix_nano - bounds.start) / bounds.duration) * timelineWidth;
            const barWidth = Math.max(2, ((span.end_time_unix_nano - span.start_time_unix_nano) / bounds.duration) * timelineWidth);
            const isError = span.status === 'ERROR';
            return (
              <g key={span.span_id}>
                <text x={14 + depth * 16} y={y + 15} className="trace-span-label">
                  {span.stage_name || span.name}
                </text>
                <text x={labelWidth - 82} y={y + 15} className="trace-span-duration">
                  {formatDuration(span.duration_ms)}
                </text>
                <rect
                  x={x}
                  y={y}
                  width={barWidth}
                  height={18}
                  rx={5}
                  className={isError ? 'trace-bar trace-bar-error' : 'trace-bar'}
                />
                {isError && <circle cx={Math.min(width - 16, x + barWidth + 8)} cy={y + 9} r={4} className="trace-error-dot" />}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

export function TracingPage() {
   
  const [config, setConfig] = useState<TracingConfig | null>(null);
   
  const [traces, setTraces] = useState<TraceSummary[]>([]);
   
  const [selectedTraceId, setSelectedTraceId] = useState<string>('');
   
  const [traceDetail, setTraceDetail] = useState<TraceDetail | null>(null);
   
  const [serviceName, setServiceName] = useState('');
   
  const [rangeMs, setRangeMs] = useState(TIME_RANGES[1].value);
   
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const endMs = Date.now();
   
      const [nextConfig, nextTraces] = await Promise.all([
        getTracingConfig(signal),
        getTraces({
          serviceName: serviceName || undefined,
          startMs: endMs - rangeMs,
          endMs,
          limit: 100,
          signal,
        }),
      ]);
      setConfig(nextConfig);
      setTraces(nextTraces);
   
      if (!selectedTraceId && nextTraces[0]) setSelectedTraceId(nextTraces[0].trace_id);
    } finally {
      setLoading(false);
    }
   
  }, [rangeMs, selectedTraceId, serviceName]);

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal).catch(() => undefined);
    const timer = window.setInterval(() => {
      refresh(controller.signal).catch(() => undefined);
    }, 10_000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
   
  }, [refresh]);

  useEffect(() => {
    if (!selectedTraceId) return;
    const controller = new AbortController();
    getTrace(selectedTraceId, controller.signal)
      .then(setTraceDetail)
      .catch(() => setTraceDetail(null));
    return () => controller.abort();
   
  }, [selectedTraceId]);

  const services = useMemo(() => {
    const names = new Set<string>();
    traces.forEach(trace => {
      if (trace.stage_name) names.add(trace.stage_name);
      if (trace.service_name) names.add(trace.service_name);
    });
    return Array.from(names).sort();
   
  }, [traces]);

  return (
    <div className="tracing-page">
      {config && (
        <section className={`trace-config-panel card mb-4 border-l-4 ${config.status === 'unreachable' ? 'border-bad' : 'border-ok'}`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-full grid place-items-center ${config.status === 'unreachable' ? 'bg-bad/10 text-bad' : 'bg-ok/10 text-ok'}`}>
                {config.status === 'unreachable' ? <AlertTriangle size={20} /> : <Zap size={20} />}
              </div>
              <div>
                <h3 className="text-sm font-bold uppercase tracking-wider">OTLP Exporter Status: {config.status}</h3>
                <p className="text-xs text-muted font-mono">{config.endpoint}</p>
              </div>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-[10px] uppercase font-bold text-muted">
              <div className="flex flex-col">
                <span>OTEL Available</span>
                <span className={config.otel_available ? 'text-ok' : 'text-bad'}>{config.otel_available ? 'Yes' : 'No'}</span>
              </div>
              <div className="flex flex-col">
                <span>Local Span DB</span>
                <span className="text-text truncate max-w-[120px]" title={config.local_span_db}>{config.local_span_db}</span>
              </div>
              <div className="flex flex-col">
                <span>Init Error</span>
                <span className="text-text truncate max-w-[120px]" title={config.initialization_error || 'None'}>{config.initialization_error || 'None'}</span>
              </div>
              {config.status === 'unreachable' && (
                <a href="https://opentelemetry.io/docs/collector/quick-start/" target="_blank" rel="noreferrer" className="flex items-center gap-1 text-accent hover:underline">
                  Debug <ExternalLink size={10} />
                </a>
              )}
            </div>
          </div>
        </section>
      )}

      <section className="trace-toolbar" aria-label="Trace filters">
        <div className="trace-field">
          <label htmlFor="trace-service">Service</label>
          <input
            id="trace-service"
            list="trace-services"
            value={serviceName}
            onChange={event => setServiceName(event.target.value)}
            placeholder="All stages"
          />
          <datalist id="trace-services">
            {services.map(service => <option key={service} value={service} />)}
          </datalist>
        </div>
        <div className="trace-segments" role="group" aria-label="Time range">
          {TIME_RANGES.map(range => (
            <button
              key={range.label}
              type="button"
              className={range.value === rangeMs ? 'active' : ''}
              onClick={() => setRangeMs(range.value)}
            >
              {range.label}
            </button>
          ))}
        </div>
        <button className="btn btn-secondary trace-refresh" type="button" onClick={() => refresh()} disabled={loading}>
          <RefreshCw size={15} aria-hidden="true" />
          Refresh
        </button>
      </section>

      <section className="trace-grid-layout">
        <div className="trace-table-shell">
          <table className="trace-table">
            <thead>
              <tr>
                <th>Root span</th>
                <th>Start</th>
                <th>Duration</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {traces.map(trace => (
                <tr
                  key={trace.trace_id}
                  className={trace.trace_id === selectedTraceId ? 'selected' : ''}
                  onClick={() => setSelectedTraceId(trace.trace_id)}
                >
                  <td>
                    <strong>{trace.stage_name || trace.name}</strong>
                    <span>{shortTrace(trace.trace_id)} · {trace.span_count} spans</span>
                  </td>
                  <td>{formatTime(trace.start_ns)}</td>
                  <td>{formatDuration(trace.duration_ms)}</td>
                  <td><span className={trace.status === 'ERROR' ? 'trace-status error' : 'trace-status ok'}>{trace.status}</span></td>
                </tr>
              ))}
              {traces.length === 0 && (
                <tr>
                  <td colSpan={4} className="trace-empty-cell">No traces found for the selected filters.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <TraceWaterfall trace={traceDetail} />
      </section>
    </div>
  );
}
