import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, ExternalLink, RefreshCw, Zap, ChevronRight } from 'lucide-react';
import { getTrace, getTraces, getTracingConfig, type TraceDetail, type TraceSpan, type TraceSummary, type TracingConfig } from '@/api/tracing';
import { PageHeader, GlassCard, Button } from '@/components/ui';

const TIME_RANGES = [
  { label: '15m', value: 15 * 60 * 1000 },
  { label: '1h', value: 60 * 60 * 1000 },
  { label: '6h', value: 6 * 60 * 60 * 1000 },
  { label: '24h', value: 24 * 60 * 60 * 1000 },
];

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

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
      <div className="trace-empty flex flex-col items-center justify-center py-16 text-[var(--text-secondary)] border border-[var(--border)] rounded-xl bg-[var(--surface-2)]">
        <Zap size={32} className="text-[var(--text-tertiary)] mb-2 opacity-50" />
        <span>Select a trace from the ledger to inspect the execution waterfall.</span>
      </div>
    );
  }

  const width = 980;
  const labelWidth = 260;
  const rowHeight = 34;
  const height = Math.max(120, spans.length * rowHeight + 42);
  const timelineWidth = width - labelWidth - 24;

  return (
    <div className="trace-waterfall-shell card bg-[var(--surface)] border border-[var(--border)] p-4 rounded-xl shadow-lg">
      <div className="trace-waterfall-head flex items-center justify-between pb-3 border-b border-[var(--border)] mb-4 font-mono text-xs">
        <div>
          <strong className="text-[var(--text-primary)]">Trace ID: </strong>
          <span className="text-[var(--accent)]">{trace.trace_id}</span>
        </div>
        <span className="bg-[var(--accent-soft)] text-[var(--accent)] px-2.5 py-0.5 rounded-full font-bold">{spans.length} spans</span>
      </div>
      <div className="trace-waterfall-scroll overflow-x-auto">
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
            
            // Depth-based opacity gradient
            const rowOpacity = Math.max(0.45, 1 - depth * 0.1);

            return (
              <motion.g
                key={span.span_id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: rowOpacity, x: 0 }}
                transition={{ duration: 0.3, delay: index * 0.025, ease: EASE_OUT }}
              >
                <text x={14 + depth * 16} y={y + 15} className="trace-span-label fill-[var(--text-primary)] text-[11px] font-semibold">
                  {span.stage_name || span.name}
                </text>
                <text x={labelWidth - 82} y={y + 15} className="trace-span-duration fill-[var(--text-secondary)] font-mono text-[10px]">
                  {formatDuration(span.duration_ms)}
                </text>
                
                {/* Cascade grow animation with custom tooltip */}
                <motion.rect
                  x={x}
                  y={y}
                  width={barWidth}
                  height={18}
                  rx={4}
                  initial={{ width: 0 }}
                  animate={{ width: barWidth }}
                  transition={{ duration: 0.5, delay: index * 0.02 + 0.1, ease: EASE_OUT }}
                  className={isError ? 'trace-bar trace-bar-error cursor-pointer' : 'trace-bar cursor-pointer'}
                >
                  <title>{`${span.stage_name || span.name}: ${formatDuration(span.duration_ms)} (Start: ${formatDuration((span.start_time_unix_nano - bounds.start) / 1_000_000)})`}</title>
                </motion.rect>
                {isError && <circle cx={Math.min(width - 16, x + barWidth + 8)} cy={y + 9} r={4} className="trace-error-dot" />}
              </motion.g>
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

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.05 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100, damping: 15 } }
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="tracing-page space-y-6"
    >
      <PageHeader
        icon={<Zap size={20} />}
        title="Distributed Tracing"
        subtitle="Real-time execution waterfall and OTLP exporter diagnostics."
      />

      {config && (
        <motion.div variants={itemVariants}>
          <GlassCard
            variant={config.status === 'unreachable' ? 'error' : 'success'}
            className="p-4"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className={`h-10 w-10 rounded-full grid place-items-center ${config.status === 'unreachable' ? 'bg-bad/10 text-bad' : 'bg-ok/10 text-ok'}`}>
                  {config.status === 'unreachable' ? <AlertTriangle size={20} /> : <Zap size={20} />}
                </div>
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider">OTLP Exporter Status: {config.status}</h3>
                  <p className="text-xs text-[var(--text-secondary)] font-mono">{config.endpoint}</p>
                </div>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-[10px] uppercase font-bold text-[var(--text-secondary)] font-mono">
                <div className="flex flex-col">
                  <span>OTEL Available</span>
                  <span className={config.otel_available ? 'text-[var(--ok)]' : 'text-[var(--bad)]'}>{config.otel_available ? 'Yes' : 'No'}</span>
                </div>
                <div className="flex flex-col">
                  <span>Local Span DB</span>
                  <span className="text-[var(--text-primary)] truncate max-w-[120px]" title={config.local_span_db}>{config.local_span_db}</span>
                </div>
                <div className="flex flex-col">
                  <span>Init Error</span>
                  <span className="text-[var(--text-primary)] truncate max-w-[120px]" title={config.initialization_error || 'None'}>{config.initialization_error || 'None'}</span>
                </div>
                {config.status === 'unreachable' && (
                  <a href="https://opentelemetry.io/docs/collector/quick-start/" target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[var(--accent)] hover:underline">
                    <span>Debug</span>
                    <ExternalLink size={10} />
                  </a>
                )}
              </div>
            </div>
          </GlassCard>
        </motion.div>
      )}

      {/* Toolbar filters with sliding time highlight */}
      <motion.section variants={itemVariants} className="trace-toolbar flex flex-wrap items-center justify-between gap-4 p-3 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow" aria-label="Trace filters">
        <div className="trace-field flex items-center gap-3">
          <label htmlFor="trace-service" className="text-xs font-semibold text-[var(--text-secondary)] font-mono uppercase">Stage</label>
          <div className="relative">
            <input
              id="trace-service"
              list="trace-services"
              value={serviceName}
              onChange={event => setServiceName(event.target.value)}
              placeholder="All stages"
              className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200"
            />
            <datalist id="trace-services">
              {services.map(service => <option key={service} value={service} />)}
            </datalist>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          {/* Time segments relative container with Framer Motion slide backdrop */}
          <div className="trace-segments relative flex bg-[var(--surface-2)] p-1 rounded-lg border border-[var(--border)]" role="group" aria-label="Time range">
            {TIME_RANGES.map(range => {
              const isActive = range.value === rangeMs;
              return (
                <button
                  key={range.label}
                  type="button"
                  className={`relative z-10 px-3 py-1 text-xs font-semibold rounded transition-colors duration-200 ${
                    isActive ? 'text-[var(--accent)] font-bold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                  }`}
                  onClick={() => setRangeMs(range.value)}
                  style={{ background: 'transparent' }}
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeRangeHighlight"
                      className="absolute inset-0 bg-[var(--accent-soft)] border border-[var(--accent)]/20 rounded z-[-1]"
                      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                    />
                  )}
                  {range.label}
                </button>
              );
            })}
          </div>
          
          <Button variant="secondary" onClick={() => refresh()} disabled={loading} size="sm" className="flex items-center gap-1.5">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} aria-hidden="true" />
            <span>Refresh</span>
          </Button>
        </div>
      </motion.section>

      {/* Main Ledger Table and Waterfall Area */}
      <AnimatePresence mode="wait">
        {loading && traces.length === 0 ? (
          <motion.div
            key="skeleton"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-pulse"
          >
            <div className="lg:col-span-1 space-y-3 card p-4 border border-[var(--border)]">
              {Array.from({ length: 7 }).map((_, i) => (
                <div key={i} className="h-10 bg-[var(--surface-3)] rounded" />
              ))}
            </div>
            <div className="lg:col-span-2 space-y-4 card p-4 border border-[var(--border)]">
              <div className="h-6 w-1/4 bg-[var(--surface-3)] rounded" />
              <div className="h-4 w-1/3 bg-[var(--surface-3)] rounded" />
              <div className="h-48 bg-[var(--surface-3)] rounded" />
            </div>
          </motion.div>
        ) : (
          <motion.section
            key="content"
            variants={itemVariants}
            className="trace-grid-layout grid grid-cols-1 lg:grid-cols-3 gap-6"
          >
            <div className="trace-table-shell card bg-[var(--surface)] border border-[var(--border)] rounded-xl overflow-hidden shadow">
              <table className="trace-table w-full">
                <thead>
                  <tr className="bg-[var(--surface-2)] border-b border-[var(--border)] text-muted text-xs">
                    <th className="py-2.5 px-3 text-left">Root span</th>
                    <th className="py-2.5 px-3 text-left">Start</th>
                    <th className="py-2.5 px-3 text-left">Duration</th>
                    <th className="py-2.5 px-3 text-left">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {traces.map(trace => {
                    const isSelected = trace.trace_id === selectedTraceId;
                    return (
                      <tr
                        key={trace.trace_id}
                        className={`border-b border-[var(--border)] hover:bg-white/5 cursor-pointer transition-colors duration-150 ${
                          isSelected ? 'bg-[var(--accent-soft)]/20' : ''
                        }`}
                        onClick={() => setSelectedTraceId(trace.trace_id)}
                      >
                        <td className="py-3 px-3">
                          <div className="flex items-center gap-1.5">
                            <ChevronRight size={14} className={`text-[var(--text-tertiary)] transform transition-transform ${isSelected ? 'rotate-90 text-[var(--accent)]' : ''}`} />
                            <strong className="text-sm text-[var(--text-primary)]">{trace.stage_name || trace.name}</strong>
                          </div>
                          <span className="block text-[10px] text-[var(--text-secondary)] font-mono ml-5">
                            {shortTrace(trace.trace_id)} · {trace.span_count} spans
                          </span>
                        </td>
                        <td className="py-3 px-3 text-xs text-[var(--text-secondary)] font-mono">{formatTime(trace.start_ns)}</td>
                        <td className="py-3 px-3 text-xs text-[var(--text-secondary)] font-mono">{formatDuration(trace.duration_ms)}</td>
                        <td className="py-3 px-3">
                          <span className={`trace-status text-[10px] font-bold px-2 py-0.5 rounded ${
                            trace.status === 'ERROR' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          }`}>{trace.status}</span>
                        </td>
                      </tr>
                    );
                  })}
                  {traces.length === 0 && (
                    <tr>
                      <td colSpan={4} className="trace-empty-cell py-8 text-center text-xs text-[var(--text-secondary)] font-mono">No traces found for the selected filters.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            
            <div className="lg:col-span-2">
              <TraceWaterfall trace={traceDetail} />
            </div>
          </motion.section>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
