import { useEffect, useState, useMemo, useCallback } from 'react';
import { Activity, Clock, Cpu, Search, ChevronRight, ChevronDown, Terminal, Shield, Network } from 'lucide-react';
import { getTraces, getTrace, getTracingConfig, type TraceSummary, type TraceSpan, type TracingConfig } from '@/api/tracing';
import { useToast } from '@/hooks/useToast';
import { format } from 'date-fns';

function formatDuration(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)}μs`;
  if (ms < 1000) return `${ms.toFixed(2)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function SpanRow({ span, depth, startTime }: { span: TraceSpan; depth: number; startTime: number }) {
  const [isOpen, setIsOpen] = useState(false);
  
  const startOffset = (span.start_time_unix_nano / 1000000) - startTime;
  const width = Math.max(0.5, span.duration_ms);
  
  return (
    <div className="border-b border-white/5">
      <div 
        className="flex items-center hover:bg-white/5 cursor-pointer py-2 group"
        onClick={() => setIsOpen(!isOpen)}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setIsOpen(!isOpen); } }}
        role="button"
        tabIndex={0}
      >
        <div className="flex-1 flex items-center min-w-0 pr-4">
          <div style={{ paddingLeft: `${depth * 1.5}rem` }} className="flex items-center gap-2 min-w-0 flex-1">
            {span.events?.length > 0 ? (
              isOpen ? <ChevronDown size={14} className="text-muted shrink-0" /> : <ChevronRight size={14} className="text-muted shrink-0" />
            ) : (
              <div className="w-[14px] shrink-0" />
            )}
            <span className={`text-xs font-mono truncate ${span.status === 'ERROR' ? 'text-bad' : 'text-text'}`}>
              {span.name}
            </span>
            <span className="text-[10px] text-muted-foreground uppercase tracking-tighter shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
              {span.service_name}
            </span>
          </div>
          
          <div className="w-1/2 h-4 relative flex items-center ml-4">
             <div 
               className={`h-2 rounded-sm absolute ${span.status === 'ERROR' ? 'bg-bad/60' : 'bg-accent/60'}`}
               style={{ 
                 left: `${(startOffset / 10) % 100}%`, 
                 width: `${(width / 10) % 100}%`,
                 minWidth: '2px'
               }}
             />
          </div>
        </div>
        <div className="w-24 text-right text-[10px] font-mono text-muted-foreground px-4">
          {formatDuration(span.duration_ms)}
        </div>
      </div>
      
      {isOpen && (
        <div className="bg-black/40 p-4 border-l-2 border-accent/20 ml-8 my-2 rounded-r-xl space-y-4">
           <div className="grid grid-cols-2 gap-4">
              <div>
                 <h5 className="text-[9px] font-black uppercase tracking-widest text-muted mb-2">Attributes</h5>
                 <div className="space-y-1">
                    {Object.entries(span.attributes || {}).map(([k, v]) => (
                      <div key={k} className="flex gap-2 text-[10px] font-mono">
                         <span className="text-accent/60">{k}:</span>
                         <span className="text-text/80 break-all">{String(v)}</span>
                      </div>
                    ))}
                 </div>
              </div>
              {span.events?.length > 0 && (
                <div>
                   <h5 className="text-[9px] font-black uppercase tracking-widest text-muted mb-2">Events</h5>
                   <div className="space-y-2">
                      {span.events.map((e, i) => (
                        <div key={i} className="text-[10px] bg-white/5 p-2 rounded border border-white/5">
                           <div className="font-bold text-accent mb-1">{String(e.name)}</div>
                           {e.attributes && Object.entries(e.attributes).map(([k, v]) => (
                             <div key={k} className="flex gap-2 opacity-60">
                                <span>{k}:</span>
                                <span>{String(v)}</span>
                             </div>
                           ))}
                        </div>
                      ))}
                   </div>
                </div>
              )}
           </div>
        </div>
      )}
    </div>
  );
}

export function TracePage() {
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [config, setConfig] = useState<TracingConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);
  const [traceDetail, setTraceDetail] = useState<TraceSpan[]>([]);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [search, setSearch] = useState('');
  const toast = useToast();

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [tracesRes, configRes] = await Promise.all([
        getTraces({ limit: 50 }),
        getTracingConfig()
      ]);
      setTraces(tracesRes);
      setConfig(configRes);
    } catch (error) {
      console.error('Failed to load tracing telemetry:', error);
      toast.error('Failed to load tracing telemetry');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSelectTrace = async (id: string) => {
    setSelectedTraceId(id);
    setLoadingDetail(true);
    try {
      const detail = await getTrace(id);
      setTraceDetail(detail.spans || []);
    } catch (error) {
      console.error('Failed to fetch trace waterfall:', error);
      toast.error('Failed to fetch trace waterfall');
    } finally {
      setLoadingDetail(false);
    }
  };

  const filteredTraces = useMemo(() => {
    if (!search) return traces;
    return traces.filter(t => 
      t.name.toLowerCase().includes(search.toLowerCase()) || 
      t.trace_id.toLowerCase().includes(search.toLowerCase()) ||
      t.service_name.toLowerCase().includes(search.toLowerCase())
    );
  }, [traces, search]);

  const rootStartTime = useMemo(() => {
    if (traceDetail.length === 0) return 0;
    return Math.min(...traceDetail.map(s => s.start_time_unix_nano / 1000000));
  }, [traceDetail]);

  return (
    <div className="flex h-full bg-bg">
      {/* Sidebar: Trace List */}
      <aside className="w-[400px] border-r border-white/10 flex flex-col bg-black/20">
        <div className="p-6 border-b border-white/10 space-y-4">
           <div className="flex items-center justify-between">
              <h2 className="text-sm font-black uppercase tracking-[0.2em] text-accent">Distributed Traces</h2>
              <button onClick={loadData} className="text-muted hover:text-white transition-colors">
                 <Activity size={16} />
              </button>
           </div>
           
           <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input 
                type="text" 
                placeholder="SEARCH TRACE ID / SERVICE..."
                className="w-full bg-white/5 border border-white/10 rounded-lg py-2 pl-10 pr-4 text-[10px] font-mono uppercase tracking-widest text-text focus:border-accent/50 outline-none"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
           </div>

           {config && (
             <div className="flex items-center gap-3 p-3 rounded-xl bg-accent/5 border border-accent/10">
                <Network size={16} className={config.status === 'connected' ? 'text-ok' : 'text-bad'} />
                <div className="min-w-0">
                   <div className="text-[9px] font-black uppercase tracking-widest text-muted">OTLP Exporter</div>
                   <div className="text-[10px] font-mono truncate text-text/80">{config.endpoint}</div>
                </div>
             </div>
           )}
        </div>

        <div className="flex-1 overflow-y-auto scrollbar-cyber">
          {loading ? (
            <div className="p-10 text-center animate-pulse text-[10px] uppercase tracking-widest text-muted">
              Syncing Span Store...
            </div>
          ) : filteredTraces.length === 0 ? (
            <div className="p-10 text-center text-[10px] uppercase tracking-widest text-muted opacity-40">
               No traces found
            </div>
          ) : (
            filteredTraces.map((trace) => (
              <button
                key={trace.trace_id}
                onClick={() => handleSelectTrace(trace.trace_id)}
                className={`w-full text-left p-6 border-b border-white/5 transition-all hover:bg-white/5 ${selectedTraceId === trace.trace_id ? 'bg-accent/10 border-r-2 border-r-accent' : ''}`}
              >
                <div className="flex justify-between items-start mb-2">
                   <div className={`px-1.5 py-0.5 rounded-[4px] text-[8px] font-black uppercase tracking-widest ${trace.status === 'ERROR' ? 'bg-bad text-white' : 'bg-ok text-black'}`}>
                      {trace.status}
                   </div>
                   <span className="text-[9px] font-mono text-muted">
                      {format(trace.start_ns / 1000000, 'HH:mm:ss.SSS')}
                   </span>
                </div>
                <h3 className="text-xs font-bold text-text mb-1 truncate">{trace.name}</h3>
                <div className="flex items-center gap-3 text-[10px] font-mono text-muted uppercase tracking-tighter">
                   <span className="flex items-center gap-1"><Terminal size={10} /> {trace.service_name}</span>
                   <span className="flex items-center gap-1"><Clock size={10} /> {formatDuration(trace.duration_ms)}</span>
                </div>
              </button>
            ))
          )}
        </div>
      </aside>

      {/* Main Content: Trace Detail / Waterfall */}
      <main className="flex-1 flex flex-col min-w-0">
        {!selectedTraceId ? (
          <div className="flex-1 flex flex-col items-center justify-center opacity-20">
             <Shield size={64} className="text-muted mb-4" />
             <p className="text-xs font-black uppercase tracking-[0.4em] text-muted">Select a trace to analyze span waterfall</p>
          </div>
        ) : loadingDetail ? (
          <div className="flex-1 flex items-center justify-center animate-pulse font-mono text-xs uppercase tracking-widest text-accent">
            Reconstructing Waterfall Topology...
          </div>
        ) : (
          <>
            <div className="p-8 border-b border-white/10 bg-black/40">
               <div className="flex items-center gap-4 mb-4">
                  <div className="h-12 w-12 rounded-xl border border-accent/20 bg-accent/10 grid place-items-center text-accent">
                     <Cpu size={24} />
                  </div>
                  <div>
                     <h2 className="text-xl font-black text-text uppercase tracking-tighter">
                        {traceDetail[0]?.name || 'Trace Waterfall'}
                     </h2>
                     <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                        TRACE_ID: {selectedTraceId}
                     </div>
                  </div>
               </div>

               <div className="grid grid-cols-4 gap-4">
                  <div className="glass-panel p-4 rounded-xl">
                     <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Total Spans</div>
                     <div className="text-xl font-black text-[var(--text-primary)]">{traceDetail.length}</div>
                  </div>
                  <div className="glass-panel p-4 rounded-xl">
                     <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Duration</div>
                     <div className="text-xl font-black text-accent">{formatDuration(Math.max(...traceDetail.map(s => s.duration_ms)))}</div>
                  </div>
                  <div className="glass-panel p-4 rounded-xl">
                     <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Service Count</div>
                     <div className="text-xl font-black text-[var(--text-primary)]">{new Set(traceDetail.map(s => s.service_name)).size}</div>
                  </div>
                  <div className="glass-panel p-4 rounded-xl">
                     <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Status</div>
                     <div className={`text-xl font-black ${traceDetail.some(s => s.status === 'ERROR') ? 'text-bad' : 'text-ok'}`}>
                        {traceDetail.some(s => s.status === 'ERROR') ? 'DEGRADED' : 'HEALTHY'}
                     </div>
                  </div>
               </div>
            </div>

            <div className="flex-1 overflow-y-auto scrollbar-cyber p-8">
               <div className="rounded-2xl border border-white/10 bg-black/20 overflow-hidden">
                  <div className="flex items-center bg-white/5 border-b border-white/10 py-2 px-4 text-[9px] font-black uppercase tracking-widest text-muted">
                     <div className="flex-1">Operation Waterfall</div>
                     <div className="w-24 text-right">Duration</div>
                  </div>
                  <div className="divide-y divide-white/5">
                     {traceDetail.map((span) => (
                        <SpanRow 
                          key={span.span_id} 
                          span={span} 
                          depth={0} // Ideally we'd calculate depth from parent_span_id
                          startTime={rootStartTime} 
                        />
                     ))}
                  </div>
               </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
