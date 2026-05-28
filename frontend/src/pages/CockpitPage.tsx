import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Icon } from '@/components/Icon';
import { AttackChainVisualizer } from '@/components/AttackChainVisualizer';
import { AttackChainGraph3D } from '@/components/charts';
import { apiClient } from '@/api/client';
import { cockpitApi } from '@/api/cockpit';
import type { CockpitEdge, CockpitNode, ForensicExchange } from '@/api/cockpit';
import { createNote, getNotes } from '@/api/notes';
import type { Note } from '@/api/notes';
import type { AttackChain, MeshHealth, Job } from '@/types/api';
import { useSSEProgress } from '@/hooks/useSSEProgress';
import { useToast } from '@/hooks/useToast';
import { startJob, stopJob, restartJob, getJob } from '@/api/jobs';

interface MigrationEvent {
  id: string;
  timestamp: number;
  actor_id: string;
  source_node: string;
  target_node: string;
  [key: string]: unknown;
}

function metadataText(metadata: CockpitNode['metadata'], key: string): string {
  const value = metadata ? Reflect.get(metadata, key) : undefined;
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return String(value);
}

function ForensicExchangeItem({ exchange, onOpen }: { exchange: ForensicExchange; onOpen: (id: string) => void }) {
  const responseStatus = exchange.response_status || exchange.response?.status;
  return (
    <button
      type="button"
      className="w-full rounded border border-line bg-black/20 p-3 text-left transition-colors hover:bg-black/40 focus:border-accent/50 focus:outline-none"
      onClick={() => onOpen(exchange.exchange_id)}
    >
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[10px] text-muted">{exchange.exchange_id}</span>
        <span className="text-[10px] text-muted">{new Date(exchange.timestamp).toLocaleTimeString()}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className={`rounded px-1 text-[10px] font-bold ${responseStatus && responseStatus < 300 ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'}`}>
          {responseStatus}
        </span>
        <span className="truncate text-xs font-bold text-text">{exchange.method} {exchange.url}</span>
      </div>
    </button>
  );
}

function ForensicExchangeDetail({ exchange, onBack }: { exchange: ForensicExchange; onBack: () => void }) {
  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex items-center gap-3 border-b border-line bg-black/20 p-4">
        <button type="button" onClick={onBack} className="text-muted hover:text-text">
          <Icon name="arrowLeft" size={18} />
        </button>
        <div>
          <h4 className="text-sm font-bold text-text">Exchange Details</h4>
          <div className="font-mono text-[10px] text-muted">{exchange.exchange_id}</div>
        </div>
      </div>
      <div className="flex-1 space-y-6 overflow-y-auto p-4">
        <section>
          <div className="mb-2 flex items-center justify-between">
            <h5 className="text-[10px] font-bold uppercase text-muted">Request</h5>
            <span className="text-[10px] text-muted">{exchange.method}</span>
          </div>
          <div className="mb-2 break-all rounded border border-line bg-black/40 p-3 font-mono text-[10px]">{exchange.url}</div>
          <div className="space-y-1">
            {Object.entries(exchange.request?.headers || {}).map(([key, value]) => (
              <div key={key} className="flex gap-2 text-[10px]">
                <span className="min-w-[80px] font-bold text-muted">{key}:</span>
                <span className="break-all text-text">{value}</span>
              </div>
            ))}
          </div>
        </section>
        <section>
          <div className="mb-2 flex items-center justify-between">
            <h5 className="text-[10px] font-bold uppercase text-muted">Response</h5>
            <span className={`text-[10px] font-bold ${exchange.response?.status < 400 ? 'text-green-400' : 'text-red-400'}`}>
              STATUS {exchange.response?.status}
            </span>
          </div>
          {exchange.response?.body_snippet && (
            <pre className="mt-3 overflow-x-auto whitespace-pre-wrap rounded bg-black/60 p-2 text-[10px] text-text">
              {exchange.response.body_snippet}
            </pre>
          )}
        </section>
      </div>
    </div>
  );
}

export function CockpitPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const target = searchParams.get('target') || '';
  const run = searchParams.get('run') || undefined;
  const jobId = searchParams.get('job_id') || undefined;
  const focusFindingId = searchParams.get('focus') || '';

  const [nodes, setNodes] = useState<CockpitNode[]>([]);
  const [edges, setEdges] = useState<CockpitEdge[]>([]);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  useEffect(() => {
    if (focusFindingId && nodes.length > 0) {
      // Find the node that matches this finding ID
      // Finding nodes often have IDs like "finding:HASH"
      const targetNode = nodes.find(n => 
        n.id === focusFindingId || 
        n.id === `finding:${focusFindingId}` ||
        n.metadata?.finding_id === focusFindingId
      );
      if (targetNode) {
        setSelectedNodeId(targetNode.id);
        setSidebarOpen(true);
        setSidebarTab('intel');
      }
    }
  }, [focusFindingId, nodes]);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarTab, setSidebarTab] = useState<'intel' | 'chains' | 'forensics'>('intel');
  const [notes, setNotes] = useState<Note[]>([]);
  const [exchanges, setExchanges] = useState<ForensicExchange[]>([]);
  const [selectedExchange, setSelectedExchange] = useState<ForensicExchange | null>(null);
  const [probing, setProbing] = useState(false);
  const [newNote, setNewNote] = useState('');
  const [activeJobId, setActiveJobId] = useState<string | undefined>(jobId);
  const [meshHealth, setMeshHealth] = useState<MeshHealth | null>(null);
  const [migrations, setMigrations] = useState<MigrationEvent[]>([]);

  const [activeJob, setActiveJob] = useState<Job | null>(null);
  const [isDeckOpen, setIsDeckOpen] = useState(true);
  const [scanMode, setScanMode] = useState<'safe' | 'aggressive'>('safe');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedModules, setSelectedModules] = useState<string[]>([
    'subdomain_enum',
    'url_discovery',
    'port_scan',
    'httpx',
  ]);
  const [launchingScan, setLaunchingScan] = useState(false);
  const [stoppingScan, setStoppingScan] = useState(false);
  const [restartingScan, setRestartingScan] = useState(false);
  const [inputTarget, setInputTarget] = useState(target);

  useEffect(() => {
    if (target) {
      setInputTarget(target);
    }
  }, [target]);

  useEffect(() => {
    if (!activeJobId) {
      setActiveJob(null);
      return;
    }
    let isMounted = true;
    const fetchJobStatus = async () => {
      try {
        const jobData = await getJob(activeJobId);
        if (isMounted) {
          setActiveJob(jobData);
        }
      } catch (error) {
        console.error('Error fetching job details:', error);
      }
    };
    fetchJobStatus();
    const interval = setInterval(fetchJobStatus, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [activeJobId]);

  const handleStartScan = async () => {
    if (!inputTarget.trim()) {
      toast.error('Please enter a target URL/host');
      return;
    }
    try {
      setLaunchingScan(true);
      const newJob = await startJob({
        base_url: inputTarget,
        mode: scanMode,
        modules: selectedModules,
      });
      setActiveJobId(newJob.id);
      setActiveJob(newJob);
      const params = new URLSearchParams(window.location.search);
      params.set('target', inputTarget);
      params.set('job_id', newJob.id);
      navigate({ search: params.toString() });
      toast.success('Multi-stage cyber pipeline successfully launched');
    } catch (error) {
      console.error(error);
      toast.error('Failed to initiate cyber pipeline');
    } finally {
      setLaunchingScan(false);
    }
  };

  const handleStopScan = async () => {
    if (!activeJobId) return;
    try {
      setStoppingScan(true);
      await stopJob(activeJobId);
      toast.success('Pipeline scan termination requested');
    } catch (error) {
      console.error(error);
      toast.error('Termination request failed');
    } finally {
      setStoppingScan(false);
    }
  };

  const handleRestartScan = async () => {
    if (!activeJobId) return;
    try {
      setRestartingScan(true);
      await restartJob(activeJobId);
      toast.success('Safe restart initiated');
    } catch (error) {
      console.error(error);
      toast.error('Safe restart failed');
    } finally {
      setRestartingScan(false);
    }
  };

  const applyGraph = useCallback((data: { nodes: CockpitNode[]; edges: CockpitEdge[] }) => {
    setNodes(data.nodes);
    setEdges(data.edges);
  }, []);

  useEffect(() => {
    if (!jobId && target) {
      apiClient.get<{ id: string }[]>('/api/jobs', { params: { target, status: 'running' } })
        .then((res) => {
          if (res.data.length > 0) setActiveJobId(res.data[0].id);
        })
        .catch((err) => console.error('API Error:', err));
    }
  }, [jobId, target]);

  useSSEProgress({
    jobId: activeJobId,
    enabled: Boolean(activeJobId),
    onEvent: (event) => {
      if (event.event_type === 'mesh_health_update') {
        setMeshHealth(event.data as unknown as MeshHealth);
      } else if (event.event_type === 'migration_event') {
        const data = event.data as Record<string, unknown>;
        const migration: MigrationEvent = {
          id: event.id,
          timestamp: Date.now(),
          actor_id: String(data.actor_id || 'unknown'),
          source_node: String(data.source_node || 'unknown'),
          target_node: String(data.target_node || 'unknown'),
          ...data,
        };
        setMigrations((prev) => [...prev, migration]);
        toast.info(`Ghost-Actor Migration: ${migration.actor_id} moved to ${migration.target_node}`);

        // Hook real-time Kuzu / telemetry update on migration events
        cockpitApi.getGraph(target, run, activeJobId || jobId)
          .then((res) => {
            applyGraph(res.data);
          })
          .catch((err) => console.error('Failed to update graph on migration:', err));
      } else if (
        event.event_type === 'finding_batch' ||
        event.event_type === 'stage_change' ||
        event.event_type === 'progress_update' ||
        event.event_type === 'completed'
      ) {
        // Hook real-time Kuzu / telemetry updates on active job progression
        cockpitApi.getGraph(target, run, activeJobId || jobId)
          .then((res) => {
            applyGraph(res.data);
          })
          .catch((err) => console.error('Failed to update graph on job telemetry:', err));
      }
    },
  });

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        setLoading(true);
        const [graphRes, chainsRes] = await Promise.all([
          cockpitApi.getGraph(target, run, jobId),
          apiClient.get<AttackChain[]>('/api/cockpit/attack-chains', { params: { target } }).catch(() => ({ data: [] })),
        ]);
        applyGraph(graphRes.data);
        setChains(chainsRes.data || []);
      } catch (error) {
        console.error('Failed to fetch cockpit intelligence', error);
      } finally {
        setLoading(false);
      }
    };
    if (target) fetchGraph();
  }, [target, run, jobId, applyGraph]);

  useEffect(() => {
    if (!target) return undefined;
    const stream = new EventSource(cockpitApi.graphStreamUrl(target, run, activeJobId || jobId));
    const handleSnapshot = (event: MessageEvent) => {
      try {
        const parsed = JSON.parse(event.data) as { data?: { nodes: CockpitNode[]; edges: CockpitEdge[] } };
        if (parsed.data) {
          applyGraph(parsed.data);
          setLoading(false);
        }
      } catch {
        // Keep the previous scene if a partial SSE frame arrives.
      }
    };
    stream.addEventListener('graph_snapshot', handleSnapshot);
    stream.onerror = () => stream.close();
    return () => {
      stream.removeEventListener('graph_snapshot', handleSnapshot);
      stream.close();
    };
  }, [target, run, jobId, activeJobId, applyGraph]);

  useEffect(() => {
    if (target && sidebarOpen) {
      getNotes(target).then((res) => setNotes(res.notes)).catch((err) => console.error('API Error:', err));
      cockpitApi.listExchanges(target).then((res) => setExchanges(res.data.exchanges)).catch((err) => console.error('API Error:', err));
    }
  }, [target, sidebarOpen]);

  const selectedNode = useMemo(() => nodes.find((node) => node.id === selectedNodeId), [nodes, selectedNodeId]);
  const hoveredNode = useMemo(() => nodes.find((node) => node.id === hoveredNodeId), [nodes, hoveredNodeId]);
  const selectedNodeUrl = selectedNode ? metadataText(selectedNode.metadata, 'url') : '';
  const selectedFindingId = selectedNode?.type === 'finding'
    ? selectedNode.id.replace('finding:', '')
    : metadataText(selectedNode?.metadata, 'finding_id');

  const handleSelectNode = (id: string) => {
    setSelectedNodeId(id);
    setSelectedExchange(null);
    setSidebarOpen(true);
    setSidebarTab('intel');
  };

  const handleOpenForensic = async (id: string) => {
    try {
      const { data } = await cockpitApi.getForensicExchange(target, id);
      setSelectedExchange(data);
    } catch {
      toast.error('Failed to open forensic exchange');
    }
  };

  const handleTriggerProbe = async () => {
    if (!selectedNodeUrl) return;
    try {
      setProbing(true);
      await cockpitApi.triggerProbe(target, selectedNodeUrl);
      toast.success('Forensic probe launched');
    } catch {
      toast.error('Probe sequence failed');
    } finally {
      setProbing(false);
    }
  };

  const handleAddNote = async () => {
    if (!newNote.trim() || !selectedNode) return;
    try {
      await createNote(target, {
        finding_id: selectedFindingId || selectedNode.id,
        note: newNote,
        graph_node_id: selectedNode.id,
        author: 'analyst',
      });
      setNewNote('');
      getNotes(target).then((res) => setNotes(res.notes));
    } catch {
      toast.error('Failed to add note');
    }
  };

  return (
    <div className="relative flex h-full w-full overflow-hidden bg-[#020204]">
      <div className="pointer-events-none fixed inset-0 z-[60] opacity-[0.04] mix-blend-overlay bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]" />

      <div className="relative flex-1">
        <div className="pointer-events-none absolute left-8 top-8 z-10">
          <h2 className="mb-1 text-2xl font-black uppercase tracking-tighter text-text">Security Cockpit</h2>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-accent/60">
            <Icon name="target" size={12} />
            {target || 'Grid Standby'}
          </div>
        </div>

        {/* Floating Scan Control Deck */}
        <div className="absolute left-8 top-28 z-30 w-80 max-h-[calc(100vh-160px)] overflow-y-auto scrollbar-none rounded-xl border border-white/10 bg-black/80 p-5 shadow-[0_4px_30px_rgba(0,0,0,0.4)] backdrop-blur-xl transition-all">
          <div className="mb-4 flex items-center justify-between border-b border-white/5 pb-3">
            <div className="flex items-center gap-2">
              <div className="relative flex h-2 w-2">
                <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${
                  activeJob?.status === 'running' ? 'bg-amber-400' :
                  activeJob?.status === 'completed' ? 'bg-green-400' :
                  activeJob?.status === 'failed' ? 'bg-red-400' :
                  activeJob?.status === 'stopped' ? 'bg-rose-500' : 'bg-slate-400'
                }`} />
                <span className={`relative inline-flex h-2 w-2 rounded-full ${
                  activeJob?.status === 'running' ? 'bg-amber-400 animate-pulse' :
                  activeJob?.status === 'completed' ? 'bg-green-400 animate-pulse' :
                  activeJob?.status === 'failed' ? 'bg-red-400 animate-pulse' :
                  activeJob?.status === 'stopped' ? 'bg-rose-500' : 'bg-slate-400'
                }`} />
              </div>
              <h3 className="font-sans text-[11px] font-black uppercase tracking-[0.2em] text-white">Pipeline Control Deck</h3>
            </div>
            
            <button
              type="button"
              onClick={() => setIsDeckOpen(!isDeckOpen)}
              className="text-[10px] font-mono uppercase tracking-widest text-accent hover:text-white transition-colors"
            >
              {isDeckOpen ? '[ Collapse ]' : '[ Expand ]'}
            </button>
          </div>

          {isDeckOpen && (
            <div className="space-y-4">
              {!activeJobId || !activeJob ? (
                // Setup & Launch Screen
                <>
                  <div className="space-y-1">
                    <label className="block space-y-1">
                      <span className="font-mono text-[9px] uppercase tracking-wider text-muted">Enter your website URL to scan.</span>
                      <input
                        type="text"
                        value={inputTarget}
                        onChange={(e) => setInputTarget(e.target.value)}
                        placeholder="e.g. https://example.com"
                        className="w-full rounded border border-white/10 bg-white/5 px-3 py-2 font-mono text-xs text-text placeholder-white/20 outline-none focus:border-accent/40 transition-colors"
                      />
                    </label>
                  </div>

                  <div className="space-y-2">
                    <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Scan Mode Preset</div>
                    <div className="flex flex-col gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setScanMode('safe');
                          setSelectedModules(['subdomain_enum', 'url_discovery', 'port_scan', 'httpx']);
                        }}
                        className={`flex flex-col items-start rounded-lg border p-3 text-left transition-all ${
                          scanMode === 'safe'
                            ? 'border-accent bg-accent/10 text-text shadow-[0_0_15px_rgba(0,255,244,0.15)]'
                            : 'border-white/5 bg-white/5 text-muted hover:bg-white/10 hover:border-white/10'
                        }`}
                      >
                        <span className="text-xs font-black uppercase tracking-wider text-white">Quick Health Check</span>
                        <span className="mt-0.5 text-[9px] font-medium leading-relaxed opacity-60">safe, non-intrusive metadata audit</span>
                      </button>
                      
                      <button
                        type="button"
                        onClick={() => {
                          setScanMode('aggressive');
                          setSelectedModules(['subdomain_enum', 'url_discovery', 'port_scan', 'httpx', 'nuclei']);
                        }}
                        className={`flex flex-col items-start rounded-lg border p-3 text-left transition-all ${
                          scanMode === 'aggressive'
                            ? 'border-accent bg-accent/10 text-text shadow-[0_0_15px_rgba(0,255,244,0.15)]'
                            : 'border-white/5 bg-white/5 text-muted hover:bg-white/10 hover:border-white/10'
                        }`}
                      >
                        <span className="text-xs font-black uppercase tracking-wider text-white">Deep Security Clean-Up</span>
                        <span className="mt-0.5 text-[9px] font-medium leading-relaxed opacity-60">full active fuzzer checks</span>
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2 border-t border-white/5 pt-3">
                    <button
                      type="button"
                      onClick={() => setShowAdvanced(!showAdvanced)}
                      className="flex w-full items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted hover:text-accent transition-colors"
                    >
                      <span>{showAdvanced ? '─ Hide Advanced Options' : '┼ Show Advanced Options'}</span>
                    </button>

                    {showAdvanced && (
                      <div className="space-y-1 rounded border border-white/5 bg-black/40 p-2.5 mt-2 animate-fadeIn">
                        {[
                          { id: 'subdomain_enum', label: 'Subdomain Recon' },
                          { id: 'url_discovery', label: 'URL Discovery' },
                          { id: 'port_scan', label: 'Port Scanning' },
                          { id: 'httpx', label: 'HTTP Prober' },
                          { id: 'nuclei', label: 'Vulnerability (Nuclei)' },
                        ].map((mod) => {
                          const active = selectedModules.includes(mod.id);
                          return (
                            <label
                              key={mod.id}
                              className="flex cursor-pointer items-center justify-between py-1 transition-colors hover:text-white"
                            >
                              <span className="font-mono text-[10px] text-muted-foreground">{mod.label}</span>
                              <input
                                type="checkbox"
                                checked={active}
                                onChange={() => {
                                  if (active) {
                                    setSelectedModules(selectedModules.filter((m) => m !== mod.id));
                                  } else {
                                    setSelectedModules([...selectedModules, mod.id]);
                                  }
                                }}
                                className="h-3 w-3 rounded border-white/10 bg-black/40 text-accent outline-none accent-accent focus:ring-0"
                              />
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={handleStartScan}
                    disabled={launchingScan || !inputTarget.trim()}
                    className="w-full rounded bg-accent py-2.5 text-center text-[10px] font-black uppercase tracking-[0.2em] text-black shadow-[0_0_15px_rgba(0,255,244,0.25)] transition-all hover:bg-white disabled:opacity-40 disabled:shadow-none"
                  >
                    {launchingScan ? 'ENGAGING ENGINE...' : 'ENGAGE SCAN ENGINE'}
                  </button>
                </>
              ) : (
                // Active Telemetry Monitor
                <div className="space-y-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Active Pipeline</div>
                      <div className="font-mono text-[11px] font-bold text-text truncate max-w-[140px]">{activeJob.base_url}</div>
                    </div>
                    <div className="text-right">
                      <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Engine State</div>
                      <div className="font-mono text-[10px] font-bold uppercase text-accent">{activeJob.status}</div>
                    </div>
                  </div>

                  {activeJob.stage_label && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between font-mono text-[9px]">
                        <span className="uppercase text-muted">Current Stage</span>
                        <span className="font-bold text-text">{activeJob.stage_label}</span>
                      </div>
                      
                      {/* Interactive Neon Progress Bar */}
                      <div className="relative h-2 w-full overflow-hidden rounded-full bg-white/10">
                        <motion.div
                          className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400 shadow-[0_0_10px_rgba(0,255,244,0.4)]"
                          initial={{ width: 0 }}
                          animate={{ width: `${activeJob.progress_percent || 0}%` }}
                          transition={{ duration: 0.5, ease: 'easeOut' }}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between font-mono text-[8px] text-muted">
                        <span>PROGRESS</span>
                        <span>{Math.round(activeJob.progress_percent || 0)}%</span>
                      </div>
                    </div>
                  )}

                  {activeJob.status_message && (
                    <div className="rounded border border-cyan-500/10 bg-cyan-950/20 p-2.5 font-mono text-[9px] leading-relaxed text-cyan-200/90 max-h-24 overflow-y-auto">
                      <div className="font-bold text-cyan-400 mb-0.5">STATUS MESSAGE:</div>
                      {activeJob.status_message}
                    </div>
                  )}

                  {/* Operational Controls */}
                  <div className="space-y-2 border-t border-white/5 pt-3">
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        type="button"
                        onClick={handleRestartScan}
                        disabled={restartingScan || activeJob.status !== 'running'}
                        className="flex items-center justify-center gap-1.5 rounded border border-accent/20 bg-accent/5 py-2 text-[9px] font-bold uppercase tracking-wider text-accent transition-all hover:bg-accent/15 disabled:opacity-40"
                      >
                        <Icon name="activity" size={10} />
                        {restartingScan ? 'RESTARTING...' : 'RESTART SAFE'}
                      </button>
                      <button
                        type="button"
                        onClick={handleStopScan}
                        disabled={stoppingScan || !['running', 'pending'].includes(activeJob.status)}
                        className="flex items-center justify-center gap-1.5 rounded border border-rose-500/20 bg-rose-950/20 py-2 text-[9px] font-bold uppercase tracking-wider text-rose-400 transition-all hover:bg-rose-900/30 disabled:opacity-40"
                      >
                        <Icon name="x" size={10} />
                        {stoppingScan ? 'STOPPING...' : 'TERMINATE SCAN'}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => {
                        setActiveJobId(undefined);
                        setActiveJob(null);
                        const params = new URLSearchParams(window.location.search);
                        params.delete('job_id');
                        navigate({ search: params.toString() });
                      }}
                      className="w-full rounded border border-white/10 bg-white/5 py-2 text-center text-[9px] font-bold uppercase tracking-widest text-muted hover:text-white transition-colors"
                    >
                      Clear / New Scan
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <AnimatePresence>
          {hoveredNode && !sidebarOpen && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              className="pointer-events-none absolute left-1/2 top-1/2 z-30 -translate-x-1/2 -translate-y-1/2"
            >
              <div className="rounded border border-accent/50 bg-black/80 p-4 shadow-[0_0_30px_rgba(0,255,65,0.2)] backdrop-blur-xl">
                <div className="mb-1 text-[10px] font-bold uppercase tracking-widest text-accent">{hoveredNode.severity}</div>
                <div className="mb-1 text-sm font-bold text-text">{hoveredNode.label}</div>
                <div className="max-w-xs truncate font-mono text-[10px] text-muted">{metadataText(hoveredNode.metadata, 'url')}</div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {loading ? (
          <div className="flex h-full items-center justify-center animate-pulse font-mono text-xs uppercase tracking-widest text-accent/40">
            Establishing 3D Neural Link...
          </div>
        ) : nodes.length === 0 ? (
          <div className="relative h-full">
            <AttackChainGraph3D
              nodes={[]}
              edges={[]}
              selectedNodeId={null}
              hoveredNodeId={null}
              onSelectNode={() => {}}
              onHoverNode={() => {}}
              className="h-full w-full opacity-60"
            />
            <div className="absolute inset-0 flex flex-col items-center justify-center text-muted opacity-50">
              <Icon name="alertTriangle" size={64} />
              <p className="mt-4 uppercase tracking-[0.3em]">No Data Points Detected</p>
            </div>
          </div>
        ) : (
          <AttackChainGraph3D
            nodes={nodes}
            edges={edges}
            selectedNodeId={selectedNodeId}
            hoveredNodeId={hoveredNodeId}
            onSelectNode={handleSelectNode}
            onHoverNode={setHoveredNodeId}
            className="h-full w-full"
          />
        )}

        <div className="absolute bottom-8 left-8 z-10 flex flex-wrap gap-4">
          <div className="flex items-center gap-4 rounded border border-white/5 bg-black/60 px-4 py-2 font-mono text-[9px] uppercase tracking-widest text-muted backdrop-blur-md">
            <div className="flex items-center gap-1.5"><div className="h-1.5 w-1.5 rounded-full bg-[#ff2d55]" /> Critical</div>
            <div className="flex items-center gap-1.5"><div className="h-1.5 w-1.5 rounded-full bg-[#ff6b35]" /> High</div>
            <div className="flex items-center gap-1.5"><div className="h-1.5 w-1.5 rounded-full bg-[#f7b731]" /> Med</div>
          </div>
          {meshHealth && (
            <div className="flex items-center gap-4 rounded border border-white/5 bg-black/60 px-4 py-2 font-mono text-[9px] uppercase tracking-widest text-accent backdrop-blur-md">
              <div className="flex items-center gap-1.5"><Icon name="activity" size={10} /> Latency: {meshHealth.avg_latency_ms}ms</div>
              <div className="flex items-center gap-1.5"><Icon name="server" size={10} /> Peers: {meshHealth.peer_count}</div>
              {migrations.length > 0 && (
                <div className="flex animate-pulse items-center gap-1.5 text-[#ff2d55]">
                  <Icon name="gitBranch" size={10} /> Migrations: {migrations.filter((m) => Date.now() - m.timestamp < 30000).length}
                </div>
              )}
            </div>
          )}
          <div className="rounded border border-white/5 bg-black/40 px-4 py-2 font-mono text-[9px] tracking-widest text-accent/40 backdrop-blur-md">
            NODES: {nodes.length} | EDGES: {edges.length} | ENGINE: R3F-INSTANCED
          </div>
        </div>
      </div>

      <AnimatePresence>
        {sidebarOpen && (
          <motion.aside
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            className="z-20 flex w-[420px] flex-col border-l border-white/10 bg-black/90 shadow-[-20px_0_50px_rgba(0,0,0,0.5)] backdrop-blur-2xl"
          >
            <div className="flex items-center justify-between border-b border-white/5 p-8">
              <h3 className="text-xs font-black uppercase tracking-[0.2em] text-accent">Operational Intelligence</h3>
              <button type="button" onClick={() => setSidebarOpen(false)} className="text-muted transition-colors hover:text-accent">
                <Icon name="x" size={20} />
              </button>
            </div>

            <div className="flex gap-4 border-b border-white/5 bg-white/5 px-8">
              {(['intel', 'chains', 'forensics'] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setSidebarTab(tab)}
                  className={`border-b-2 pb-4 pt-4 text-[10px] font-black uppercase tracking-widest transition-all ${sidebarTab === tab ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'}`}
                >
                  {tab === 'intel' ? 'Findings' : tab === 'chains' ? 'Kill-Chains' : 'Forensics'}
                </button>
              ))}
            </div>

            <div className="scrollbar-cyber flex-1 overflow-y-auto p-8">
              {sidebarTab === 'intel' && selectedNode && (
                <div className="space-y-8">
                  <div>
                    <div className={`mb-3 inline-block rounded px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${selectedNode.severity === 'high' || selectedNode.severity === 'critical' ? 'bg-red-500 text-white' : 'bg-accent text-black'}`}>
                      {selectedNode.type}
                    </div>
                    <h4 className="mb-2 text-xl font-bold leading-tight text-text">{selectedNode.label}</h4>
                    <div className="break-all font-mono text-[10px] text-muted opacity-60">{selectedNodeUrl || metadataText(selectedNode.metadata, 'host')}</div>
                  </div>

                  <section>
                    <h5 className="mb-4 text-[10px] font-black uppercase tracking-[0.2em] text-white/30">Operations</h5>
                    <div className="grid grid-cols-2 gap-3">
                      <button type="button" onClick={handleTriggerProbe} disabled={probing || !selectedNodeUrl} className="rounded border border-accent/20 bg-accent/10 py-3 text-[10px] font-bold uppercase tracking-widest text-accent transition-all hover:bg-accent/20 disabled:opacity-40">
                        {probing ? 'Probing...' : 'Forensic Probe'}
                      </button>
                      <button type="button" onClick={() => selectedFindingId && navigate(`/findings?finding=${encodeURIComponent(selectedFindingId)}`)} disabled={!selectedFindingId} className="rounded border border-white/10 bg-white/5 py-3 text-[10px] font-bold uppercase tracking-widest text-white transition-all hover:bg-white/10 disabled:opacity-40">
                        Drill To Finding
                      </button>
                    </div>
                  </section>

                  <section>
                    <h5 className="mb-4 text-[10px] font-black uppercase tracking-[0.2em] text-white/30">Collaboration</h5>
                    <div className="mb-6 space-y-3">
                      {notes.map((note) => (
                        <div key={note.id} className="rounded border border-white/5 bg-white/5 p-4 group">
                          <div className="mb-2 flex items-center justify-between font-mono text-[9px] uppercase opacity-40">
                            <span className="text-accent">{note.author}</span>
                            <div className="flex items-center gap-2">
                               <span>{new Date(note.created_at).toLocaleDateString()}</span>
                               <button 
                                 className="text-bad opacity-0 group-hover:opacity-100 transition-opacity"
                                 onClick={async () => {
                                   if (!target) return;
                                   try {
                                     const { deleteNote } = await import('@/api/notes');
                                     await deleteNote(target, note.id);
                                     getNotes(target).then((res) => setNotes(res.notes));
                                     toast.success('Note removed');
                                   } catch {
                                     toast.error('Failed to remove note');
                                   }
                                 }}
                               >
                                 <Icon name="x" size={10} />
                               </button>
                            </div>
                          </div>
                          <p className="text-xs leading-relaxed text-text/80">{note.note}</p>
                        </div>
                      ))}
                    </div>
                    <textarea value={newNote} onChange={(event) => setNewNote(event.target.value)} placeholder="ENTER DATA..." className="min-h-[100px] w-full rounded border border-white/10 bg-white/5 p-4 font-mono text-xs text-text outline-none focus:border-accent/50" />
                    <button type="button" onClick={handleAddNote} disabled={!newNote.trim()} className="mt-3 w-full rounded bg-accent py-3 text-[10px] font-black uppercase tracking-[0.2em] text-black transition-colors hover:bg-white disabled:opacity-40">
                      Submit Intel
                    </button>
                  </section>
                </div>
              )}

              {sidebarTab === 'chains' && (
                <AttackChainVisualizer chains={chains} onFindingSelect={(findingId) => navigate(`/findings?finding=${encodeURIComponent(findingId)}`)} />
              )}

              {sidebarTab === 'forensics' && (
                <div className="space-y-4">
                  {selectedExchange ? (
                    <ForensicExchangeDetail exchange={selectedExchange} onBack={() => setSelectedExchange(null)} />
                  ) : (
                    exchanges.map((exchange) => <ForensicExchangeItem key={exchange.exchange_id} exchange={exchange} onOpen={handleOpenForensic} />)
                  )}
                </div>
              )}
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </div>
  );
}
