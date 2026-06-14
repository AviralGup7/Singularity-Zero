import { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Icon } from '@/components/ui/Icon';
import { AttackChainVisualizer } from '@/components/AttackChainVisualizer';
import { AttackChainGraph3D } from '@/components/charts';
import { cockpitApi } from '@/api/cockpit';
import type { CockpitEdge, CockpitNode, ForensicExchange } from '@/api/cockpit';
import { createNote, getNotes } from '@/api/notes';
import type { AttackChain, MeshHealth, MigrationEvent } from '@/types/api';
import { useSSEProgress } from '@/hooks/useSSEProgress';
import { useToast } from '@/hooks/useToast';
import { startJob, stopJob, restartJob, pauseJob, resumeJob } from '@/api/jobs';
import { useCockpitData, useActiveJob } from '@/hooks/useCockpitData';
import { useCockpitGraph } from '@/hooks/useCockpitGraph';
import { ScanControlDeck } from '@/components/cockpit/ScanControlDeck';
import type { Project } from '@/api/projects';
import { ForensicExchangeItem } from '@/components/cockpit/ForensicExchangeItem';
import { ForensicExchangeDetail } from '@/components/cockpit/ForensicExchangeDetail';
import { IntelSidebar } from '@/components/cockpit/IntelSidebar';
import { GraphLegend } from '@/components/cockpit/GraphLegend';
import { useSettingsStore } from '@/stores/settingsStore';
import { ScopeWarningBanner } from '@/components/scope/ScopeComplianceBadge';
import { validateUrl } from '@/lib/utils';
import { getProjects } from '@/api/projects';

function sanitizeHtml(str: string): string {
  return str.replace(/[<>&"']/g, (m) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[m]!));
}

function metadataText(metadata: CockpitNode['metadata'], key: string): string {
  const value = metadata ? Reflect.get(metadata, key) : undefined;
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return String(value);
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500 border-red-500/30 bg-red-500/5',
  high: 'text-orange-500 border-orange-500/30 bg-orange-500/5',
  medium: 'text-amber-500 border-amber-500/30 bg-amber-500/5',
  low: 'text-blue-500 border-blue-500/30 bg-blue-500/5',
  info: 'text-slate-400 border-slate-400/30 bg-slate-400/5',
};

export function CockpitPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const rawTarget = searchParams.get('target') || '';
  const rawRun = searchParams.get('run') || '';
  const rawJobId = searchParams.get('job_id') || '';
  const rawFocus = searchParams.get('focus') || '';

  const target = sanitizeHtml(rawTarget);
  const run = rawRun ? sanitizeHtml(rawRun) : undefined;
  const jobId = rawJobId ? sanitizeHtml(rawJobId) : undefined;
  const focusFindingId = sanitizeHtml(rawFocus);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedExchange, setSelectedExchange] = useState<ForensicExchange | null>(null);
  const [probing, setProbing] = useState(false);
  const [newNote, setNewNote] = useState('');
  const [now, setNow] = useState(() => Date.now());

  // Center View Switcher
  const [activeCenterTab, setActiveCenterTab] = useState<'3d' | '2d' | 'chains'>('3d');

  // Load projects for setup landing page
  const [projectsList, setProjectsList] = useState<Project[]>([]);
  useEffect(() => {
    getProjects().then(setProjectsList).catch(() => {});
  }, []);

  const cockpitLayout = useSettingsStore((state) => state.settings.cockpitLayout);
  const updateCockpitLayout = useSettingsStore((state) => state.updater.updateSection);
  const setSidebarTab = useCallback(
    (tab: 'intel' | 'chains' | 'forensics') => updateCockpitLayout('cockpitLayout', { sidebarTab: tab }),
    [updateCockpitLayout]
  );
  const setIsDeckOpen = useCallback(
    (open: boolean) => updateCockpitLayout('cockpitLayout', { deckOpen: open }),
    [updateCockpitLayout]
  );
  const setScanMode = useCallback(
    (mode: 'safe' | 'aggressive') => updateCockpitLayout('cockpitLayout', { scanMode: mode }),
    [updateCockpitLayout]
  );
  const { sidebarTab, deckOpen: isDeckOpen, scanMode } = cockpitLayout;

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(id);
  }, []);

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
  const [pausingScan, setPausingScan] = useState(false);
  const [resumingScan, setResumingScan] = useState(false);
  const [inputTarget, setInputTarget] = useState(target);

  const [scanDepth, setScanDepth] = useState<number>(3);
  const [scanConcurrency, setScanConcurrency] = useState<number>(10);
  const [scanRateLimit, setScanRateLimit] = useState<number>(50);
  const [excludedPaths, setExcludedPaths] = useState<string>('');
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);

  const { nodes, edges, chains, loading, applyGraph, notes, setNotes, exchanges, setExchanges, meshHealth, migrations, handleMeshHealth, handleMigrationEvent } =
    useCockpitData({ target, run, jobId });
  const { activeJob, activeJobId, setActiveJobId } = useActiveJob(jobId);

  useEffect(() => {
    if (target) {
      setInputTarget(target);
    }
  }, [target]);

  const { requestGraphUpdate } = useCockpitGraph(applyGraph, target, run, jobId, activeJobId);

  useEffect(() => {
    if (focusFindingId && nodes.length > 0) {
      const targetNode = nodes.find(
        (n) =>
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
  }, [focusFindingId, nodes, setSidebarTab]);

  const targetRef = useRef(target);
  const runRef = useRef(run);
  const jobIdRef = useRef(jobId);
  const activeJobIdRef = useRef(activeJobId);

  useEffect(() => { targetRef.current = target; }, [target]);
  useEffect(() => { runRef.current = run; }, [run]);
  useEffect(() => { jobIdRef.current = jobId; }, [jobId]);
  useEffect(() => { activeJobIdRef.current = activeJobId; }, [activeJobId]);

  useSSEProgress({
    jobId: activeJobId,
    enabled: Boolean(activeJobId),
    onEvent: (event) => {
      if (event.event_type === 'mesh_health_update') {
        handleMeshHealth(event.data as unknown as MeshHealth);
      } else if (event.event_type === 'migration_event') {
        const data = event.data as Record<string, unknown>;
        const migration = handleMigrationEvent(event.id, data);
        toast.info(`Agent Migration: ${sanitizeHtml(migration.actor_id)} to ${sanitizeHtml(migration.target_node)}`);
        requestGraphUpdate(targetRef.current, runRef.current, activeJobIdRef.current || jobIdRef.current);
      } else if (
        event.event_type === 'finding_batch' ||
        event.event_type === 'stage_change' ||
        event.event_type === 'progress_update' ||
        event.event_type === 'completed'
      ) {
        requestGraphUpdate(targetRef.current, runRef.current, activeJobIdRef.current || jobIdRef.current);
      }
    },
  });

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
    const selectedNode = nodes.find((node) => node.id === selectedNodeId);
    const selectedNodeUrl = selectedNode ? metadataText(selectedNode.metadata, 'url') : '';
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
    if (!newNote.trim() || !selectedNodeId) return;
    try {
      const selectedNode = nodes.find((node) => node.id === selectedNodeId);
      const findingId = selectedNode?.type === 'finding'
        ? selectedNode.id.replace('finding:', '')
        : selectedNode?.metadata?.finding_id;
      await createNote(target, {
        finding_id: findingId || selectedNodeId,
        note: newNote,
        graph_node_id: selectedNodeId,
        author: 'analyst',
      });
      setNewNote('');
      getNotes(target).then((res) => setNotes(res.notes));
    } catch {
      toast.error('Failed to add note');
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!target) return;
    try {
      const { deleteNote } = await import('@/api/notes');
      await deleteNote(target, noteId);
      getNotes(target).then((res) => setNotes(res.notes));
      toast.success('Note removed');
    } catch {
      toast.error('Failed to remove note');
    }
  };

  const handleStartScan = async () => {
    if (!inputTarget.trim() && !selectedProject) {
      toast.error('Please enter a target URL/host or select a project');
      return;
    }
    if (inputTarget.trim()) {
      const validation = validateUrl(inputTarget);
      if (!validation.valid) {
        toast.error(validation.error!);
        return;
      }
    }
    try {
      setLaunchingScan(true);
      const newJob = await startJob({
        base_url: inputTarget || (selectedProject ? `https://${selectedProject.scope.split(',')[0].trim().replace('*.', '')}` : ''),
        mode: scanMode,
        modules: selectedModules,
        depth: scanDepth,
        concurrency: scanConcurrency,
        rate_limit_rps: scanRateLimit,
        excluded_paths: excludedPaths.trim() || undefined,
        project_id: selectedProject?.id,
      });
      setActiveJobId(newJob.id);
      const params = new URLSearchParams(window.location.search);
      params.set('target', inputTarget || selectedProject?.scope || '');
      params.set('job_id', newJob.id);
      navigate({ search: params.toString() });
      toast.success(selectedProject ? `${selectedProject.name} scan launched` : 'Multi-stage cyber pipeline successfully launched');
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

  const handlePauseScan = async () => {
    if (!activeJobId) return;
    try {
      setPausingScan(true);
      await pauseJob(activeJobId);
      toast.success('Scan pause requested');
    } catch (error) {
      console.error(error);
      toast.error('Pause request failed');
    } finally {
      setPausingScan(false);
    }
  };

  const handleResumeScan = async () => {
    if (!activeJobId) return;
    try {
      setResumingScan(true);
      await resumeJob(activeJobId);
      toast.success('Scan resumed');
    } catch (error) {
      console.error(error);
      toast.error('Resume failed');
    } finally {
      setResumingScan(false);
    }
  };

  const handleClearScan = () => {
    setActiveJobId(undefined);
    const params = new URLSearchParams(window.location.search);
    params.delete('job_id');
    navigate({ search: params.toString() });
  };

  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId),
    [nodes, selectedNodeId]
  );
  const hoveredNode = useMemo(
    () => nodes.find((node) => node.id === hoveredNodeId),
    [nodes, hoveredNodeId]
  );
  const selectedNodeUrl = selectedNode ? metadataText(selectedNode.metadata, 'url') : '';

  // Statistics for HUD Dashboard
  const stats = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    nodes.forEach((n) => {
      const sev = n.severity?.toLowerCase();
      if (sev in counts) {
        counts[sev as keyof typeof counts]++;
      }
    });
    return counts;
  }, [nodes]);

  // Standard standalone initialization Console View
  if (!target && !loading) {
    return (
      <div className="relative flex h-full w-full flex-col overflow-y-auto bg-[#05070a] p-8 cyber-grid-overlay scrollbar-cyber">
        {/* Animated Cyber Radar sweep element */}
        <div className="pointer-events-none absolute inset-0 z-0 opacity-15 overflow-hidden">
          <div className="absolute top-1/2 left-1/2 w-[60vw] h-[60vw] -translate-x-1/2 -translate-y-1/2 rounded-full border border-accent/20">
            <div className="radar-sweep-indicator absolute inset-0 rounded-full bg-gradient-to-tr from-accent/10 to-transparent" />
          </div>
        </div>

        <div className="relative z-10 m-auto flex w-full max-w-4xl flex-col items-center justify-center py-12">
          {/* Main Title Banner */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-950/20 px-3 py-1 font-mono text-[10px] uppercase tracking-widest text-cyan-400">
              <span className="pulse-dot bg-cyan-400" /> SYSTEM STANDBY: READY FOR TELEMETRY
            </div>
            <h1 className="mt-4 text-4xl font-extrabold tracking-tighter text-white uppercase sm:text-5xl">
              CYBER STEERING COCKPIT
            </h1>
            <p className="mt-2 text-sm text-muted font-mono max-w-xl mx-auto leading-relaxed">
              Launch multi-stage distributed security scan engines. Graph and simulate target attack-chains and live forensic telemetry.
            </p>
          </div>

          {/* Configuration Console Card */}
          <div className="w-full rounded-2xl border border-white/10 bg-[#0c0f16]/85 p-6 shadow-2xl backdrop-blur-xl md:p-8">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              {/* Left Column: Scope & Project setup */}
              <div className="space-y-6">
                <div>
                  <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-white mb-2 flex items-center gap-2">
                    <Icon name="target" size={14} className="text-accent" /> Scan Target URI
                  </h3>
                  <input
                    type="text"
                    value={inputTarget}
                    onChange={(e) => setInputTarget(e.target.value)}
                    placeholder="e.g. https://example.com"
                    className="w-full rounded-lg border border-white/10 bg-white/5 px-4 py-3 font-mono text-xs text-text placeholder-white/20 outline-none focus:border-accent/40 focus:ring-1 focus:ring-accent/40 transition-all shadow-inner"
                  />
                  <p className="mt-1.5 font-mono text-[9px] text-muted leading-relaxed">
                    Ensure the domain lies within your compliance program boundaries.
                  </p>
                </div>

                {projectsList.length > 0 && (
                  <div>
                    <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-white mb-2">
                      Active Bounty Programs
                    </h3>
                    <div className="grid grid-cols-1 gap-2 max-h-48 overflow-y-auto scrollbar-cyber rounded border border-white/5 bg-black/30 p-2">
                      {projectsList.map((project) => (
                        <button
                          key={project.id}
                          type="button"
                          onClick={() => {
                            setSelectedProject(project);
                            setInputTarget(`https://${project.scope.split(',')[0].trim().replace('*.', '')}`);
                          }}
                          className={`w-full rounded-lg border p-3 text-left transition-all flex items-center justify-between ${
                            selectedProject?.id === project.id
                              ? 'border-accent bg-accent/10 shadow-[0_0_12px_rgba(59,130,246,0.2)]'
                              : 'border-white/5 bg-white/5 hover:bg-white/10 hover:border-white/10'
                          }`}
                        >
                          <div className="truncate pr-4">
                            <div className="font-mono text-[10px] font-bold text-white truncate">{project.name}</div>
                            <div className="font-mono text-[8px] text-muted truncate">{project.scope}</div>
                          </div>
                          {project.rewards && (
                            <span className="font-mono text-[9px] font-bold text-accent px-2 py-0.5 rounded border border-accent/20 bg-accent/5">
                              {project.rewards}
                            </span>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: Preset Tuning Config */}
              <div className="space-y-6">
                <div>
                  <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-white mb-2 flex items-center gap-2">
                    <Icon name="settings" size={14} className="text-accent" /> Scan Preset
                  </h3>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      type="button"
                      onClick={() => {
                        setScanMode('safe');
                        setSelectedModules(['subdomain_enum', 'url_discovery', 'port_scan', 'httpx']);
                      }}
                      className={`flex flex-col items-start rounded-xl border p-3.5 text-left transition-all ${
                        scanMode === 'safe'
                          ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(59,130,246,0.15)] text-white'
                          : 'border-white/5 bg-white/5 text-muted hover:bg-white/10'
                      }`}
                    >
                      <span className="text-xs font-black uppercase tracking-wider text-white">Passive Safe</span>
                      <span className="mt-1 text-[9px] leading-relaxed opacity-60 font-mono">
                        Passive metadata gathering. Low footprint.
                      </span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setScanMode('aggressive');
                        setSelectedModules(['subdomain_enum', 'url_discovery', 'port_scan', 'httpx', 'nuclei']);
                      }}
                      className={`flex flex-col items-start rounded-xl border p-3.5 text-left transition-all ${
                        scanMode === 'aggressive'
                          ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(59,130,246,0.15)] text-white'
                          : 'border-white/5 bg-white/5 text-muted hover:bg-white/10'
                      }`}
                    >
                      <span className="text-xs font-black uppercase tracking-wider text-white">Active Vulnerability</span>
                      <span className="mt-1 text-[9px] leading-relaxed opacity-60 font-mono">
                        Intrusive active probe scan sequences.
                      </span>
                    </button>
                  </div>
                </div>

                <div className="space-y-3 rounded-xl border border-white/5 bg-black/40 p-4">
                  <div className="flex items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted">
                    <span>Depth: Level {scanDepth}</span>
                    <span>Concurrency: {scanConcurrency} workers</span>
                    <span>Rate Limit: {scanRateLimit} rps</span>
                  </div>
                  {/* Slider controls */}
                  <div className="space-y-2">
                    <input
                      type="range"
                      min={1}
                      max={8}
                      value={scanDepth}
                      onChange={(e) => setScanDepth(Number(e.target.value))}
                      className="cockpit-slider w-full"
                      aria-label="Crawl Depth"
                    />
                    <input
                      type="range"
                      min={1}
                      max={64}
                      value={scanConcurrency}
                      onChange={(e) => setScanConcurrency(Number(e.target.value))}
                      className="cockpit-slider w-full"
                      aria-label="Concurrency"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Launch Action */}
            <div className="mt-8 border-t border-white/5 pt-6 flex items-center justify-end">
              <button
                type="button"
                onClick={handleStartScan}
                disabled={launchingScan || !inputTarget.trim()}
                className="w-full sm:w-auto rounded-lg bg-accent px-8 py-3 text-center text-xs font-black uppercase tracking-[0.2em] text-black shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all hover:bg-white disabled:opacity-40 disabled:shadow-none font-mono"
              >
                {launchingScan ? 'INITIALIZING OPERATIONS...' : 'ENGAGE PIPELINE ENGINE'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden bg-[#030508] text-text font-sans">
      {/* Scope compliance banner */}
      <ScopeWarningBanner asset={inputTarget || target} />

      {/* Top HUD Dashboard bar */}
      <div className="flex-shrink-0 z-20 flex flex-col md:flex-row items-stretch md:items-center justify-between border-b border-white/10 bg-[#080b11]/80 backdrop-blur-md px-6 py-4 gap-4">
        {/* Left Telemetry Title */}
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/20 bg-accent/5">
            <Icon name="shield" size={18} className="text-accent" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-extrabold uppercase tracking-tight text-white">Steering Cockpit</h2>
              <span className="font-mono text-[9px] rounded-full border border-cyan-500/20 bg-cyan-950/20 px-2 py-0.5 text-cyan-400">
                {activeJob?.status || 'Active telemetry'}
              </span>
            </div>
            <div className="flex items-center gap-1.5 font-mono text-[10px] text-muted">
              <span className="pulse-dot" /> {target}
            </div>
          </div>
        </div>

        {/* Global Progress telemetry */}
        {activeJob && (
          <div className="flex-1 max-w-sm mx-4 space-y-1">
            <div className="flex items-center justify-between font-mono text-[9px]">
              <span className="uppercase text-muted truncate max-w-[150px]">{activeJob.stage_label || 'Scanning'}</span>
              <span className="font-bold text-accent">{Math.round(activeJob.progress_percent || 0)}%</span>
            </div>
            <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full bg-gradient-to-r from-accent via-cyan-400 to-emerald-400 transition-all duration-300"
                style={{ width: `${activeJob.progress_percent || 0}%` }}
              />
            </div>
          </div>
        )}

        {/* Right HUD metrics */}
        <div className="flex items-center gap-2.5">
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <div
              key={sev}
              className={`rounded-lg border px-3 py-1 text-center min-w-16 transition-all ${SEVERITY_COLORS[sev]}`}
            >
              <div className="font-mono text-xs font-black">{stats[sev]}</div>
              <div className="text-[8px] font-black uppercase tracking-wider opacity-60">{sev}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Main content body */}
      <div className="flex-1 flex items-stretch overflow-hidden relative">
        {/* Left Column: Docked Pipeline Engine Control Deck */}
        <div className="w-80 flex-shrink-0 border-r border-white/10 bg-[#05070a]/65 overflow-y-auto scrollbar-cyber z-10">
          <ScanControlDeck
            activeJob={activeJob}
            activeJobId={activeJobId}
            isDeckOpen={isDeckOpen}
            setIsDeckOpen={setIsDeckOpen}
            scanMode={scanMode}
            setScanMode={setScanMode}
            selectedModules={selectedModules}
            setSelectedModules={setSelectedModules}
            showAdvanced={showAdvanced}
            setShowAdvanced={setShowAdvanced}
            launchingScan={launchingScan}
            handleStartScan={handleStartScan}
            stoppingScan={stoppingScan}
            restartingScan={restartingScan}
            pausingScan={pausingScan}
            resumingScan={resumingScan}
            handleStopScan={handleStopScan}
            handleRestartScan={handleRestartScan}
            handlePauseScan={handlePauseScan}
            handleResumeScan={handleResumeScan}
            inputTarget={inputTarget}
            setInputTarget={setInputTarget}
            onClearScan={handleClearScan}
            scanDepth={scanDepth}
            setScanDepth={setScanDepth}
            scanConcurrency={scanConcurrency}
            setScanConcurrency={setScanConcurrency}
            scanRateLimit={scanRateLimit}
            setScanRateLimit={setScanRateLimit}
            excludedPaths={excludedPaths}
            setExcludedPaths={setExcludedPaths}
            selectedProject={selectedProject}
            setSelectedProject={setSelectedProject}
            className="w-full bg-transparent p-6 shadow-none max-h-none h-full border-none relative left-0 top-0 overflow-y-visible"
          />
        </div>

        {/* Center Viewport Stage */}
        <div className="flex-1 flex flex-col items-stretch bg-[#020305] relative overflow-hidden">
          {/* Center View Switched Controls */}
          <div className="flex-shrink-0 flex items-center justify-between border-b border-white/5 px-6 py-3 bg-[#080a0e]/40 z-10">
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setActiveCenterTab('3d')}
                className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider transition-all border ${
                  activeCenterTab === '3d'
                    ? 'border-accent/40 bg-accent/10 text-white shadow-[0_0_10px_rgba(59,130,246,0.15)]'
                    : 'border-transparent text-muted hover:text-white'
                }`}
              >
                [ 3D Threat Topology ]
              </button>
              <button
                type="button"
                onClick={() => setActiveCenterTab('2d')}
                className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider transition-all border ${
                  activeCenterTab === '2d'
                    ? 'border-accent/40 bg-accent/10 text-white shadow-[0_0_10px_rgba(59,130,246,0.15)]'
                    : 'border-transparent text-muted hover:text-white'
                }`}
              >
                [ 2D Node Grid ]
              </button>
              <button
                type="button"
                onClick={() => setActiveCenterTab('chains')}
                className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider transition-all border ${
                  activeCenterTab === 'chains'
                    ? 'border-accent/40 bg-accent/10 text-white shadow-[0_0_10px_rgba(59,130,246,0.15)]'
                    : 'border-transparent text-muted hover:text-white'
                }`}
              >
                [ Attack Kill-Chains ({chains.length}) ]
              </button>
            </div>
            {activeCenterTab === '3d' && (
              <div className="text-[10px] font-mono text-muted uppercase tracking-widest flex items-center gap-1.5">
                <span className="pulse-dot" /> Dynamic 3D Renderer Active
              </div>
            )}
          </div>

          {/* Actual View render */}
          <div className="flex-1 relative overflow-hidden">
            {loading ? (
              <div className="flex h-full items-center justify-center animate-pulse font-mono text-xs uppercase tracking-widest text-accent/40">
                Syncing Cluster Graph...
              </div>
            ) : nodes.length === 0 ? (
              <div className="absolute inset-0 flex flex-col items-center justify-center text-muted/50 p-12">
                <Icon name="alertTriangle" size={48} className="text-muted/30" />
                <p className="mt-4 uppercase tracking-[0.2em] font-mono text-xs">No active telemetry nodes mapped</p>
                <p className="mt-1 font-mono text-[10px] text-muted/40">Try adjusting your scan settings or preset mode.</p>
              </div>
            ) : activeCenterTab === '3d' ? (
              <AttackChainGraph3D
                nodes={nodes}
                edges={edges}
                selectedNodeId={selectedNodeId}
                hoveredNodeId={hoveredNodeId}
                onSelectNode={handleSelectNode}
                onHoverNode={setHoveredNodeId}
                className="h-full w-full"
              />
            ) : activeCenterTab === '2d' ? (
              <div className="absolute inset-0 overflow-y-auto p-6 scrollbar-cyber space-y-2">
                {nodes.map((node) => {
                  const healthVal = typeof node.metadata?.health === 'number' ? Math.round(node.metadata.health * 100) : 82;
                  const isFocused = selectedNodeId === node.id || hoveredNodeId === node.id;
                  return (
                    <div
                      key={node.id}
                      onClick={() => handleSelectNode(node.id)}
                      className={`flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl border transition-all cursor-pointer ${
                        isFocused
                          ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(59,130,246,0.12)]'
                          : 'border-white/5 bg-[#0a0d13]/40 hover:border-white/10 hover:bg-[#0a0d13]/60'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`rounded-lg border px-2.5 py-1 text-[9px] font-bold uppercase tracking-wider ${SEVERITY_COLORS[node.severity]}`}>
                          {node.severity}
                        </div>
                        <div>
                          <div className="font-mono text-xs font-bold text-white">{node.label}</div>
                          <div className="font-mono text-[9px] text-muted truncate max-w-sm">
                            {metadataText(node.metadata, 'url') || node.id}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 mt-2 sm:mt-0 font-mono text-[10px]">
                        <div className="text-right">
                          <div className="text-[9px] uppercase text-muted">Type</div>
                          <div className="font-bold text-white uppercase">{node.type}</div>
                        </div>
                        <div className="text-right min-w-24">
                          <div className="text-[9px] uppercase text-muted">Node Health</div>
                          <div className="font-bold text-emerald-400">{healthVal}%</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="absolute inset-0 overflow-y-auto p-6 scrollbar-cyber">
                <AttackChainVisualizer
                  chains={chains}
                  onFindingSelect={(findingId) =>
                    navigate(`/findings?finding=${encodeURIComponent(findingId)}`)
                  }
                />
              </div>
            )}
          </div>

          {/* Bottom HUD Legend info */}
          <GraphLegend nodes={nodes} edges={edges} meshHealth={meshHealth} migrations={migrations} now={now} />
        </div>

        {/* Right Column: Intelligence Drawer */}
        <AnimatePresence>
          {sidebarOpen && (
            <motion.aside
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              className="w-96 flex-shrink-0 z-20 flex flex-col border-l border-white/10 bg-[#06080c]/90 backdrop-blur-2xl shadow-2xl"
            >
              <div className="flex items-center justify-between border-b border-white/5 px-6 py-4">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-accent">
                  Inspector Telemetry
                </h3>
                <button
                  type="button"
                  onClick={() => setSidebarOpen(false)}
                  className="text-muted transition-colors hover:text-accent"
                >
                  <Icon name="x" size={18} />
                </button>
              </div>

              {/* Inspector tabs */}
              <div className="flex border-b border-white/5 bg-white/5">
                {(['intel', 'forensics'] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => setSidebarTab(tab as 'intel' | 'chains' | 'forensics')}
                    className={`flex-1 text-center py-3 font-mono text-[10px] font-black uppercase tracking-wider transition-all border-b-2 ${
                      sidebarTab === tab ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'
                    }`}
                  >
                    {tab === 'intel' ? 'Findings' : 'Forensics'}
                  </button>
                ))}
              </div>

              {/* Side Content */}
              <div className="scrollbar-cyber flex-1 overflow-y-auto p-6">
                {sidebarTab === 'intel' && selectedNode && (
                  <IntelSidebar
                    selectedNode={selectedNode}
                    selectedNodeUrl={selectedNodeUrl}
                    notes={notes}
                    newNote={newNote}
                    setNewNote={setNewNote}
                    onAddNote={handleAddNote}
                    onTriggerProbe={handleTriggerProbe}
                    onDrillToFinding={(findingId) => navigate(`/findings?finding=${encodeURIComponent(findingId)}`)}
                    onDeleteNote={handleDeleteNote}
                    target={target}
                  />
                )}

                {sidebarTab === 'forensics' && (
                  <div className="space-y-4">
                    {selectedExchange ? (
                      <ForensicExchangeDetail
                        exchange={selectedExchange}
                        onBack={() => setSelectedExchange(null)}
                      />
                    ) : (
                      exchanges.map((exchange) => (
                        <ForensicExchangeItem
                          key={exchange.exchange_id}
                          exchange={exchange}
                          onOpen={handleOpenForensic}
                        />
                      ))
                    )}
                  </div>
                )}
              </div>
            </motion.aside>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
