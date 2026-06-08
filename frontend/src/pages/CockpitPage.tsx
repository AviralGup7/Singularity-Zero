import { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Icon } from '@/components/ui/Icon';
import { AttackChainVisualizer } from '@/components/AttackChainVisualizer';
import { AttackChainGraph3D } from '@/components/charts';
import { apiClient } from '@/api/client';
import { cockpitApi } from '@/api/cockpit';
import type { CockpitEdge, CockpitNode, ForensicExchange } from '@/api/cockpit';
import { createNote, getNotes } from '@/api/notes';
import type { Note } from '@/api/notes';
import type { AttackChain, MeshHealth, Job, MigrationEvent } from '@/types/api';
import { useSSEProgress } from '@/hooks/useSSEProgress';
import { useToast } from '@/hooks/useToast';
import { startJob, stopJob, restartJob, getJob } from '@/api/jobs';
import { useCockpitData, useActiveJob } from '@/hooks/useCockpitData';
import { useCockpitGraph } from '@/hooks/useCockpitGraph';
import { ScanControlDeck } from '@/components/cockpit/ScanControlDeck';
import { ForensicExchangeItem } from '@/components/cockpit/ForensicExchangeItem';
import { ForensicExchangeDetail } from '@/components/cockpit/ForensicExchangeDetail';
import { IntelSidebar } from '@/components/cockpit/IntelSidebar';
import { GraphLegend } from '@/components/cockpit/GraphLegend';
import { useSettingsStore } from '@/stores/settingsStore';
import { ScopeWarningBanner } from '@/components/scope/ScopeComplianceBadge';

function metadataText(metadata: CockpitNode['metadata'], key: string): string {
  const value = metadata ? Reflect.get(metadata, key) : undefined;
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return String(value);
}

export function CockpitPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const target = searchParams.get('target') || '';
  const run = searchParams.get('run') || undefined;
  const jobId = searchParams.get('job_id') || undefined;
  const focusFindingId = searchParams.get('focus') || '';

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedExchange, setSelectedExchange] = useState<ForensicExchange | null>(null);
  const [probing, setProbing] = useState(false);
  const [newNote, setNewNote] = useState('');

  // R3: Persist cockpit-side UI state via settingsStore. The active side tab,
  // scan control deck open/closed, and selected scan mode all now survive a
  // page reload (and the `updater.updateSection('cockpitLayout', ...)` call
  // is debounced + Zod-validated, same path as every other setting).
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

  // High-level scan tuning knobs (P1-3). These were previously buried in the
  // 4-step wizard. For 12-hour scans operators MUST be able to see and tune
  // depth, rate and concurrency before launching; the cockpit is the surface
  // they look at for the entire duration of a run.
  const [scanDepth, setScanDepth] = useState<number>(3);
  const [scanConcurrency, setScanConcurrency] = useState<number>(10);
  const [scanRateLimit, setScanRateLimit] = useState<number>(50);
  const [excludedPaths, setExcludedPaths] = useState<string>('');

  const { nodes, edges, chains, loading, applyGraph, notes, setNotes, exchanges, setExchanges, meshHealth, setMeshHealth, migrations, setMigrations, handleMeshHealth, handleMigrationEvent } =
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
  }, [focusFindingId, nodes]);

  useSSEProgress({
    jobId: activeJobId,
    enabled: Boolean(activeJobId),
    onEvent: (event) => {
      if (event.event_type === 'mesh_health_update') {
        handleMeshHealth(event.data as unknown as MeshHealth);
      } else if (event.event_type === 'migration_event') {
        const data = event.data as Record<string, unknown>;
        const migration = handleMigrationEvent(event.id, data);
        toast.info(`Distributed Agent Migration: ${migration.actor_id} moved to ${migration.target_node}`);
        requestGraphUpdate(target, run, activeJobId || jobId);
      } else if (
        event.event_type === 'finding_batch' ||
        event.event_type === 'stage_change' ||
        event.event_type === 'progress_update' ||
        event.event_type === 'completed'
      ) {
        requestGraphUpdate(target, run, activeJobId || jobId);
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
        depth: scanDepth,
        concurrency: scanConcurrency,
        rate_limit_rps: scanRateLimit,
        excluded_paths: excludedPaths.trim() || undefined,
      });
      setActiveJobId(newJob.id);
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
  const selectedFindingId = selectedNode?.type === 'finding'
    ? selectedNode.id.replace('finding:', '')
    : metadataText(selectedNode?.metadata, 'finding_id');

  return (
    <div className="relative flex h-full w-full overflow-hidden bg-[#020204]">
      <div
        className="pointer-events-none fixed inset-0 z-[60] opacity-[0.04] mix-blend-overlay bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]"
      />

      <div className="relative flex-1">
        <div className="pointer-events-none absolute left-8 top-8 z-10">
          <h2 className="mb-1 text-2xl font-black uppercase tracking-tighter text-text">Security Cockpit</h2>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-accent/60">
            <Icon name="target" size={12} />
            {target || 'Grid Standby'}
          </div>
        </div>

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
          handleStopScan={handleStopScan}
          handleRestartScan={handleRestartScan}
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
        />

        <ScopeWarningBanner asset={inputTarget || target} />

        <AnimatePresence>
          {hoveredNode && !sidebarOpen && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              className="pointer-events-none absolute left-1/2 top-1/2 z-30 -translate-x-1/2 -translate-y-1/2"
            >
              <div className="rounded border border-accent/50 bg-black/80 p-4 shadow-[0_0_30px_rgba(0,255,65,0.2)] backdrop-blur-xl">
                <div className="mb-1 text-[10px] font-bold uppercase tracking-widest text-accent">
                  {hoveredNode.severity}
                </div>
                <div className="mb-1 text-sm font-bold text-text">{hoveredNode.label}</div>
                <div className="max-w-xs truncate font-mono text-[10px] text-muted">
                  {metadataText(hoveredNode.metadata, 'url')}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {loading ? (
          <div className="flex h-full items-center justify-center animate-pulse font-mono text-xs uppercase tracking-widest text-accent/40">
            Establishing 3D View...
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

        <GraphLegend nodes={nodes} edges={edges} meshHealth={meshHealth} migrations={migrations} />

        <AnimatePresence>
          {sidebarOpen && (
            <motion.aside
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              className="z-20 flex w-[420px] flex-col border-l border-white/10 bg-black/90 shadow-[-20px_0_50px_rgba(0,0,0,0.5)] backdrop-blur-2xl"
            >
              <div className="flex items-center justify-between border-b border-white/5 p-8">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-accent">
                  Operational Intelligence
                </h3>
                <button
                  type="button"
                  onClick={() => setSidebarOpen(false)}
                  className="text-muted transition-colors hover:text-accent"
                >
                  <Icon name="x" size={20} />
                </button>
              </div>

              <div className="flex gap-4 border-b border-white/5 bg-white/5 px-8">
                {(['intel', 'chains', 'forensics'] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => setSidebarTab(tab)}
                    className={`border-b-2 pb-4 pt-4 text-[10px] font-black uppercase tracking-widest transition-all ${
                      sidebarTab === tab ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'
                    }`}
                  >
                    {tab === 'intel' ? 'Findings' : tab === 'chains' ? 'Kill-Chains' : 'Forensics'}
                  </button>
                ))}
              </div>

              <div className="scrollbar-cyber flex-1 overflow-y-auto p-8">
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

                {sidebarTab === 'chains' && (
                  <AttackChainVisualizer
                    chains={chains}
                    onFindingSelect={(findingId) =>
                      navigate(`/findings?finding=${encodeURIComponent(findingId)}`)
                    }
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
