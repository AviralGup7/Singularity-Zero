import { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import DOMPurify from 'dompurify';
import { cockpitApi } from '@/api/cockpit';
import type { CockpitNode, ForensicExchange } from '@/api/cockpit';
import { createNote, getNotes } from '@/api/notes';
import type { MeshHealth, MigrationEvent } from '@/types/api';
import { useSSEProgress } from '@/hooks/useSSEProgress';
import { useToast } from '@/hooks/useToast';
import { startJob, stopJob, restartJob, pauseJob, resumeJob } from '@/api/jobs';
import { useCockpitData, useActiveJob } from '@/hooks/useCockpitData';
import { useCockpitGraph } from '@/hooks/useCockpitGraph';
import { ScanControlDeck } from '@/components/cockpit/ScanControlDeck';
import { GraphLegend } from '@/components/cockpit/GraphLegend';
import { useSettingsStore } from '@/stores/settingsStore';
import { ScopeWarningBanner } from '@/components/scope/ScopeComplianceBadge';
import { validateUrl } from '@/lib/utils';
import { CockpitHeader, CockpitCenterViewport, CockpitSidebar, CockpitSetupView } from './cockpit';

function sanitizeHtml(str: string): string {
  return DOMPurify.sanitize(str, { ALLOWED_TAGS: [], ALLOW_DATA_ATTR: false });
}

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
  const [activeCenterTab, setActiveCenterTab] = useState<'3d' | '2d' | 'chains'>('3d');

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
  const [scanRateLimit] = useState<number>(50);
  const [excludedPaths] = useState<string>('');
  const [selectedProject, setSelectedProject] = useState<import('@/api/projects').Project | null>(null);

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

  const handleSelectNode = useCallback((id: string) => {
    setSelectedNodeId(id);
    setSelectedExchange(null);
    setSidebarOpen(true);
    setSidebarTab('intel');
  }, [setSidebarTab]);

  const handleOpenForensic = useCallback(async (id: string) => {
    try {
      const { data } = await cockpitApi.getForensicExchange(target, id);
      setSelectedExchange(data);
    } catch {
      toast.error('Failed to open forensic exchange');
    }
  }, [target, toast]);

  const handleTriggerProbe = useCallback(async () => {
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
  }, [nodes, selectedNodeId, target, toast]);

  const handleAddNote = useCallback(async () => {
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
  }, [newNote, selectedNodeId, nodes, target, setNotes, toast]);

  const handleDeleteNote = useCallback(async (noteId: string) => {
    if (!target) return;
    try {
      const { deleteNote } = await import('@/api/notes');
      await deleteNote(target, noteId);
      getNotes(target).then((res) => setNotes(res.notes));
      toast.success('Note removed');
    } catch {
      toast.error('Failed to remove note');
    }
  }, [target, setNotes, toast]);

  const handleStartScan = useCallback(async () => {
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
      toast.error('Failed to initiate cyber pipeline');
    } finally {
      setLaunchingScan(false);
    }
  }, [inputTarget, selectedProject, scanMode, selectedModules, scanDepth, scanConcurrency, scanRateLimit, excludedPaths, setActiveJobId, navigate, toast]);

  const handleStopScan = useCallback(async () => {
    if (!activeJobId) return;
    try {
      setStoppingScan(true);
      await stopJob(activeJobId);
      toast.success('Pipeline scan termination requested');
    } catch {
      toast.error('Termination request failed');
    } finally {
      setStoppingScan(false);
    }
  }, [activeJobId, toast]);

  const handleRestartScan = useCallback(async () => {
    if (!activeJobId) return;
    try {
      setRestartingScan(true);
      await restartJob(activeJobId);
      toast.success('Safe restart initiated');
    } catch {
      toast.error('Safe restart failed');
    } finally {
      setRestartingScan(false);
    }
  }, [activeJobId, toast]);

  const handlePauseScan = useCallback(async () => {
    if (!activeJobId) return;
    try {
      setPausingScan(true);
      await pauseJob(activeJobId);
      toast.success('Scan pause requested');
    } catch {
      toast.error('Pause request failed');
    } finally {
      setPausingScan(false);
    }
  }, [activeJobId, toast]);

  const handleResumeScan = useCallback(async () => {
    if (!activeJobId) return;
    try {
      setResumingScan(true);
      await resumeJob(activeJobId);
      toast.success('Scan resumed');
    } catch {
      toast.error('Resume failed');
    } finally {
      setResumingScan(false);
    }
  }, [activeJobId, toast]);

  const handleClearScan = useCallback(() => {
    setActiveJobId(undefined);
    const params = new URLSearchParams(window.location.search);
    params.delete('job_id');
    navigate({ search: params.toString() });
  }, [setActiveJobId, navigate]);

  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId),
    [nodes, selectedNodeId]
  );
  const selectedNodeUrl = selectedNode ? metadataText(selectedNode.metadata, 'url') : '';

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

  if (!target && !loading) {
    return (
      <CockpitSetupView
        inputTarget={inputTarget}
        setInputTarget={setInputTarget}
        scanMode={scanMode}
        setScanMode={setScanMode}
        onStartScan={handleStartScan}
        launchingScan={launchingScan}
        setSelectedModules={setSelectedModules}
        selectedProject={selectedProject}
        setSelectedProject={setSelectedProject}
        scanDepth={scanDepth}
        setScanDepth={setScanDepth}
        scanConcurrency={scanConcurrency}
        setScanConcurrency={setScanConcurrency}
      />
    );
  }

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden bg-[#030508] text-text font-sans">
      <ScopeWarningBanner asset={inputTarget || target} />

      <CockpitHeader target={target} activeJob={activeJob} stats={stats} />

      <div className="flex-1 flex items-stretch overflow-hidden relative">
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
            setScanRateLimit={() => {}}
            excludedPaths={excludedPaths}
            setExcludedPaths={() => {}}
            selectedProject={selectedProject}
            setSelectedProject={setSelectedProject}
            className="w-full bg-transparent p-6 shadow-none max-h-none h-full border-none relative left-0 top-0 overflow-y-visible"
          />
        </div>

        <CockpitCenterViewport
          activeCenterTab={activeCenterTab}
          setActiveCenterTab={setActiveCenterTab}
          nodes={nodes}
          edges={edges}
          chains={chains}
          selectedNodeId={selectedNodeId}
          hoveredNodeId={hoveredNodeId}
          onSelectNode={handleSelectNode}
          onHoverNode={setHoveredNodeId}
          loading={loading}
          onFindingSelect={(findingId: string) => navigate(`/findings?finding=${encodeURIComponent(findingId)}`)}
        />

        <div className="flex-shrink-0">
          <GraphLegend nodes={nodes} edges={edges} meshHealth={meshHealth} migrations={migrations} now={now} />
        </div>

        <CockpitSidebar
          sidebarOpen={sidebarOpen}
          setSidebarOpen={setSidebarOpen}
          sidebarTab={sidebarTab}
          setSidebarTab={setSidebarTab}
          selectedNode={selectedNode}
          selectedNodeUrl={selectedNodeUrl}
          notes={notes}
          newNote={newNote}
          setNewNote={setNewNote}
          onAddNote={handleAddNote}
          onTriggerProbe={handleTriggerProbe}
          onDrillToFinding={(findingId: string) => navigate(`/findings?finding=${encodeURIComponent(findingId)}`)}
          onDeleteNote={handleDeleteNote}
          target={target}
          probing={probing}
          selectedExchange={selectedExchange}
          setSelectedExchange={setSelectedExchange}
          exchanges={exchanges}
          onOpenForensic={handleOpenForensic}
        />
      </div>
    </div>
  );
}
