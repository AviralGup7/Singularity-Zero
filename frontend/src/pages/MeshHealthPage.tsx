import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from 'd3-force';
import { Activity, Crown, GitBranch, Radio, RefreshCw, Server, Shield, Zap } from 'lucide-react';

import { electMeshLeader } from '@/api/health';
import { useApi } from '@/hooks/useApi';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';
import { useSSEProgress, type SseEvent } from '@/hooks/useSSEProgress';
import type { Job, MeshEdge, MeshHealth, MeshNode } from '@/types/api';

interface JobListPayload {
  jobs: Job[];
  total: number;
}

interface GraphNode extends MeshNode, SimulationNodeDatum {
  radius: number;
}

interface GraphLink extends SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
  edge: MeshEdge;
}

const STATUS_TONE: Record<MeshNode['status'], { fill: string; ring: string; text: string; label: string }> = {
  alive: { fill: '#10b981', ring: 'rgba(16, 185, 129, 0.38)', text: 'text-ok', label: 'Alive' },
  suspect: { fill: '#f59e0b', ring: 'rgba(245, 158, 11, 0.38)', text: 'text-warning', label: 'Suspect' },
  dead: { fill: '#ff0055', ring: 'rgba(255, 0, 85, 0.38)', text: 'text-danger', label: 'Dead' },
};

function formatAge(lastSeen: number): string {
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - lastSeen));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.round(seconds / 60)}m`;
}

function resolveEndpoint(value: string | GraphNode): string {
  return typeof value === 'string' ? value : value.id;
}

function MeshTopologyGraph({
  health,
  selectedId,
  onSelect,
}: {
  health: MeshHealth;
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { policy } = useMotionPolicy('graph');
  const [size, setSize] = useState({ width: 900, height: 500 });

  useEffect(() => {
    const element = containerRef.current;
    if (!element || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(([entry]) => {
      const rect = entry.contentRect;
      setSize({
        width: Math.max(320, Math.round(rect.width)),
        height: Math.max(360, Math.round(rect.height)),
      });
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const layout = useMemo(() => {
    const nodes: GraphNode[] = health.nodes.map((node) => ({
      ...node,
      radius: node.id === health.leader_id ? 25 : 19,
    }));
    const nodeIds = new Set(nodes.map((node) => node.id));
    const links: GraphLink[] = health.edges
      .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
      .map((edge) => ({
        source: edge.source,
        target: edge.target,
        edge,
      }));

    if (nodes.length > 1 && links.length === 0) {
      const anchor = health.leader_id || nodes[0].id;
      for (const node of nodes) {
        if (node.id !== anchor) {
          links.push({
            source: anchor,
            target: node.id,
            edge: {
              source: anchor,
              target: node.id,
              throughput: 0,
              latency_ms: 0,
              drop_rate: health.drop_rate,
              status: node.status,
            },
          });
        }
      }
    }

    const simulation = forceSimulation<GraphNode>(nodes)
      .force('link', forceLink<GraphNode, GraphLink>(links).id((node) => node.id).distance(170).strength(0.52))
      .force('charge', forceManyBody<GraphNode>().strength(-520))
      .force('collision', forceCollide<GraphNode>().radius((node) => node.radius + 22))
      .force('center', forceCenter(size.width / 2, size.height / 2))
      .stop();

    for (let i = 0; i < 120; i += 1) simulation.tick();

    for (const node of nodes) {
      node.x = Math.max(46, Math.min(size.width - 46, node.x ?? size.width / 2));
      node.y = Math.max(46, Math.min(size.height - 46, node.y ?? size.height / 2));
    }

    return { nodes, links };
  }, [health, size]);

  const particlesEnabled = policy.tier !== 'static';

  return (
    <div ref={containerRef} className="ops-panel min-h-[420px] overflow-hidden">
      <svg width="100%" height={size.height} viewBox={`0 0 ${size.width} ${size.height}`} role="img" aria-label="Mesh topology graph">
        <defs>
          <filter id="meshNodeGlow" x="-70%" y="-70%" width="240%" height="240%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {layout.links.map((link, index) => {
          const sourceId = resolveEndpoint(link.source);
          const targetId = resolveEndpoint(link.target);
          const source = layout.nodes.find((node) => node.id === sourceId);
          const target = layout.nodes.find((node) => node.id === targetId);
          if (!source || !target) return null;
          const throughput = Math.max(0, link.edge.throughput || 0);
          const width = Math.max(1, Math.min(5, 1 + throughput / 8));
          const color = link.edge.status === 'suspect' ? '#f59e0b' : link.edge.status === 'dead' ? '#ff0055' : '#2fd8f8';
          const duration = Math.max(0.8, 3.6 - Math.min(2.3, throughput / 18));

          return (
            <g key={`${sourceId}-${targetId}-${index}`}>
              <line
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={color}
                strokeOpacity={0.34}
                strokeWidth={width}
              />
              {particlesEnabled ? (
                <circle r="3" fill={color} opacity="0.86">
                  <animate attributeName="cx" values={`${source.x};${target.x}`} dur={`${duration}s`} repeatCount="indefinite" begin={`${index * 0.25}s`} />
                  <animate attributeName="cy" values={`${source.y};${target.y}`} dur={`${duration}s`} repeatCount="indefinite" begin={`${index * 0.25}s`} />
                </circle>
              ) : (
                <circle cx={((source.x ?? 0) + (target.x ?? 0)) / 2} cy={((source.y ?? 0) + (target.y ?? 0)) / 2} r="2.5" fill={color} opacity="0.72" />
              )}
            </g>
          );
        })}

        {layout.nodes.map((node) => {
          const tone = STATUS_TONE[node.status] ?? STATUS_TONE.suspect;
          const selected = selectedId === node.id;
          return (
            <g
              key={node.id}
              transform={`translate(${node.x}, ${node.y})`}
              onClick={() => onSelect(node.id)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') onSelect(node.id);
              }}
              tabIndex={0}
              role="button"
              aria-label={`Inspect ${node.id}`}
              className="cursor-pointer"
            >
              <circle r={node.radius + 12} fill={tone.ring} opacity={selected ? 0.9 : 0.42} filter="url(#meshNodeGlow)" />
              <circle r={node.radius} fill="#0B1728" stroke={selected ? '#ffffff' : tone.fill} strokeWidth={selected ? 3 : 2} />
              <circle r={Math.max(8, node.radius - 8)} fill={tone.fill} opacity={node.status === 'dead' ? 0.72 : 0.95} />
              {node.id === health.leader_id && <Crown size={15} x={-7.5} y={-45} color="#f59e0b" />}
              <text y={node.radius + 24} textAnchor="middle" fill="#e2e8f0" fontSize="11" fontWeight="700">
                {node.id.length > 18 ? `${node.id.slice(0, 15)}...` : node.id}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export function MeshHealthPage() {
  const [meshHealth, setMeshHealth] = useState<MeshHealth | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState('');
  const [electing, setElecting] = useState(false);

  const { data, loading, error, refetch } = useApi<MeshHealth>('/api/health/mesh', {
    bypassCache: true,
    refetchInterval: 5000,
    onSuccess: (next) => setMeshHealth(next),
  });
  const { data: runningJobs } = useApi<JobListPayload>('/api/jobs', {
    bypassCache: true,
    refetchInterval: 5000,
    params: { status: 'running', page_size: 1 },
  });


  const activeJobId = runningJobs?.jobs?.[0]?.id;
  const handleSseEvent = useCallback((event: SseEvent<MeshHealth>) => {
    if (event.event_type === 'mesh_health_update') {
      setMeshHealth(event.data);
    }
  }, []);

  const { connectionState } = useSSEProgress<MeshHealth>({
    jobId: activeJobId,
    enabled: Boolean(activeJobId),
    endpoint: 'progress',
    onEvent: handleSseEvent,
  });

  const health = meshHealth ?? data;
  const nodes = health?.nodes ?? [];
  const selectedNode = useMemo(() => {
    if (!health) return null;
    return health.nodes.find((node) => node.id === selectedNodeId) ?? health.nodes.find((node) => node.id === health.leader_id) ?? health.nodes[0] ?? null;
  }, [health, selectedNodeId]);

  useEffect(() => {
    if (!selectedNodeId && selectedNode?.id) {
      const tid = setTimeout(() => setSelectedNodeId(selectedNode.id!), 0);
      return () => clearTimeout(tid);
    }
  }, [selectedNode, selectedNodeId]);

  const selectedStats = selectedNode && health?.peer_stats ? health.peer_stats[selectedNode.id] : undefined;
  const aliveCount = nodes.filter((node) => node.status === 'alive').length;
  const suspectCount = nodes.filter((node) => node.status === 'suspect').length;
  const deadCount = nodes.filter((node) => node.status === 'dead').length;

  const handleElection = async () => {
    setElecting(true);
    try {
      const result = await electMeshLeader();
      setMeshHealth(result.mesh);
      setSelectedNodeId(result.leader_id);
      await refetch();
    } finally {
      setElecting(false);
    }
  };

  if (loading && !health) {
    return (
      <div className="flex items-center justify-center h-full text-accent/70 font-mono text-xs uppercase">
        Establishing mesh telemetry...
      </div>
    );
  }

  return (
    <div className="mesh-topology-page p-6 md:p-8 grid gap-4 bg-bg min-h-full">
      <header className="page-header flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3 min-w-0">
          <div className="h-11 w-11 rounded-lg border border-accent/30 bg-accent/10 grid place-items-center text-accent">
            <GitBranch size={23} />
          </div>
          <div className="min-w-0">
            <h1>Mesh Topology</h1>
            <p className="page-subtitle">
              {health?.peer_count ?? 0} peers, leader {health?.leader_id || 'unassigned'}, SSE {activeJobId ? connectionState : 'idle'}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn inline-flex items-center gap-2 px-3" type="button" onClick={() => void refetch()}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button className="btn btn-primary inline-flex items-center gap-2 px-3" type="button" disabled={electing} onClick={() => void handleElection()}>
            <Crown size={14} /> {electing ? 'Electing' : 'Elect Leader'}
          </button>
        </div>
      </header>

      {error && (
        <div className="banner error" role="alert">
          {error.message}
        </div>
      )}

      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
        <div className="pipeline-stat-card">
          <span className="stat-label">Peers</span>
          <strong className="stat-value">{health?.peer_count ?? 0}</strong>
        </div>
        <div className="pipeline-stat-card">
          <span className="stat-label">Latency</span>
          <strong className="stat-value">{health?.avg_latency_ms ?? 0}ms</strong>
        </div>
        <div className="pipeline-stat-card">
          <span className="stat-label">Drop Rate</span>
          <strong className="stat-value">{Math.round((health?.drop_rate ?? 0) * 100)}%</strong>
        </div>
        <div className="pipeline-stat-card">
          <span className="stat-label">Heartbeat</span>
          <strong className="stat-value">{health?.active_heartbeats ? 'On' : 'Off'}</strong>
        </div>
        <div className="pipeline-stat-card">
          <span className="stat-label">Status</span>
          <strong className="stat-value">{aliveCount}/{suspectCount}/{deadCount}</strong>
        </div>
      </section>

      <section className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_360px] gap-4 items-start">
        {health ? (
          <MeshTopologyGraph health={health} selectedId={selectedNode?.id ?? ''} onSelect={setSelectedNodeId} />
        ) : (
          <div className="empty">No mesh health payload is available.</div>
        )}

        <aside className="ops-panel p-4 grid gap-4">
          <div className="panel-title-row">
            <h2>Node Stats</h2>
            <span className={`status-pill ${selectedNode?.status ? `status-${selectedNode.status}` : ''}`}>
              {selectedNode?.status ?? 'none'}
            </span>
          </div>

          {selectedNode ? (
            <>
              <div className="grid gap-2 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted inline-flex items-center gap-2"><Server size={14} /> Node</span>
                  <strong className="truncate max-w-[190px]">{selectedNode.id}</strong>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted inline-flex items-center gap-2"><Radio size={14} /> Endpoint</span>
                  <strong className="font-mono text-xs">{selectedNode.host}:{selectedNode.port}</strong>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted inline-flex items-center gap-2"><Crown size={14} /> Leader</span>
                  <strong>{selectedNode.id === health?.leader_id ? 'Yes' : 'No'}</strong>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted inline-flex items-center gap-2"><Zap size={14} /> Active Jobs</span>
                  <strong>{selectedNode.active_jobs}</strong>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted inline-flex items-center gap-2"><Activity size={14} /> CPU</span>
                  <strong>{Math.round(selectedNode.cpu_usage)}%</strong>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted inline-flex items-center gap-2"><Shield size={14} /> Last Seen</span>
                  <strong>{formatAge(selectedNode.last_seen)} ago</strong>
                </div>
              </div>

              <div className="grid gap-2 border-t border-white/10 pt-4">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted">Retry Count</span>
                  <strong>{String(selectedStats?.retry_count ?? 0)}</strong>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted">Heartbeat Misses</span>
                  <strong>{String(selectedStats?.heartbeat_misses ?? 0)}</strong>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted">Messages Sent</span>
                  <strong>{String(selectedStats?.sent ?? 0)}</strong>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted">Messages Received</span>
                  <strong>{String(selectedStats?.received ?? 0)}</strong>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted">Failures</span>
                  <strong>{String(selectedStats?.failed ?? 0)}</strong>
                </div>
              </div>
            </>
          ) : (
            <div className="empty">Select a node from the graph.</div>
          )}
        </aside>
      </section>
    </div>
  );
}
