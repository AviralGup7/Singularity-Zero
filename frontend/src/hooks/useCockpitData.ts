import { useCallback, useEffect, useRef, useState } from 'react';
import type { CockpitNode, CockpitEdge, ForensicExchange } from '@/api/cockpit';
import { cockpitApi } from '@/api/cockpit';
import { getNotes, createNote } from '@/api/notes';
import type { Note } from '@/api/notes';
import type { AttackChain, Job, MeshHealth, MigrationEvent } from '@/types/api';

interface UseCockpitDataOptions {
  target: string;
  run: string | undefined;
  jobId: string | undefined;
}

export function useCockpitData({
  target,
  run,
  jobId,
}: UseCockpitDataOptions) {
  const [nodes, setNodes] = useState<CockpitNode[]>([]);
  const [edges, setEdges] = useState<CockpitEdge[]>([]);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState<Note[]>([]);
  const [exchanges, setExchanges] = useState<ForensicExchange[]>([]);
  const [meshHealth, setMeshHealth] = useState<MeshHealth | null>(null);
  const [migrations, setMigrations] = useState<MigrationEvent[]>([]);

  const applyGraph = useCallback((data: { nodes: CockpitNode[]; edges: CockpitEdge[] }) => {
    setNodes(data.nodes);
    setEdges(data.edges);
  }, []);

  useEffect(() => {
    if (!target) return;
    const controller = new AbortController();
    const fetchGraph = async () => {
      try {
        setLoading(true);
        const [graphRes, chainsRes] = await Promise.all([
          cockpitApi.getGraph(target, run, jobId, { signal: controller.signal }),
          cockpitApi
            .getAttackChains(target, { signal: controller.signal })
            .catch(() => ({ data: [] })),
        ]);
        applyGraph(graphRes.data);
        setChains(chainsRes.data || []);
      } catch (error) {
        if ((error as Error).name !== 'CanceledError') {
          console.error('Failed to fetch cockpit intelligence', error);
        }
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
    return () => controller.abort();
  }, [target, run, jobId, applyGraph]);

  useEffect(() => {
    if (!target) return;
    const stream = new EventSource(cockpitApi.graphStreamUrl(target, run, jobId));
    const handleSnapshot = (event: MessageEvent) => {
      try {
        const parsed = JSON.parse(event.data) as {
          data?: { nodes: CockpitNode[]; edges: CockpitEdge[] };
        };
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
  }, [target, run, jobId, applyGraph]);

  useEffect(() => {
    if (!target) return;
    const controller = new AbortController();
    getNotes(target)
      .then((res) => setNotes(res.notes))
      .catch((err) => console.error('API Error:', err));
    cockpitApi
      .listExchanges(target)
      .then((res) => setExchanges(res.data.exchanges))
      .catch((err) => console.error('API Error:', err));
    return () => controller.abort();
  }, [target]);

  const handleMeshHealth = useCallback((data: unknown) => {
    setMeshHealth(data as MeshHealth);
  }, []);

  const handleMigrationEvent = useCallback((eventId: string, data: Record<string, unknown>) => {
    const migration: MigrationEvent = {
      id: eventId,
      timestamp: Date.now(),
      actor_id: String(data.actor_id || 'unknown'),
      source_node: String(data.source_node || 'unknown'),
      target_node: String(data.target_node || 'unknown'),
      ...data,
    };
    setMigrations((prev) => [...prev, migration]);
    return migration;
  }, []);

  return {
    nodes,
    edges,
    chains,
    loading,
    applyGraph,
    notes,
    setNotes,
    exchanges,
    setExchanges,
    meshHealth,
    setMeshHealth,
    migrations,
    setMigrations,
    handleMeshHealth,
    handleMigrationEvent,
  };
}

export function useActiveJob(jobId?: string) {
  const [activeJob, setActiveJob] = useState<Job | null>(null);
  const [activeJobId, setActiveJobId] = useState<string | undefined>(jobId);

  useEffect(() => {
    if (!activeJobId) {
      setActiveJob(null);
      return;
    }
    let isMounted = true;
    const fetchJobStatus = async () => {
      try {
        const { getJob } = await import('@/api/jobs');
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

  return { activeJob, activeJobId, setActiveJobId, setActiveJob };
}
