import { useCallback, useEffect, useRef, useState } from 'react';
import type { CockpitNode, CockpitEdge, ForensicExchange } from '@/api/cockpit';
import { cockpitApi } from '@/api/cockpit';
import { getNotes } from '@/api/notes';
import type { Note } from '@/api/notes';
import type { AttackChain, Job, MeshHealth, MigrationEvent } from '@/types/api';
import { useMountedRef } from './realtime/shared';
import { showErrorToast } from '@/utils/extractErrorMessage';

interface UseCockpitDataOptions {
  target: string;
  run: string | undefined;
  jobId: string | undefined;
}

const COCKPIT_MIN_DELAY = 1000;
const COCKPIT_MAX_DELAY = 30000;
const COCKPIT_BACKOFF_FACTOR = 1.5;

export function shouldResetMountedOnStreamCleanup(): boolean {
  return false;
}

export function capMigrations<T>(items: T[], max = 50): T[] {
  return items.slice(-max);
}

export function asNoteList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
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

  const { mountedRef } = useMountedRef();
  const streamRef = useRef<EventSource | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef(COCKPIT_MIN_DELAY);

  const applyGraph = useCallback((data: { nodes: CockpitNode[]; edges: CockpitEdge[] }) => {
    setNodes(data.nodes);
    setEdges(data.edges);
  }, []);

  useEffect(() => {
    if (!target) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    const fetchGraph = async () => {
      try {
        setLoading(true);
        const [graphRes, chainsRes] = await Promise.all([
          cockpitApi.getGraph(target, run, jobId, { signal: controller.signal }),
          cockpitApi
            .getAttackChains(target, { signal: controller.signal })
            .catch((err) => {
               showErrorToast(err, 'Failed to load attack chains');
               return { data: [] };
            }),
        ]);
        applyGraph(graphRes.data);
        setChains(chainsRes.data || []);
      } catch (error) {
        if ((error as Error).name !== 'CanceledError') {
          showErrorToast(error, 'Failed to load cockpit intelligence');
        }
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
    return () => controller.abort();
  }, [target, run, jobId, applyGraph]);

  // Cockpit EventSource with reconnection backoff
  useEffect(() => {
    if (!target) return;

    const cleanupStream = () => {
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current);
        retryTimeoutRef.current = null;
      }
      if (streamRef.current) {
        streamRef.current.onerror = null;
        streamRef.current.close();
        streamRef.current = null;
      }
    };

    const connectStream = () => {
      if (!mountedRef.current) return;

      cleanupStream();

      const stream = new EventSource(cockpitApi.graphStreamUrl(target, run, jobId));
      streamRef.current = stream;

      stream.onopen = () => {
        if (!mountedRef.current) return;
        backoffRef.current = COCKPIT_MIN_DELAY;
      };

      const handleSnapshot = (event: MessageEvent) => {
        if (!mountedRef.current) {
          stream.close();
          return;
        }
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

      stream.onerror = () => {
        if (!mountedRef.current) return;
        stream.close();

        // Reconnect with exponential backoff
        const delay = backoffRef.current;
        backoffRef.current = Math.min(backoffRef.current * COCKPIT_BACKOFF_FACTOR, COCKPIT_MAX_DELAY);
        retryTimeoutRef.current = setTimeout(() => {
          if (mountedRef.current) {
            connectStream();
          }
        }, delay);
      };
    };

    connectStream();

    return () => {
      cleanupStream();
    };
  }, [target, run, jobId, applyGraph, mountedRef]);

  useEffect(() => {
    if (!target) return;
    const controller = new AbortController();
    getNotes(target)
      .then((res) => {
        if (mountedRef.current) setNotes(asNoteList(res.notes) as typeof res.notes);
      })
      .catch((err) => {
        showErrorToast(err, 'Failed to load notes');
      });
    cockpitApi
      .listExchanges(target)
      .then((res) => {
        if (mountedRef.current) setExchanges(asNoteList(res.data?.exchanges) as typeof res.data.exchanges);
      })
      .catch((err) => {
        showErrorToast(err, 'Failed to load forensic exchanges');
      });
    return () => controller.abort();
  }, [target, mountedRef]);

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
    setMigrations((prev) => capMigrations([...prev, migration]));
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
        showErrorToast(error, 'Failed to fetch job details');
      }
    };
    fetchJobStatus();
    const interval = setInterval(() => {
      if (isMounted) void fetchJobStatus();
    }, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [activeJobId]);

  return { activeJob, activeJobId, setActiveJobId, setActiveJob };
}
