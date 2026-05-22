import { apiClient } from './client';

export interface CockpitNode {
  id: string;
  type: 'subdomain' | 'endpoint' | 'finding';
  label: string;
  severity: string;
  metadata?: Record<string, unknown> & {
    url?: string;
    host?: string;
    health?: number;
    finding_id?: string;
   };
   
  position?: [number, number, number];
}

export interface CockpitEdge {
  source: string;
  target: string;
  label: string;
  metadata?: Record<string, unknown>;
}

export interface CockpitGraphResponse {
  nodes: CockpitNode[];
  edges: CockpitEdge[];
  metadata: {
    target: string;
    run?: string;
    job_id?: string;
    node_count?: number;
    edge_count?: number;
    severity_counts?: Record<string, number>;
    type_counts?: Record<string, number>;
    source?: string;
    generated_at?: number;
  };
}

export interface CockpitEvent {
  id: string;
  type: 'finding' | 'note';
  timestamp: string;
  severity?: string;
  title?: string;
  url?: string;
  author?: string;
  note?: string;
  finding_id?: string;
}

export interface CockpitEventsResponse {
  events: CockpitEvent[];
  next_cursor: string | null;
}

export interface ForensicExchange {
  exchange_id: string;
  timestamp: string;
  url: string;
  method: string;
  latency_seconds: number;
  response_status?: number; // Legacy alias
  request: {
    headers: Record<string, string>;
    body_snippet: string;
    body_hash: string;
    truncated: boolean;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body_snippet: string;
    body_hash: string;
    truncated: boolean;
  };
}

export const cockpitApi = {
  getGraph: (target: string, run?: string, jobId?: string) =>
    apiClient.get<CockpitGraphResponse>('/api/cockpit/graph', { params: { target, run, job_id: jobId } }),

  graphStreamUrl: (target: string, run?: string, jobId?: string) => {
    const params = new URLSearchParams({ target });
    if (run) params.set('run', run);
    if (jobId) params.set('job_id', jobId);
    return `/api/cockpit/graph/stream?${params.toString()}`;
  },

  getEvents: (target: string, cursor?: string) =>
    apiClient.get<CockpitEventsResponse>('/api/cockpit/events', { params: { target, cursor } }),

  listExchanges: (target: string) =>
    apiClient.get<{ exchanges: ForensicExchange[] }>('/api/cockpit/forensics', { params: { target } }),

  triggerProbe: (target: string, url: string, method: string = 'GET') =>
    apiClient.post<{ status: string; exchange_id: string; status_code: number; url: string }>('/api/cockpit/probes', null, {
      params: { target, url, method },
    }),

  getForensicExchange: (target: string, exchangeId: string) =>
    apiClient.get<ForensicExchange>(`/api/cockpit/forensics/${exchangeId}`, { params: { target } }),
};
