import { apiClient } from './core';

export interface AccessLogEntry {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  reason: string;
  details: Record<string, unknown>;
  outcome: 'success' | 'failure' | 'denied';
}

export async function listAccessLogs(options?: {
  limit?: number;
  offset?: number;
  user?: string;
  action?: string;
  signal?: AbortSignal;
}): Promise<AccessLogEntry[]> {
  const params: Record<string, unknown> = {};
  if (options?.limit) params.limit = options.limit;
  if (options?.offset) params.offset = options.offset;
  if (options?.user) params.user = options.user;
  if (options?.action) params.action = options.action;
  const { data } = await apiClient.get<AccessLogEntry[]>('/api/access-logs', {
    params,
    signal: options?.signal,
  });
  return data;
}

export async function createAccessLog(entry: {
  action: string;
  resource: string;
  reason?: string;
  details?: Record<string, unknown>;
  user?: string;
  outcome?: string;
  signal?: AbortSignal;
}): Promise<AccessLogEntry> {
  const { data } = await apiClient.post<AccessLogEntry>('/api/access-logs', entry, {
    signal: entry.signal,
  });
  return data;
}

export async function clearAccessLogs(signal?: AbortSignal): Promise<{ status: string }> {
  const { data } = await apiClient.delete<{ status: string }>('/api/access-logs', { signal });
  return data;
}
