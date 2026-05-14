import { apiClient } from './core';

export async function exportTargetFindings(targetName: string, format: 'csv' | 'json' = 'json', signal?: AbortSignal): Promise<Blob> {
  const { data } = await apiClient.get(`/api/export/findings/${targetName}`, {
    signal,
    params: { format },
    responseType: 'blob',
  });
  return data;
}

export async function exportLatestFindings(targetName: string, format: 'csv' | 'json' = 'json', signal?: AbortSignal): Promise<Blob> {
  const { data } = await apiClient.get(`/api/export/findings/${targetName}/latest`, {
    signal,
    params: { format },
    responseType: 'blob',
  });
  return data;
}
